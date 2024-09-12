#ifndef BLOCK_PIR_H
#define BLOCK_PIR_H
#include <iostream>
#include <cstdlib>
#include <cassert>
#include <chrono>
#include <functional>
#include <unordered_map>

#include "PIRServer.h"
#include "PIRParams.h"
#include "PIRClient.h"
#include "BatchPIRParams.h"
#include "BatchPIRServer.h"
#include "BatchPIRClient.h"

#include "Kunlun/netio/stream_channel.hpp"
#include "Kunlun/mpc/okvs/okvs_utility.hpp"

void printM128iVector(const std::vector<__m128i> &vec)
{
    for (size_t i = 0; i < vec.size(); ++i)
    {
        const int *p = reinterpret_cast<const int *>(&vec[i]);
        std::cout << "Element " << i << ": [";
        for (int j = 0; j < 4; ++j)
        {
            std::cout << p[j];
            if (j < 3)
            {
                std::cout << ", ";
            }
        }
        std::cout << "]" << std::endl;
    }
}
void printBlockTupleVector(const std::unordered_map<uint64_t, std::tuple<__m128i, __m128i>> &dict)
{
    for (auto &pair : dict)
    {
        const auto &tupleElement = pair.second;
        const block &first = std::get<0>(tupleElement);
        const block &second = std::get<1>(tupleElement);

        const int *p1 = reinterpret_cast<const int *>(&first);
        const int *p2 = reinterpret_cast<const int *>(&second);

        std::cout << "Element " << pair.first << ":\n";
        std::cout << "  First block: [";
        for (int j = 0; j < 4; ++j)
        {
            std::cout << p1[j];
            if (j < 3)
            {
                std::cout << ", ";
            }
        }
        std::cout << "]\n";

        std::cout << "  Second block: [";
        for (int j = 0; j < 4; ++j)
        {
            std::cout << p2[j];
            if (j < 3)
            {
                std::cout << ", ";
            }
        }
        std::cout << "]\n";
    }
}

void SendMap(NetIO &io, const std::unordered_map<uint64_t, uint64_t> &m)
{
    // 发送map的大小
    size_t mapSize = m.size();
    io.SendInteger(mapSize);

    // 提取所有键并发送
    std::vector<uint64_t> keys;
    for (const auto &kv : m)
    {
        keys.push_back(kv.first);
    }

    io.SendBytes(keys.data(), keys.size() * sizeof(uint64_t));
    // 提取所有值并发送
    std::vector<uint64_t> values;
    for (const auto &kv : m)
    {
        values.push_back(kv.second);
    }
    io.SendBytes(values.data(), values.size() * sizeof(uint64_t));
}

std::unordered_map<uint64_t, uint64_t> ReceiveMap(NetIO &io)
{
    std::unordered_map<uint64_t, uint64_t> m;

    // 接收map的大小
    size_t mapSize;
    io.ReceiveInteger(mapSize);

    // 接收所有键
    std::vector<uint64_t> keys(mapSize);
    io.ReceiveBytes(keys.data(), keys.size() * sizeof(uint64_t));

    // 接收所有值
    std::vector<uint64_t> values(mapSize);
    io.ReceiveBytes(values.data(), values.size() * sizeof(uint64_t));

    // 将键值对插入到map中
    for (size_t i = 0; i < mapSize; ++i)
    {
        m[keys[i]] = values[i];
    }

    return m;
}
void sendStringStream(NetIO &io, stringstream &ss)
{
    string s = ss.str();
    io.SendInteger(s.size());
    io.SendString(s);
}
stringstream recvStringStream(NetIO &io)
{
    uint64_t s_size;
    io.ReceiveInteger(s_size);
    string s;
    s.resize(s_size);
    io.ReceiveString(s);
    return stringstream(s);
}

template <size_t N = 9>
std::unordered_map<uint64_t, BlockArrayValue<N>> batchpir_client(NetIO &io, std::vector<uint64_t> entry_indices)
{
    auto query_num = entry_indices.size();
    io.SendInteger(query_num);
    uint64_t db_size;
    io.ReceiveInteger(db_size);
    string selection = std::to_string(query_num) + "," + std::to_string(db_size) + "," + std::to_string(16*N);

    auto encryption_params = utils::create_encryption_parameters(selection);
    BatchPirParams params(query_num, db_size, 16*N, encryption_params);
    uint64_t max_bucket_size;
    io.ReceiveInteger(max_bucket_size);
    params.set_max_bucket_size(max_bucket_size);
    BatchPIRClient batch_client(params);
    seal::SEALContext context(encryption_params);

    auto map = ReceiveMap(io);
    batch_client.set_map(map);

    std::pair<seal::GaloisKeys, seal::RelinKeys> public_keys = batch_client.get_public_keys();
    stringstream ss;
    public_keys.first.save(ss);
    public_keys.second.save(ss);
    sendStringStream(io, ss);

    auto queries = batch_client.create_queries(entry_indices);
    io.SendInteger((uint64_t)queries.size());
    for (auto query : queries)
    {
        io.SendInteger(query.size());
        stringstream sss;
        for (auto cipher : query)
        {
            cipher.save(sss);
        }
        sendStringStream(io, sss);
    }

    uint64_t responses_size;
    io.ReceiveInteger(responses_size);
    PIRResponseList responses;
    auto response_ss = recvStringStream(io);
    for (auto i = 0; i < responses_size; i++)
    {
        seal::Ciphertext cp;
        cp.load(context, response_ss);
        responses.emplace_back(cp);
    }

    auto decode_responses = batch_client.decode_responses_chunks(responses);
    auto cuckoo_table = batch_client.get_cuckoo_table_raw();
    auto extract_response = batch_client.extractResponse(decode_responses, cuckoo_table);
    // printBlockTupleVector(extract_response);

    // std::cout << "Client: Response received and processed." << std::endl;
    // getchar();
    return extract_response;
}

template <size_t N = 9>
void batchpir_server_batch(NetIO &io, std::vector<BlockArrayValue<N>> values)
{
    auto client_id = 0;
    auto batch_size = 512;
    uint64_t query_num;
    io.ReceiveInteger(query_num);
    auto db_size = values.size();
    io.SendInteger(db_size);

    string selection = std::to_string(batch_size) + "," + std::to_string(db_size) + "," + std::to_string(16*N);
    auto encryption_params = utils::create_encryption_parameters(selection);
    BatchPirParams params(batch_size, db_size, 16*N, encryption_params);
    BatchPIRServer<N> batch_server(params, values);
    io.SendInteger(params.get_max_bucket_size());
    seal::SEALContext context(encryption_params);
    auto map = batch_server.get_hash_map();
    SendMap(io, map);

    seal::GaloisKeys glk;
    seal::RelinKeys rlk;

    for (uint64_t start = 0; start < query_num; start += batch_size)
    {
        stringstream ss = recvStringStream(io);
        glk.load(context, ss);
        rlk.load(context, ss);
        auto public_keys = std::make_pair(glk, rlk);
        batch_server.set_client_keys(client_id, public_keys);
        uint64_t queries_size;
        io.ReceiveInteger(queries_size);
        std::vector<PIRQuery> queries(queries_size);
        for (auto i = 0; i < queries_size; i++)
        {
            uint64_t query_size;
            io.ReceiveInteger(query_size);
            auto sss = recvStringStream(io);
            for (auto j = 0; j < query_size; j++)
            {
                seal::Ciphertext cp;
                cp.load(context, sss);
                queries[i].emplace_back(cp);
            }
        }

        PIRResponseList responses = batch_server.generate_response(client_id, queries);
        io.SendInteger(uint64_t(responses.size()));

        stringstream response_ss;
        for (auto response : responses)
        {
            response.save(response_ss);
        }
        sendStringStream(io, response_ss);

        std::cout << "Server: Response generation and sending complete." << std::endl;
    }

    // getchar();
}
template <size_t N = 9>
std::unordered_map<uint64_t, BlockArrayValue<N>> batchpir_client_batch(NetIO &io, std::vector<uint64_t> entry_indices)
{
    auto query_num = entry_indices.size();
    auto batch_size = 512;
    io.SendInteger(query_num);
    uint64_t db_size;
    io.ReceiveInteger(db_size);
    string selection = std::to_string(batch_size) + "," + std::to_string(db_size) + "," + std::to_string(16*N);

    auto encryption_params = utils::create_encryption_parameters(selection);
    BatchPirParams params(batch_size, db_size, 16*N, encryption_params);
    uint64_t max_bucket_size;
    io.ReceiveInteger(max_bucket_size);
    params.set_max_bucket_size(max_bucket_size);

    auto map = ReceiveMap(io);
    seal::SEALContext context(encryption_params);

    std::unordered_map<uint64_t, BlockArrayValue<N>> final_response;

    for (uint64_t start = 0; start < query_num; start += batch_size)
    {
        BatchPIRClient batch_client(params);
        batch_client.set_map(map);

        std::pair<seal::GaloisKeys, seal::RelinKeys> public_keys = batch_client.get_public_keys();
        stringstream ss;
        public_keys.first.save(ss);
        public_keys.second.save(ss);
        sendStringStream(io, ss);

        uint64_t end = std::min(start + batch_size, query_num);
        std::vector<uint64_t> batch_entry_indices(entry_indices.begin() + start, entry_indices.begin() + end);
        while (batch_entry_indices.size() < batch_size)
        {
            batch_entry_indices.emplace_back(0);
        }

        auto queries = batch_client.create_queries(batch_entry_indices);
        io.SendInteger(static_cast<uint64_t>(queries.size()));
        for (auto query : queries)
        {
            io.SendInteger(query.size());
            stringstream sss;
            for (auto cipher : query)
            {
                cipher.save(sss);
            }
            sendStringStream(io, sss);
        }

        uint64_t responses_size;
        io.ReceiveInteger(responses_size);
        PIRResponseList responses;
        auto response_ss = recvStringStream(io);
        for (auto i = 0; i < responses_size; i++)
        {
            seal::Ciphertext cp;
            cp.load(context, response_ss);
            responses.emplace_back(cp);
        }

        auto decode_responses = batch_client.decode_responses_chunks(responses);
        auto cuckoo_table = batch_client.get_cuckoo_table_raw();
        auto extract_response = batch_client.extractResponse<N>(decode_responses, cuckoo_table);

        // Merge the current batch's extract_response into final_response
        for (const auto &[key, value] : extract_response)
        {
            final_response[key] = value;
        }
        std::cout << "over extract" << std::endl;
    }

    // Return the final response
    return final_response;
}
void print_m128i(const __m128i &value)
{
    // 提取 __m128i 中的两个 64 位整数并输出
    uint64_t item1 = ((uint32_t *)(&value))[0];
    uint64_t item2 = ((uint32_t *)(&value))[1];
    uint64_t item3 = ((uint32_t *)(&value))[2];
    uint64_t item4 = ((uint32_t *)(&value))[3];

    std::cout << "([" << item1 << ", " << item2 << ", " << item3 << ", " << item4 << "])";
}

// 封装输出unordered_map的函数
template <size_t N = 9>
void print_unordered_map(const std::unordered_map<uint64_t, BlockArrayValue<N>> &my_map)
{
    // return ;
    // 遍历 unordered_map 并输出内容
    for (const auto &pair : my_map)
    {
        uint64_t key = pair.first;
        BlockArrayValue<N> blockArray = (BlockArrayValue<N>)pair.second; // 绑定为 const 引用

        std::cout << "Key: " << key << " -> ";
        uint32_t len = sizeof(blockArray.var) / sizeof(block);
        for (auto i = 0; i < len; ++i)
        {
            std::cout << ((uint32_t *)(&blockArray.var[i]))[0] << " " << ((uint32_t *)(&blockArray.var[i]))[1] << std::endl;
            std::cout << ((uint32_t *)(&blockArray.var[i]))[2] << " " << ((uint32_t *)(&blockArray.var[i]))[3] << std::endl;
        }
        std::cout << "" << std::endl;
    }
}

int batchpir_test2(int argc, char *argv[])
{
    pid_t pid = fork();
    if (pid < 0)
    {
        std::cerr << "Fork failed!" << std::endl;
        return 1;
    }

    if (pid == 0)
    {
        // 子进程作为客户端
        sleep(1); // 确保服务器先启动
        std::cout << "Client process started." << std::endl;
        NetIO io("client", "127.0.0.1", 9090);
        std::cout << "begin------" << std::endl;
        std::vector<uint64_t> entry_indices; // 示例 entry indices
        for (auto i = 0; i < 3939; i++)
        {
            entry_indices.emplace_back(i + 1);
        }
        print_unordered_map(batchpir_client_batch<2>(io, entry_indices));
        std::cout << "hello world1" << std::endl;
    }
    else
    {
        // 父进程作为服务器
        std::cout << "Server process started." << std::endl;
        NetIO io("server", "", 9090);

        std::vector<BlockArrayValue<2>> values(42768); // 示例数据
        for (size_t i = 0; i < values.size(); ++i)
        {
            BlockArrayValue<2> value;
            block block_value = _mm_set1_epi32(static_cast<int>(i + 1)); // 所有分量都设置为 i + 1
            for (auto j = 0; j < sizeof(BlockArrayValue<2>) / sizeof(block); j++)
                value.var[j] = block_value;
            values[i] = value;
        }

        batchpir_server_batch<2>(io, values);
        std::cout << "hello world2" << std::endl;
    }

    return 0;
}
#endif
