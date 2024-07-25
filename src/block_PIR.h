#ifndef BLOCK_PIR_H
#define BLOCK_PIR_H
#include <iostream>
#include <cstdlib>
#include <cassert>
#include <chrono>
#include <functional>
#include "../header/server.h"
#include "../header/pirparams.h"
#include "../header/client.h"
#include "../header/batchpirparams.h"
#include "../header/batchpirserver.h"
#include "../header/batchpirclient.h"
#include <iostream>
#include "../../Kunlun/netio/stream_channel.hpp"
#include <unordered_map>
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
void batchpir_combined()
{
    std::vector<std::tuple<__m128i, __m128i>> values(1ull << 20);

    for (size_t i = 0; i < 1ull << 20; ++i)
    {
        values[i] = std::make_tuple(_mm_set_epi32(i + 1, i + 1, i + 1, i + 1), _mm_set_epi32(i + 1, i + 1, i + 1, i + 1)); // 将第i个元素设置为__m128i(i)
    }
    std::vector<uint64_t> entry_indices; // 示例 entry indices
    for (auto i = 0; i < 1ull << 8; i++)
    {
        entry_indices.emplace_back(i);
    }
    auto client_id = 0;
    uint64_t query_num = entry_indices.size();
    auto db_size = values.size();

    string selection = std::to_string(query_num) + "," + std::to_string(db_size) + "," + std::to_string(32);
    auto encryption_params = utils::create_encryption_parameters(selection);
    BatchPirParams params(query_num, db_size, 32, encryption_params);
    BatchPIRServer batch_server(params, values);
    seal::SEALContext context(encryption_params);
    auto map = batch_server.get_hash_map();

    stringstream ss;
    seal::GaloisKeys glk;
    seal::RelinKeys rlk;

    // 客户端部分生成密钥并加载到服务器部分
    BatchPIRClient batch_client(params);
    auto public_keys = batch_client.get_public_keys();
    public_keys.first.save(ss);
    public_keys.second.save(ss);
    glk.load(context, ss);
    rlk.load(context, ss);
    batch_server.set_client_keys(client_id, public_keys);

    // 设置服务器端的哈希映射到客户端
    batch_client.set_map(map);
    std::cout << "process1" << std::endl;
    // 客户端生成查询
    auto queries = batch_client.create_queries(entry_indices);
    std::vector<PIRQuery> server_queries;

    std::cout << "process2" << std::endl;
    // 将客户端查询加载到服务器
    stringstream sss;
    for (auto query : queries)
    {
        for (auto cipher : query)
        {
            cipher.save(sss);
        }
        PIRQuery q;
        for (auto j = 0; j < query.size(); j++)
        {
            seal::Ciphertext cp;
            cp.load(context, sss);
            q.emplace_back(cp);
        }
        server_queries.push_back(q);
    }

    // 服务器生成响应
    std::cout << "process3" << std::endl;
    PIRResponseList responses = batch_server.generate_response(client_id, server_queries);

    std::cout << "process4" << std::endl;
    // 客户端解码响应
    stringstream response_ss;
    for (auto response : responses)
    {
        response.save(response_ss);
    }
    PIRResponseList client_responses;
    std::cout << "process5" << std::endl;
    for (auto i = 0; i < responses.size(); i++)
    {
        seal::Ciphertext cp;
        cp.load(context, response_ss);
        client_responses.emplace_back(cp);
    }
    std::cout << "process6" << std::endl;
    auto decode_responses = batch_client.decode_responses_chunks(client_responses);

    // 输出或处理解码后的响应
    std::cout << "over" << std::endl;
    auto cuckoo_table = batch_client.get_cuckoo_table();
    auto extract_response = batch_client.extractResponse(decode_responses, cuckoo_table);
    printBlockTupleVector(extract_response);
    // getchar();
}
void batchpir_server(NetIO &io, std::vector<std::tuple<block, block>> values)
{
    auto client_id = 0;
    uint64_t query_num;
    io.ReceiveInteger(query_num);
    auto db_size = values.size();
    io.SendInteger(db_size);

    string selection = std::to_string(query_num) + "," + std::to_string(db_size) + "," + std::to_string(32);
    auto encryption_params = utils::create_encryption_parameters(selection);
    BatchPirParams params(query_num, db_size, 32, encryption_params);
    BatchPIRServer batch_server(params, values);
    io.SendInteger(params.get_max_bucket_size());
    seal::SEALContext context(encryption_params);
    auto map = batch_server.get_hash_map();
    SendMap(io, map);

    seal::GaloisKeys glk;
    seal::RelinKeys rlk;
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
    // getchar();
}

std::unordered_map<uint64_t, std::tuple<__m128i, __m128i>> batchpir_client(NetIO &io, std::vector<uint64_t> entry_indices)
{
    auto query_num = entry_indices.size();
    io.SendInteger(query_num);
    uint64_t db_size;
    io.ReceiveInteger(db_size);
    string selection = std::to_string(query_num) + "," + std::to_string(db_size) + "," + std::to_string(32);

    auto encryption_params = utils::create_encryption_parameters(selection);
    BatchPirParams params(query_num, db_size, 32, encryption_params);
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
    printBlockTupleVector(extract_response);

    // std::cout << "Client: Response received and processed." << std::endl;
    // getchar();
    return extract_response;
}

// int batchpir_test(int argc, char *argv[])
// {
//     const int client_id = 0;
//     //  batch size, number of entries, size of entry
//     std::vector<std::array<size_t, 3>> input_choices;
//     input_choices.push_back({1ULL << 8, 1ULL << 20, 32});

//     std::vector<std::chrono::milliseconds> init_times;
//     std::vector<std::chrono::milliseconds> query_gen_times;
//     std::vector<std::chrono::milliseconds> resp_gen_times;
//     std::vector<size_t> communication_list;

//     for (size_t iteration = 0; iteration < input_choices.size(); ++iteration)
//     {
//         const auto &choice = input_choices[iteration];

//         string selection = std::to_string(choice[0]) + "," + std::to_string(choice[1]) + "," + std::to_string(choice[2]);

//         auto encryption_params = utils::create_encryption_parameters(selection);
//         BatchPirParams params(choice[0], choice[1], choice[2], encryption_params);
//         params.print_params();
//         std::vector<std::tuple<__m128i, __m128i>> data(choice[1]);

//         for (size_t i = 0; i < choice[1]; ++i)
//         {
//             data[i] = std::make_tuple(_mm_set_epi32(i + 1, i + 1, i + 1, i + 1), _mm_set_epi32(i + 1, i + 1, i + 1, i + 1)); // 将第i个元素设置为__m128i(i)
//         }

//         auto start = chrono::high_resolution_clock::now();
//         BatchPIRServer batch_server(params, data);
//         auto end = chrono::high_resolution_clock::now();
//         auto duration_init = chrono::duration_cast<chrono::milliseconds>(end - start);
//         init_times.push_back(duration_init);

//         BatchPIRClient batch_client(params);

//         auto map = batch_server.get_hash_map();
//         std::unordered_map<std::string, uint64_t> map_1;
//         // map_1["16 29"] = 42;
//         // map_1["17 30"] = 84;

//         // std::cout << "map:" << map_1["16 29"] << "nono" << std::endl;
//         // map_1["16 29"] = 2;
//         batch_client.set_map(map_1);

//         batch_server.set_client_keys(client_id, batch_client.get_public_keys());

//         vector<uint64_t> entry_indices;
//         for (int i = 0; i < choice[0]; i++)
//         {
//             entry_indices.push_back(i);
//         }

//         cout << "Main: Starting query generation for example " << (iteration + 1) << "..." << endl;
//         start = chrono::high_resolution_clock::now();
//         auto queries = batch_client.create_queries(entry_indices);
//         end = chrono::high_resolution_clock::now();
//         auto duration_querygen = chrono::duration_cast<chrono::milliseconds>(end - start);
//         query_gen_times.push_back(duration_querygen);
//         cout << "Main: Query generation complete for example " << (iteration + 1) << "." << endl;

//         cout << "Main: Starting response generation for example " << (iteration + 1) << "..." << endl;
//         start = chrono::high_resolution_clock::now();
//         PIRResponseList responses = batch_server.generate_response(client_id, queries);
//         end = chrono::high_resolution_clock::now();
//         auto duration_respgen = chrono::duration_cast<chrono::milliseconds>(end - start);
//         resp_gen_times.push_back(duration_respgen);
//         cout << "Main: Response generation complete for example " << (iteration + 1) << "." << endl;

//         cout << "Main: Checking decoded entries for example " << (iteration + 1) << "..." << endl;
//         auto decode_responses = batch_client.decode_responses_chunks(responses);

//         communication_list.push_back(batch_client.get_serialized_commm_size());
//         auto table = batch_server.buckets_;
//         auto cuckoo_table = batch_client.get_cuckoo_table();
//         // printM128iVector({convertToM128i(table[28][0])});
//         // printM128iVector({convertToM128i(table[35][0])});
//         // printM128iVector({convertToM128i(table[29][1])});
//         // std::cout<<cuckoo_table[28]<<std::endl;
//         // std::cout<<cuckoo_table[35]<<std::endl;
//         // std::cout<<cuckoo_table[29]<<std::endl;
//         // for (auto i = 0; i < cuckoo_table.size(); i++)
//         // {
//         //     if (cuckoo_table[i] <= 100)
//         //     {
//         //         //     printM128iVector({convertToM128i(table[i][cuckoo_table[i]])});
//         //         printM128iVector({convertToM128i(table[i][cuckoo_table[i]])});
//         //     }
//         // }
//         // for(auto i:cuckoo_table){
//         //     std::cout<<i<<std::endl;
//         // }
//         auto extract_response = batch_client.extractResponse(decode_responses, cuckoo_table);
//         // printBlockTupleVector(extract_response);
//         batch_server.check_decoded_entries(decode_responses, cuckoo_table);
//     }

//     cout << "***********************" << endl;
//     cout << "     Timings Report    " << endl;
//     cout << "***********************" << endl;
//     for (size_t i = 0; i < input_choices.size(); ++i)
//     {
//         cout << "Input Parameters: ";
//         cout << "Batch Size: " << input_choices[i][0] << ", ";
//         cout << "Number of Entries: " << input_choices[i][1] << ", ";
//         cout << "Entry Size: " << input_choices[i][2] << endl;

//         cout << "Initialization time: " << init_times[i].count() << " milliseconds" << endl;
//         cout << "Query generation time: " << query_gen_times[i].count() << " milliseconds" << endl;
//         cout << "Response generation time: " << resp_gen_times[i].count() << " milliseconds" << endl;
//         cout << "Total communication: " << communication_list[i] << " KB" << endl;
//         cout << endl;
//     }

//     return 0;
// }
void batchpir_server_batch(NetIO &io, std::vector<std::tuple<block, block>> values)
{
    auto client_id = 0;
    auto batch_size = 512;
    uint64_t query_num;
    io.ReceiveInteger(query_num);
    auto db_size = values.size();
    io.SendInteger(db_size);

    string selection = std::to_string(batch_size) + "," + std::to_string(db_size) + "," + std::to_string(32);
    auto encryption_params = utils::create_encryption_parameters(selection);
    BatchPirParams params(batch_size, db_size, 32, encryption_params);
    BatchPIRServer batch_server(params, values);
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

std::unordered_map<uint64_t, std::tuple<__m128i, __m128i>> batchpir_client_batch(NetIO &io, std::vector<uint64_t> entry_indices)
{
    auto query_num = entry_indices.size();
    auto batch_size = 512;
    io.SendInteger(query_num);
    uint64_t db_size;
    io.ReceiveInteger(db_size);
    string selection = std::to_string(batch_size) + "," + std::to_string(db_size) + "," + std::to_string(32);

    auto encryption_params = utils::create_encryption_parameters(selection);
    BatchPirParams params(batch_size, db_size, 32, encryption_params);
    uint64_t max_bucket_size;
    io.ReceiveInteger(max_bucket_size);
    params.set_max_bucket_size(max_bucket_size);

    auto map = ReceiveMap(io);
    seal::SEALContext context(encryption_params);

    std::unordered_map<uint64_t, std::tuple<__m128i, __m128i>> final_response;

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
        auto extract_response = batch_client.extractResponse(decode_responses, cuckoo_table);

        // Merge the current batch's extract_response into final_response
        for (const auto& [key, value] : extract_response)
        {
            final_response[key] = value;
        }
        std::cout<<"over extract"<<std::endl;
    }

    // Return the final response
    return final_response;
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
            entry_indices.emplace_back(i);
        }
        batchpir_client_batch(io, entry_indices);
    }
    else
    {
        // 父进程作为服务器
        std::cout << "Server process started." << std::endl;
        NetIO io("server", "", 9090);

        std::vector<std::tuple<block, block>> values(42768); // 示例数据
        for (size_t i = 0; i < values.size(); ++i)
        {
            values[i] = std::make_tuple(_mm_set_epi32(i + 1, i + 1, i + 1, i + 1), _mm_set_epi32(i + 1, i + 1, i + 1, i + 1));
        }

        batchpir_server_batch(io, values);
    }

    return 0;
}
#endif