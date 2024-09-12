#ifndef BATCHPIR_SERVER_H
#define BATCHPIR_SERVER_H

#include "BatchPIRParams.h"
#include "PIRServer.h"
#include "utils.h"
#include <emmintrin.h>
template <size_t N = 9>
class BatchPIRServer
{

public:
    BatchPIRServer(BatchPirParams &batchpir_params);
    BatchPIRServer(BatchPirParams &batchpir_params, std::vector<BlockArrayValue<N>> data);
    std::unordered_map<uint64_t, uint64_t> get_hash_map();
    void set_client_keys(uint32_t client_id, std::pair<seal::GaloisKeys, seal::RelinKeys> keys);
    void get_client_keys();
    PIRResponseList generate_response(uint32_t client_id, vector<PIRQuery> queries);
    bool check_decoded_entries(vector<std::vector<std::vector<unsigned char>>> entries_list, vector<uint64_t> cuckoo_table);
    vector<RawDB> buckets_;

private:
    BatchPirParams *batchpir_params_;
    RawDB rawdb_;
    vector<Server> server_list_;
    bool is_simple_hash_;
    bool is_client_keys_set_;
    std::unordered_map<uint64_t, uint64_t> map_; // map from key to bucket index

    void simeple_hash();
    std::vector<std::vector<uint64_t>> simeple_hash_with_map();
    void prepare_pir_server();
    void populate_raw_db();
    std::size_t get_max_bucket_size() const;
    std::size_t get_min_bucket_size() const;
    std::size_t get_avg_bucket_size() const;
    void balance_buckets();
    size_t get_first_dimension_size(size_t num_entries);
    PIRResponseList merge_responses(vector<PIRResponseList> &responses, uint32_t client_id);
    void print_stats() const;
};
template <size_t N>
BatchPIRServer<N>::BatchPIRServer(BatchPirParams &batchpir_params)
{
    batchpir_params_ = &batchpir_params;
    is_client_keys_set_ = false;
    is_simple_hash_ = false;

    std::cout << "BatchPIRServer: Populating raw database..." << std::endl;
    populate_raw_db();
    std::cout << "BatchPIRServer: Raw database populated." << std::endl;

    std::cout << "BatchPIRServer: Performing simple hash and bucket balancing..." << std::endl;
    simeple_hash();
    balance_buckets();
    std::cout << "BatchPIRServer: Simple hash and balancing completed." << std::endl;

    std::cout << "BatchPIRServer: Preparing PIR servers......" << std::endl;
    prepare_pir_server();
    std::cout << "BatchPIRServer: PIR servers preparation complete." << std::endl;
}
std::vector<unsigned char> convertToVector(__m128i vec)
{
    std::vector<unsigned char> result(16); // 128 位等于 16 字节
    _mm_storeu_si128(reinterpret_cast<__m128i *>(result.data()), vec);
    return result;
}
std::vector<unsigned char> convertTupleToVector(const std::tuple<__m128i, __m128i> &vecTuple)
{
    std::vector<unsigned char> result(32); // 2 x 128 bits = 2 x 16 bytes = 32 bytes

    // Extract the __m128i values from the tuple
    __m128i part1 = std::get<0>(vecTuple);
    __m128i part2 = std::get<1>(vecTuple);

    // Store the __m128i values into the vector
    _mm_storeu_si128(reinterpret_cast<__m128i *>(result.data()), part1);
    _mm_storeu_si128(reinterpret_cast<__m128i *>(result.data() + 16), part2);

    return result;
}
template <size_t N = 9>
std::vector<unsigned char> convertBlockArrayValueToVector(const BlockArrayValue<N> &blockArray)
{
    // 计算 block 数组的字节大小
    size_t blockSize = sizeof(blockArray.var);

    // 创建 vector 并分配足够的空间
    std::vector<unsigned char> result(blockSize);

    // 将 block 数组的内容复制到 vector 中
    std::memcpy(result.data(), blockArray.var, blockSize);

    return result;
}
template <size_t N>
BatchPIRServer<N>::BatchPIRServer(BatchPirParams &batchpir_params, std::vector<BlockArrayValue<N>> data)
{
    batchpir_params_ = &batchpir_params;
    is_client_keys_set_ = false;
    is_simple_hash_ = false;

    std::cout << "BatchPIRServer: Populating raw database..." << std::endl;
    auto db_entries = batchpir_params_->get_num_entries();
    auto entry_size = batchpir_params_->get_entry_size();

    // Resize the rawdb vector to the correct size
    rawdb_.resize(db_entries);
    // Populate the rawdb vector with entries
    for (size_t i = 0; i < db_entries; ++i)
    {
        rawdb_[i] = convertBlockArrayValueToVector(data[i]);
    }
    std::cout << "BatchPIRServer: Raw database populated." << std::endl;

    std::cout << "BatchPIRServer: Performing simple hash and bucket balancing..." << std::endl;
    simeple_hash();
    balance_buckets();
    std::cout << "BatchPIRServer: Simple hash and balancing completed." << std::endl;

    std::cout << "BatchPIRServer: Preparing PIR servers......" << std::endl;
    prepare_pir_server();
    std::cout << "BatchPIRServer: PIR servers preparation complete." << std::endl;
}
template <size_t N>
void BatchPIRServer<N>::populate_raw_db()
{
    auto db_entries = batchpir_params_->get_num_entries();
    auto entry_size = batchpir_params_->get_entry_size();

    // Resize the rawdb vector to the correct size
    rawdb_.resize(db_entries);

    // Define a function to generate a random entry
    auto generate_random_entry = [entry_size](int i) -> std::vector<unsigned char>
    {
        std::vector<unsigned char> entry(entry_size);
        std::generate(entry.begin(), entry.end(), [i]()
                      {
                          return 1 % 0xFF;
                          // return 1;s
                      });
        return entry;
    };

    // Populate the rawdb vector with entries
    for (size_t i = 0; i < db_entries; ++i)
    {
        rawdb_[i] = generate_random_entry(i);
    }
}
template <size_t N>
std::unordered_map<uint64_t, uint64_t> BatchPIRServer<N>::get_hash_map()
{

    if (!is_simple_hash_)
    {
        throw std::logic_error("Error: No map created yet");
    }
    return map_;
}
template <size_t N>
std::size_t BatchPIRServer<N>::get_max_bucket_size() const
{
    std::size_t max_size = 0;
    for (const auto &bucket : buckets_)
    {
        max_size = std::max(max_size, bucket.size());
    }
    return max_size;
}
template <size_t N>
size_t BatchPIRServer<N>::get_min_bucket_size() const
{
    size_t min_size = std::numeric_limits<size_t>::max();
    for (const auto &bucket : buckets_)
    {
        min_size = std::min(min_size, bucket.size());
    }
    return min_size;
}
template <size_t N>
size_t BatchPIRServer<N>::get_avg_bucket_size() const
{
    double total_size = 0;
    for (const auto &bucket : buckets_)
    {
        total_size += bucket.size();
    }
    return total_size / buckets_.size();
}
template <size_t N>
void BatchPIRServer<N>::simeple_hash()
{
    auto total_buckets = ceil(batchpir_params_->get_cuckoo_factor() * batchpir_params_->get_batch_size());
    auto db_entries = batchpir_params_->get_num_entries();
    auto num_candidates = batchpir_params_->get_num_hash_funcs();
    buckets_.resize(total_buckets);

    for (uint64_t i = 0; i < db_entries; i++)
    {
        std::vector<size_t> candidates = utils::get_candidate_buckets(i, num_candidates, total_buckets);
        for (auto b : candidates)
        {
            // std::cout<<i<<" "<<b<<" -> "<<i*db_entries+b<<" -> "<<buckets_[b].size()<<std::endl;
            map_[i * db_entries + b] = buckets_[b].size();
            buckets_[b].push_back(rawdb_[i]);
        }
    }

    batchpir_params_->set_max_bucket_size(get_max_bucket_size());
    balance_buckets();
}
template <size_t N>
std::vector<std::vector<uint64_t>> BatchPIRServer<N>::simeple_hash_with_map()
{
    auto total_buckets = ceil(batchpir_params_->get_cuckoo_factor() * batchpir_params_->get_batch_size());
    auto db_entries = batchpir_params_->get_num_entries();
    auto num_candidates = batchpir_params_->get_num_hash_funcs();
    buckets_.resize(total_buckets);

    std::vector<std::vector<uint64_t>> map(total_buckets);

    for (int i = 0; i < db_entries; i++)
    {
        std::vector<size_t> candidates = utils::get_candidate_buckets(i, num_candidates, total_buckets);
        for (auto b : candidates)
        {
            buckets_[b].push_back(rawdb_[i]);
            map[b].push_back(i);
        }
    }

    // print_stats();

    cout << "get_max_bucket_size: " << get_max_bucket_size() << endl;
    batchpir_params_->set_max_bucket_size(get_max_bucket_size());
    balance_buckets();
    is_simple_hash_ = true;

    return map;
}
template <size_t N>
void BatchPIRServer<N>::balance_buckets()
{
    auto max_bucket = batchpir_params_->get_max_bucket_size();
    auto num_buckets = buckets_.size();
    auto entry_size = batchpir_params_->get_entry_size();

    auto generate_one_entry = [entry_size]() -> std::vector<unsigned char>
    {
        return std::vector<unsigned char>(entry_size, 1);
    };

    for (int i = 0; i < num_buckets; i++)
    {
        auto size = (max_bucket - buckets_[i].size());
        for (int j = 0; j < size; j++)
        {

            buckets_[i].push_back(generate_one_entry());
        }
    }

    is_simple_hash_ = true;
}
template <size_t N>
void BatchPIRServer<N>::print_stats() const
{
    std::cout << "BatchPIRServer: Bucket Statistics:\n";
    std::cout << "===================\n";
    std::cout << "BatchPIRServer: Number of Buckets: " << buckets_.size() << "\n";

    size_t max_bucket_size = get_max_bucket_size();
    size_t min_bucket_size = get_min_bucket_size();
    size_t avg_bucket_size = get_avg_bucket_size();

    std::cout << "Max Bucket Size: " << max_bucket_size << "\n";
    std::cout << "Min Bucket Size: " << min_bucket_size << "\n";
    std::cout << "Avg Bucket Size: " << avg_bucket_size << "\n";
}
template <size_t N>
size_t BatchPIRServer<N>::get_first_dimension_size(size_t num_entries)
{
    size_t cube_root = std::ceil(std::cbrt(num_entries));
    return utils::next_power_of_two(cube_root);
}
template <size_t N>
void BatchPIRServer<N>::prepare_pir_server()
{

    if (!is_simple_hash_)
    {
        throw std::logic_error("Error: Simple hash must be performed before preparing PIR server.");
    }

    size_t max_bucket_size = batchpir_params_->get_max_bucket_size();
    size_t entry_size = batchpir_params_->get_entry_size();
    size_t dim_size = batchpir_params_->get_first_dimension_size();
    auto max_slots = batchpir_params_->get_seal_parameters().poly_modulus_degree();
    auto num_buckets = buckets_.size();
    size_t per_server_capacity = max_slots / dim_size;
    size_t num_servers = ceil(num_buckets * 1.0 / per_server_capacity);

    auto remaining_buckets = num_buckets;
    auto previous_idx = 0;
    for (int i = 0; i < num_servers; i++)
    {
        const size_t offset = std::min(per_server_capacity, num_buckets - previous_idx);
        vector<RawDB> sub_buckets(buckets_.begin() + previous_idx, buckets_.begin() + previous_idx + offset);
        previous_idx += offset;

        PirParams params(max_bucket_size, entry_size, offset, batchpir_params_->get_seal_parameters(), dim_size);
        params.print_values();
        Server server(params, sub_buckets);

        server_list_.push_back(server);
    }
}
template <size_t N>
void BatchPIRServer<N>::set_client_keys(uint32_t client_id, std::pair<seal::GaloisKeys, seal::RelinKeys> keys)
{
    for (int i = 0; i < server_list_.size(); i++)
    {
        server_list_[i].set_client_keys(client_id, keys);
    }
    is_client_keys_set_ = true;
}

template <size_t N>
void BatchPIRServer<N>::get_client_keys()
{

    for (int i = 0; i < server_list_.size(); i++)
    {
        server_list_[i].get_client_keys();
    }
}

template <size_t N>
PIRResponseList BatchPIRServer<N>::generate_response(uint32_t client_id, vector<PIRQuery> queries)
{

    if (!is_client_keys_set_)
    {
        throw std::runtime_error("Error: Client keys not set");
    }
    vector<PIRResponseList> responses;

    for (int i = 0; i < server_list_.size(); i++)
    {
        responses.push_back(server_list_[i].generate_response(client_id, queries[i]));
    }

    return merge_responses(responses, client_id);
}
template <size_t N>
PIRResponseList BatchPIRServer<N>::merge_responses(vector<PIRResponseList> &responses, uint32_t client_id)
{
    return server_list_[0].merge_responses_chunks_buckets(responses, client_id);
}

template <size_t N>
bool BatchPIRServer<N>::check_decoded_entries(vector<std::vector<std::vector<unsigned char>>> entries_list, vector<uint64_t> cuckoo_table)
{
    size_t entry_size = batchpir_params_->get_entry_size();
    size_t dim_size = batchpir_params_->get_first_dimension_size();
    auto max_slots = batchpir_params_->get_seal_parameters().poly_modulus_degree();
    auto num_buckets = cuckoo_table.size();
    size_t per_server_capacity = max_slots / dim_size;
    size_t num_servers = ceil(num_buckets / per_server_capacity);
    auto previous_idx = 0;

    for (int i = 0; i < server_list_.size(); i++)
    {
        const size_t offset = std::min(per_server_capacity, num_buckets - previous_idx);
        vector<uint64_t> sub_buckets(cuckoo_table.begin() + previous_idx, cuckoo_table.begin() + previous_idx + offset);
        previous_idx += offset;
        server_list_[i].check_decoded_entries(entries_list[i], sub_buckets);
    }

    return true;
}

#endif // BATCHPIR_SERVER_H
