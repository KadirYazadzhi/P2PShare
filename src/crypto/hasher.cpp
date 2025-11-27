#include "crypto/hasher.hpp"
#include <openssl/sha.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>

namespace Hasher {

hash_t sha256(const std::vector<uint8_t>& data) {
    hash_t hash;
    SHA256_CTX sha256;
    if (!SHA256_Init(&sha256)) {
        throw std::runtime_error("SHA256_Init failed");
    }
    if (!SHA256_Update(&sha256, data.data(), data.size())) {
        throw std::runtime_error("SHA256_Update failed");
    }
    if (!SHA256_Final(hash.data(), &sha256)) {
        throw std::runtime_error("SHA256_Final failed");
    }
    return hash;
}

hash_t sha256(const std::string& data) {
    hash_t hash;
    SHA256_CTX sha256;
    if (!SHA256_Init(&sha256)) {
        throw std::runtime_error("SHA256_Init failed");
    }
    if (!SHA256_Update(&sha256, data.c_str(), data.size())) {
        throw std::runtime_error("SHA256_Update failed");
    }
    if (!SHA256_Final(hash.data(), &sha256)) {
        throw std::runtime_error("SHA256_Final failed");
    }
    return hash;
}

hash_t hex_to_hash(const std::string& hex_str) {
    hash_t hash;
    for (size_t i = 0; i < HASH_SIZE; ++i) {
        hash[i] = static_cast<uint8_t>(std::stoul(hex_str.substr(i * 2, 2), nullptr, 16));
    }
    return hash;
}

std::string hash_to_hex(const hash_t& hash) {
    std::stringstream ss;
    for (uint8_t byte : hash) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return ss.str();
}

} // namespace Hasher
