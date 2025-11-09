#include "crypto/hasher.hpp"
#include <openssl/sha.h>
#include <stdexcept>

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

} // namespace Hasher
