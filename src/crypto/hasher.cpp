#include "crypto/hasher.hpp"
#include <openssl/evp.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <memory>

namespace Hasher {

// Helper deleter
struct EVP_MD_CTX_Deleter { void operator()(EVP_MD_CTX* c) { EVP_MD_CTX_free(c); } };

hash_t sha256(const std::vector<uint8_t>& data) {
    hash_t hash;
    std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> ctx(EVP_MD_CTX_new());
    
    if (!ctx) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    if (!EVP_DigestInit_ex(ctx.get(), EVP_sha256(), NULL)) {
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }

    if (!EVP_DigestUpdate(ctx.get(), data.data(), data.size())) {
        throw std::runtime_error("EVP_DigestUpdate failed");
    }

    unsigned int len = 0;
    if (!EVP_DigestFinal_ex(ctx.get(), hash.data(), &len)) {
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }
    
    return hash;
}

hash_t sha256(const std::string& data) {
    std::vector<uint8_t> data_vec(data.begin(), data.end());
    return sha256(data_vec);
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
