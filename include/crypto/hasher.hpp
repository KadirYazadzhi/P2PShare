#ifndef P2P_HASHER_HPP
#define P2P_HASHER_HPP

#include <vector>
#include <string>
#include "../files/manifest.hpp" // For hash_t

namespace Hasher {

/**
 * @brief Calculates the SHA-256 hash of a data buffer.
 * @param data The data to hash.
 * @return A 32-byte SHA-256 hash.
 */
hash_t sha256(const std::vector<uint8_t>& data);

    // Calculate SHA-256 hash of a string
    hash_t sha256(const std::string& data);

    // Helpers
    hash_t hex_to_hash(const std::string& hex);
    std::string hash_to_hex(const hash_t& hash);

} // namespace Hasher

hash_t hex_to_hash(const std::string& hex_str);

#endif //P2P_HASHER_HPP
