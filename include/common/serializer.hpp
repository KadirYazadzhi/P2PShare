#ifndef P2P_SERIALIZER_HPP
#define P2P_SERIALIZER_HPP

#include "../files/manifest.hpp"
#include <vector>

namespace Serializer {

/**
 * @brief Serializes a Manifest object into a byte vector.
 */
std::vector<uint8_t> serialize_manifest(const Manifest& m);

/**
 * @brief Deserializes a byte vector into a Manifest object.
 */
Manifest deserialize_manifest(const std::vector<uint8_t>& buffer);

} // namespace Serializer

#endif //P2P_SERIALIZER_HPP
