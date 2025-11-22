#ifndef P2P_SERIALIZER_HPP
#define P2P_SERIALIZER_HPP

#include "../files/manifest.hpp"
#include "../network/protocol.hpp" // For DHT payload structs
#include <vector>
#include <optional>

namespace Serializer {

/**
 * @brief Serializes a Manifest object into a byte vector.
 */
std::vector<uint8_t> serialize_manifest(const Manifest& m);

/**
 * @brief Deserializes a byte vector into a Manifest object.
 */
Manifest deserialize_manifest(const std::vector<uint8_t>& buffer);

/**
 * @brief Serializes a DhtPingPayload object into a byte vector.
 */
std::vector<uint8_t> serialize_dht_ping_payload(const DhtPingPayload& p);

/**
 * @brief Deserializes a byte vector into a DhtPingPayload object.
 */
DhtPingPayload deserialize_dht_ping_payload(const std::vector<uint8_t>& buffer);

/**
 * @brief Serializes a DhtPongPayload object into a byte vector.
 */
std::vector<uint8_t> serialize_dht_pong_payload(const DhtPongPayload& p);

/**
 * @brief Deserializes a byte vector into a DhtPongPayload object.
 */
DhtPongPayload deserialize_dht_pong_payload(const std::vector<uint8_t>& buffer);

/**
 * @brief Serializes a DhtFindNodePayload object into a byte vector.
 */
std::vector<uint8_t> serialize_dht_find_node_payload(const DhtFindNodePayload& p);

/**
 * @brief Deserializes a byte vector into a DhtFindNodePayload object.
 */
DhtFindNodePayload deserialize_dht_find_node_payload(const std::vector<uint8_t>& buffer);

/**
 * @brief Serializes a DhtFindNodeResponsePayload (list of NodeInfo) into a byte vector.
 */
std::vector<uint8_t> serialize_dht_find_node_response_payload(const std::vector<dht::NodeInfo>& nodes);

/**
 * @brief Serializes a list of NodeInfo into a byte vector for DHT_FIND_NODE_RESPONSE.
 */
std::vector<uint8_t> serialize_dht_find_node_response_payload(const dht::NodeID& target_id, const std::vector<dht::NodeInfo>& nodes);

/**
 * @brief Deserializes a byte vector into a list of NodeInfo for DHT_FIND_NODE_RESPONSE.
 */
std::pair<dht::NodeID, std::vector<dht::NodeInfo>> deserialize_dht_find_node_response_payload(const std::vector<uint8_t>& buffer);

/**
 * @brief Serializes a DhtStorePayload object into a byte vector.
 */
std::vector<uint8_t> serialize_dht_store_payload(const dht::NodeID& key, const std::vector<uint8_t>& value);

/**
 * @brief Deserializes a byte vector into a DhtStorePayload object.
 */
std::pair<dht::NodeID, std::vector<uint8_t>> deserialize_dht_store_payload(const std::vector<uint8_t>& buffer);

/**
 * @brief Serializes a DhtFindValuePayload object into a byte vector.
 */
std::vector<uint8_t> serialize_dht_find_value_payload(const DhtFindValuePayload& p);

/**
 * @brief Deserializes a byte vector into a DhtFindValuePayload object.
 */
DhtFindValuePayload deserialize_dht_find_value_payload(const std::vector<uint8_t>& buffer);

/**
 * @brief Serializes a DhtFindValueResponsePayload object into a byte vector.
 */
std::vector<uint8_t> serialize_dht_find_value_response_payload(const dht::NodeID& key, bool found, const std::optional<std::vector<uint8_t>>& value, const std::vector<dht::NodeInfo>& closest_nodes);

/**
 * @brief Deserializes a byte vector into a DhtFindValueResponsePayload object.
 */
std::tuple<dht::NodeID, bool, std::optional<std::vector<uint8_t>>, std::vector<dht::NodeInfo>> deserialize_dht_find_value_response_payload(const std::vector<uint8_t>& buffer);

/**
 * @brief Serializes a HavePayload object into a byte vector.
 */
std::vector<uint8_t> serialize_have_payload(const hash_t& root_hash, uint32_t piece_index);

/**
 * @brief Deserializes a byte vector into a HavePayload object.
 */
std::pair<hash_t, uint32_t> deserialize_have_payload(const std::vector<uint8_t>& buffer);

} // namespace Serializer

#endif //P2P_SERIALIZER_HPP
