#include "common/serializer.hpp"
#include <cstring> // For std::memcpy
#include <optional>

namespace Serializer {

std::vector<uint8_t> serialize_manifest(const Manifest& m) {
    std::vector<uint8_t> buffer;
    buffer.reserve(
        sizeof(uint32_t) + m.file_name.length() +
        sizeof(uint64_t) + sizeof(uint32_t) * 2 +
        HASH_SIZE + m.piece_hashes.size() * HASH_SIZE
    );

    // file_name
    uint32_t name_len = m.file_name.length();
    buffer.insert(buffer.end(), (uint8_t*)&name_len, (uint8_t*)&name_len + sizeof(uint32_t));
    buffer.insert(buffer.end(), m.file_name.begin(), m.file_name.end());
    // file_size
    buffer.insert(buffer.end(), (uint8_t*)&m.file_size, (uint8_t*)&m.file_size + sizeof(uint64_t));
    // piece_size
    buffer.insert(buffer.end(), (uint8_t*)&m.piece_size, (uint8_t*)&m.piece_size + sizeof(uint32_t));
    // pieces_count
    buffer.insert(buffer.end(), (uint8_t*)&m.pieces_count, (uint8_t*)&m.pieces_count + sizeof(uint32_t));
    // root_hash
    buffer.insert(buffer.end(), m.root_hash.begin(), m.root_hash.end());
    // piece_hashes
    for(const auto& h : m.piece_hashes) {
        buffer.insert(buffer.end(), h.begin(), h.end());
    }
    return buffer;
}

Manifest deserialize_manifest(const std::vector<uint8_t>& buffer) {
    Manifest m;
    size_t offset = 0;
    // file_name
    uint32_t name_len;
    std::memcpy(&name_len, buffer.data() + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    m.file_name.assign(buffer.begin() + offset, buffer.begin() + offset + name_len);
    offset += name_len;
    // file_size
    std::memcpy(&m.file_size, buffer.data() + offset, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    // piece_size
    std::memcpy(&m.piece_size, buffer.data() + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    // pieces_count
    std::memcpy(&m.pieces_count, buffer.data() + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    // root_hash
    std::memcpy(m.root_hash.data(), buffer.data() + offset, HASH_SIZE);
    offset += HASH_SIZE;
    // piece_hashes
    m.piece_hashes.resize(m.pieces_count);
    for(uint32_t i = 0; i < m.pieces_count; ++i) {
        std::memcpy(m.piece_hashes[i].data(), buffer.data() + offset, HASH_SIZE);
        offset += HASH_SIZE;
    }
    return m;
}

std::vector<uint8_t> serialize_dht_ping_payload(const DhtPingPayload& p) {
    std::vector<uint8_t> buffer;
    buffer.reserve(dht::NODE_ID_SIZE + sizeof(uint16_t));
    buffer.insert(buffer.end(), p.sender_id.begin(), p.sender_id.end());
    buffer.insert(buffer.end(), (uint8_t*)&p.sender_port, (uint8_t*)&p.sender_port + sizeof(uint16_t));
    return buffer;
}

DhtPingPayload deserialize_dht_ping_payload(const std::vector<uint8_t>& buffer) {
    DhtPingPayload p;
    size_t offset = 0;
    std::memcpy(p.sender_id.data(), buffer.data() + offset, dht::NODE_ID_SIZE);
    offset += dht::NODE_ID_SIZE;
    std::memcpy(&p.sender_port, buffer.data() + offset, sizeof(uint16_t));
    return p;
}

std::vector<uint8_t> serialize_dht_pong_payload(const DhtPongPayload& p) {
    std::vector<uint8_t> buffer;
    buffer.reserve(dht::NODE_ID_SIZE);
    buffer.insert(buffer.end(), p.sender_id.begin(), p.sender_id.end());
    return buffer;
}

DhtPongPayload deserialize_dht_pong_payload(const std::vector<uint8_t>& buffer) {
    DhtPongPayload p;
    size_t offset = 0;
    std::memcpy(p.sender_id.data(), buffer.data() + offset, dht::NODE_ID_SIZE);
    return p;
}

std::vector<uint8_t> serialize_dht_find_node_payload(const DhtFindNodePayload& p) {
    std::vector<uint8_t> buffer;
    buffer.reserve(dht::NODE_ID_SIZE);
    buffer.insert(buffer.end(), p.target_id.begin(), p.target_id.end());
    return buffer;
}

DhtFindNodePayload deserialize_dht_find_node_payload(const std::vector<uint8_t>& buffer) {
    DhtFindNodePayload p;
    std::memcpy(p.target_id.data(), buffer.data(), dht::NODE_ID_SIZE);
    return p;
}

std::vector<uint8_t> serialize_dht_find_node_response_payload(const dht::NodeID& target_id, const std::vector<dht::NodeInfo>& nodes) {
    std::vector<uint8_t> buffer;
    buffer.reserve(dht::NODE_ID_SIZE + sizeof(uint32_t) + nodes.size() * (dht::NODE_ID_SIZE + 16 + sizeof(uint16_t))); // Rough estimate

    buffer.insert(buffer.end(), target_id.begin(), target_id.end());

    uint32_t count = nodes.size();
    buffer.insert(buffer.end(), (uint8_t*)&count, (uint8_t*)&count + sizeof(uint32_t));

    for (const auto& node : nodes) {
        buffer.insert(buffer.end(), node.id.begin(), node.id.end());
        // Serialize IP address
        asio::ip::address_v4::bytes_type ipv4_bytes;
        asio::ip::address_v6::bytes_type ipv6_bytes;
        if (node.endpoint.address().is_v4()) {
            ipv4_bytes = node.endpoint.address().to_v4().to_bytes();
            buffer.insert(buffer.end(), ipv4_bytes.begin(), ipv4_bytes.end());
        } else { // is_v6
            ipv6_bytes = node.endpoint.address().to_v6().to_bytes();
            buffer.insert(buffer.end(), ipv6_bytes.begin(), ipv6_bytes.end());
        }
        uint16_t port = node.endpoint.port();
        buffer.insert(buffer.end(), (uint8_t*)&port, (uint8_t*)&port + sizeof(uint16_t));
    }
    return buffer;
}

std::pair<dht::NodeID, std::vector<dht::NodeInfo>> deserialize_dht_find_node_response_payload(const std::vector<uint8_t>& buffer) {
    dht::NodeID target_id;
    std::vector<dht::NodeInfo> nodes;
    size_t offset = 0;

    std::memcpy(target_id.data(), buffer.data() + offset, dht::NODE_ID_SIZE);
    offset += dht::NODE_ID_SIZE;

    uint32_t count;
    std::memcpy(&count, buffer.data() + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    for (uint32_t i = 0; i < count; ++i) {
        dht::NodeID id;
        std::memcpy(id.data(), buffer.data() + offset, dht::NODE_ID_SIZE);
        offset += dht::NODE_ID_SIZE;

        asio::ip::address addr;
        // Assuming IPv4 for simplicity for now, need to handle IPv6
        asio::ip::address_v4::bytes_type ipv4_bytes;
        std::memcpy(ipv4_bytes.data(), buffer.data() + offset, ipv4_bytes.size());
        addr = asio::ip::address_v4(ipv4_bytes);
        offset += ipv4_bytes.size();

        uint16_t port;
        std::memcpy(&port, buffer.data() + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);

        nodes.push_back({id, asio::ip::udp::endpoint(addr, port)});
    }
    return {target_id, nodes};
}

std::vector<uint8_t> serialize_dht_store_payload(const dht::NodeID& key, const std::vector<uint8_t>& value) {
    std::vector<uint8_t> buffer;
    buffer.reserve(dht::NODE_ID_SIZE + sizeof(uint32_t) + value.size());
    buffer.insert(buffer.end(), key.begin(), key.end());
    uint32_t value_len = value.size();
    buffer.insert(buffer.end(), (uint8_t*)&value_len, (uint8_t*)&value_len + sizeof(uint32_t));
    buffer.insert(buffer.end(), value.begin(), value.end());
    return buffer;
}

std::pair<dht::NodeID, std::vector<uint8_t>> deserialize_dht_store_payload(const std::vector<uint8_t>& buffer) {
    dht::NodeID key;
    std::vector<uint8_t> value;
    size_t offset = 0;

    std::memcpy(key.data(), buffer.data() + offset, dht::NODE_ID_SIZE);
    offset += dht::NODE_ID_SIZE;

    uint32_t value_len;
    std::memcpy(&value_len, buffer.data() + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    value.assign(buffer.begin() + offset, buffer.begin() + offset + value_len);
    return {key, value};
}

std::vector<uint8_t> serialize_dht_find_value_payload(const DhtFindValuePayload& p) {
    std::vector<uint8_t> buffer;
    buffer.reserve(dht::NODE_ID_SIZE);
    buffer.insert(buffer.end(), p.key.begin(), p.key.end());
    return buffer;
}

DhtFindValuePayload deserialize_dht_find_value_payload(const std::vector<uint8_t>& buffer) {
    DhtFindValuePayload p;
    std::memcpy(p.key.data(), buffer.data(), dht::NODE_ID_SIZE);
    return p;
}

std::vector<uint8_t> serialize_dht_find_value_response_payload(const dht::NodeID& key, bool found, const std::optional<std::vector<uint8_t>>& value, const std::vector<dht::NodeInfo>& closest_nodes) {
    std::vector<uint8_t> buffer;
    buffer.reserve(dht::NODE_ID_SIZE + sizeof(uint8_t) + (found ? (sizeof(uint32_t) + value->size()) : (sizeof(uint32_t) + closest_nodes.size() * (dht::NODE_ID_SIZE + 16 + sizeof(uint16_t))))); // Rough estimate

    buffer.insert(buffer.end(), key.begin(), key.end());
    buffer.push_back(found ? 1 : 0); // 1 byte for 'found' flag

    if (found && value) {
        uint32_t value_len = value->size();
        buffer.insert(buffer.end(), (uint8_t*)&value_len, (uint8_t*)&value_len + sizeof(uint32_t));
        buffer.insert(buffer.end(), value->begin(), value->end());
    } else {
        // If not found, or no value, send closest nodes
        std::vector<uint8_t> nodes_data = serialize_dht_find_node_response_payload(key, closest_nodes); // Pass key here
        buffer.insert(buffer.end(), nodes_data.begin(), nodes_data.end());
    }
    return buffer;
}

std::tuple<dht::NodeID, bool, std::optional<std::vector<uint8_t>>, std::vector<dht::NodeInfo>> deserialize_dht_find_value_response_payload(const std::vector<uint8_t>& buffer) {
    dht::NodeID key;
    bool found;
    std::optional<std::vector<uint8_t>> value;
    std::vector<dht::NodeInfo> closest_nodes;
    size_t offset = 0;

    std::memcpy(key.data(), buffer.data() + offset, dht::NODE_ID_SIZE);
    offset += dht::NODE_ID_SIZE;

    found = (buffer[offset] == 1);
    offset += sizeof(uint8_t); // Skip 'found' flag

    if (found) {
        uint32_t value_len;
        std::memcpy(&value_len, buffer.data() + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        value = std::vector<uint8_t>(buffer.begin() + offset, buffer.begin() + offset + value_len);
    } else {
        // If not found, the rest of the payload is closest nodes
        std::vector<uint8_t> nodes_data(buffer.begin() + offset, buffer.end());
        auto [deserialized_key, deserialized_nodes] = deserialize_dht_find_node_response_payload(nodes_data); // Get key and nodes
        closest_nodes = deserialized_nodes;
    }
    return {key, found, value, closest_nodes};
}

std::vector<uint8_t> serialize_have_payload(const hash_t& root_hash, uint32_t piece_index) {
    std::vector<uint8_t> buffer;
    buffer.reserve(HASH_SIZE + sizeof(uint32_t));
    buffer.insert(buffer.end(), root_hash.begin(), root_hash.end());
    buffer.insert(buffer.end(), (uint8_t*)&piece_index, (uint8_t*)&piece_index + sizeof(uint32_t));
    return buffer;
}

std::pair<hash_t, uint32_t> deserialize_have_payload(const std::vector<uint8_t>& buffer) {
    hash_t root_hash;
    uint32_t piece_index;
    size_t offset = 0;

    std::memcpy(root_hash.data(), buffer.data() + offset, HASH_SIZE);
    offset += HASH_SIZE;

    std::memcpy(&piece_index, buffer.data() + offset, sizeof(uint32_t));
    
    return {root_hash, piece_index};
}

} // namespace Serializer
