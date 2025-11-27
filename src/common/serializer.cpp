#include "common/serializer.hpp"
#include <cstring> // For std::memcpy
#include <optional>
#include <algorithm> // For std::copy

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
    // signer_pubkey
    uint32_t pk_len = m.signer_pubkey.size();
    buffer.insert(buffer.end(), (uint8_t*)&pk_len, (uint8_t*)&pk_len + sizeof(uint32_t));
    buffer.insert(buffer.end(), m.signer_pubkey.begin(), m.signer_pubkey.end());
    // signature
    uint32_t sig_len = m.signature.size();
    buffer.insert(buffer.end(), (uint8_t*)&sig_len, (uint8_t*)&sig_len + sizeof(uint32_t));
    buffer.insert(buffer.end(), m.signature.begin(), m.signature.end());

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
    // signer_pubkey
    if (offset < buffer.size()) {
        uint32_t pk_len;
        std::memcpy(&pk_len, buffer.data() + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        if (offset + pk_len <= buffer.size()) {
            m.signer_pubkey.assign(buffer.begin() + offset, buffer.begin() + offset + pk_len);
            offset += pk_len;
        }
    }
    // signature
    if (offset < buffer.size()) {
        uint32_t sig_len;
        std::memcpy(&sig_len, buffer.data() + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        if (offset + sig_len <= buffer.size()) {
            m.signature.assign(buffer.begin() + offset, buffer.begin() + offset + sig_len);
            offset += sig_len;
        }
    }
    return m;
}

std::vector<uint8_t> serialize_dht_ping_payload(const DhtPingPayload& p) {
    std::vector<uint8_t> buffer;
    buffer.reserve(dht::NODE_ID_SIZE + sizeof(uint16_t) + sizeof(asio::ip::address_v4::bytes_type) + sizeof(uint16_t));
    buffer.insert(buffer.end(), p.sender_id.begin(), p.sender_id.end());
    buffer.insert(buffer.end(), (uint8_t*)&p.sender_port, (uint8_t*)&p.sender_port + sizeof(uint16_t));
    buffer.insert(buffer.end(), p.sender_external_ip.begin(), p.sender_external_ip.end());
    buffer.insert(buffer.end(), (uint8_t*)&p.sender_external_port, (uint8_t*)&p.sender_external_port + sizeof(uint16_t));
    return buffer;
}

DhtPingPayload deserialize_dht_ping_payload(const std::vector<uint8_t>& buffer) {
    DhtPingPayload p;
    size_t offset = 0;
    std::memcpy(p.sender_id.data(), buffer.data() + offset, dht::NODE_ID_SIZE);
    offset += dht::NODE_ID_SIZE;
    std::memcpy(&p.sender_port, buffer.data() + offset, sizeof(uint16_t));
    offset += sizeof(uint16_t);
    std::memcpy(p.sender_external_ip.data(), buffer.data() + offset, sizeof(asio::ip::address_v4::bytes_type));
    offset += sizeof(asio::ip::address_v4::bytes_type);
    std::memcpy(&p.sender_external_port, buffer.data() + offset, sizeof(uint16_t));
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
        // Serialize endpoint (address and port)
        asio::ip::address_v4::bytes_type addr_bytes = node.endpoint.address().to_v4().to_bytes(); // Assuming IPv4
        buffer.insert(buffer.end(), addr_bytes.begin(), addr_bytes.end());
        uint16_t port = node.endpoint.port();
        buffer.insert(buffer.end(), (uint8_t*)&port, (uint8_t*)&port + sizeof(uint16_t));

        // Serialize external_endpoint (optional)
        if (node.external_endpoint) {
            buffer.push_back(1); // Flag: external_endpoint is present
            asio::ip::address_v4::bytes_type ext_addr_bytes = node.external_endpoint->address().to_v4().to_bytes();
            buffer.insert(buffer.end(), ext_addr_bytes.begin(), ext_addr_bytes.end());
            uint16_t ext_port = node.external_endpoint->port();
            buffer.insert(buffer.end(), (uint8_t*)&ext_port, (uint8_t*)&ext_port + sizeof(uint16_t));
        } else {
            buffer.push_back(0); // Flag: external_endpoint is not present
        }
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
        asio::ip::address_v4::bytes_type ipv4_bytes;
        std::memcpy(ipv4_bytes.data(), buffer.data() + offset, ipv4_bytes.size());
        addr = asio::ip::address_v4(ipv4_bytes);
        offset += ipv4_bytes.size();

        uint16_t port;
        std::memcpy(&port, buffer.data() + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);

        std::optional<asio::ip::udp::endpoint> external_endpoint;
        uint8_t has_external_endpoint;
        if (offset + sizeof(uint8_t) <= buffer.size()) { // Check if flag is available
            has_external_endpoint = buffer[offset];
            offset += sizeof(uint8_t);
            if (has_external_endpoint == 1) {
                asio::ip::address_v4::bytes_type ext_ipv4_bytes;
                std::memcpy(ext_ipv4_bytes.data(), buffer.data() + offset, ext_ipv4_bytes.size());
                offset += ext_ipv4_bytes.size();
                uint16_t ext_port;
                std::memcpy(&ext_port, buffer.data() + offset, sizeof(uint16_t));
                offset += sizeof(uint16_t);
                external_endpoint = asio::ip::udp::endpoint(asio::ip::address_v4(ext_ipv4_bytes), ext_port);
            }
        }
        nodes.push_back({id, asio::ip::udp::endpoint(addr, port), external_endpoint});
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

std::vector<uint8_t> serialize_handshake_payload(const HandshakePayload& p) {
    std::vector<uint8_t> buffer;
    buffer.reserve(PUBKEY_SIZE + sizeof(uint16_t) + sizeof(uint16_t) + dht::NODE_ID_SIZE + sizeof(uint32_t));

    buffer.insert(buffer.end(), p.pubkey.begin(), p.pubkey.end());
    buffer.insert(buffer.end(), (uint8_t*)&p.protocol_version, (uint8_t*)&p.protocol_version + sizeof(uint16_t));
    buffer.insert(buffer.end(), (uint8_t*)&p.listen_port, (uint8_t*)&p.listen_port + sizeof(uint16_t));
    buffer.insert(buffer.end(), p.peer_id.begin(), p.peer_id.end());
    buffer.insert(buffer.end(), (uint8_t*)&p.features, (uint8_t*)&p.features + sizeof(uint32_t));

    return buffer;
}

HandshakePayload deserialize_handshake_payload(const std::vector<uint8_t>& buffer) {
    HandshakePayload p;
    size_t offset = 0;

    std::memcpy(p.pubkey.data(), buffer.data() + offset, PUBKEY_SIZE);
    offset += PUBKEY_SIZE;

    std::memcpy(&p.protocol_version, buffer.data() + offset, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    std::memcpy(&p.listen_port, buffer.data() + offset, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    std::memcpy(p.peer_id.data(), buffer.data() + offset, dht::NODE_ID_SIZE);
    offset += dht::NODE_ID_SIZE;

    std::memcpy(&p.features, buffer.data() + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    return p;
}

std::vector<uint8_t> serialize_request_piece_payload(const RequestPiecePayload& p) {
    std::vector<uint8_t> buffer(sizeof(RequestPiecePayload));
    std::memcpy(buffer.data(), &p, sizeof(RequestPiecePayload));
    return buffer;
}

RequestPiecePayload deserialize_request_piece_payload(const std::vector<uint8_t>& buffer) {
    if (buffer.size() != sizeof(RequestPiecePayload)) {
        throw std::runtime_error("Invalid buffer size for request piece payload deserialization");
    }
    RequestPiecePayload p;
    std::memcpy(&p, buffer.data(), sizeof(RequestPiecePayload));
    return p;
}

std::vector<uint8_t> serialize_piece_payload(const hash_t& root_hash, uint32_t piece_index, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> buffer;
    buffer.reserve(sizeof(hash_t) + sizeof(uint32_t) + data.size());

    // Append root_hash
    buffer.insert(buffer.end(), root_hash.begin(), root_hash.end());

    // Append piece_index
    const uint8_t* index_bytes = reinterpret_cast<const uint8_t*>(&piece_index);
    buffer.insert(buffer.end(), index_bytes, index_bytes + sizeof(uint32_t));

    // Append piece data
    buffer.insert(buffer.end(), data.begin(), data.end());

    return buffer;
}

std::tuple<hash_t, uint32_t, std::vector<uint8_t>> deserialize_piece_payload(const std::vector<uint8_t>& buffer) {
    if (buffer.size() < sizeof(hash_t) + sizeof(uint32_t)) {
        throw std::runtime_error("Invalid buffer size for piece payload deserialization");
    }

    hash_t root_hash;
    uint32_t piece_index;
    std::vector<uint8_t> data;
    size_t offset = 0;

    // Extract root_hash
    std::copy(buffer.begin() + offset, buffer.begin() + offset + sizeof(hash_t), root_hash.begin());
    offset += sizeof(hash_t);

    // Extract piece_index
    piece_index = *reinterpret_cast<const uint32_t*>(&buffer[offset]);
    offset += sizeof(uint32_t);

    // The rest is the data
    data.assign(buffer.begin() + offset, buffer.end());

    return {root_hash, piece_index, data};
}

std::vector<uint8_t> serialize_bitfield_payload(const hash_t& root_hash, const Bitfield& bitfield) {
    std::vector<uint8_t> buffer;
    buffer.reserve(sizeof(hash_t) + sizeof(uint64_t) + bitfield.get_bytes().size());

    // Append root_hash
    buffer.insert(buffer.end(), root_hash.begin(), root_hash.end());

    // Append num_bits
    uint64_t num_bits = bitfield.get_num_bits();
    const uint8_t* num_bits_bytes = reinterpret_cast<const uint8_t*>(&num_bits);
    buffer.insert(buffer.end(), num_bits_bytes, num_bits_bytes + sizeof(uint64_t));

    // Append bitfield data
    buffer.insert(buffer.end(), bitfield.get_bytes().begin(), bitfield.get_bytes().end());

    return buffer;
}

std::tuple<hash_t, Bitfield> deserialize_bitfield_payload(const std::vector<uint8_t>& buffer) {
    if (buffer.size() < sizeof(hash_t) + sizeof(uint64_t)) {
        throw std::runtime_error("Invalid buffer size for bitfield payload deserialization");
    }

    hash_t root_hash;
    uint64_t num_bits;
    std::vector<uint8_t> bitfield_bytes;
    size_t offset = 0;

    // Extract root_hash
    std::copy(buffer.begin() + offset, buffer.begin() + offset + sizeof(hash_t), root_hash.begin());
    offset += sizeof(hash_t);

    // Extract num_bits
    num_bits = *reinterpret_cast<const uint64_t*>(&buffer[offset]);
    offset += sizeof(uint64_t);

    // The rest is the bitfield data
    bitfield_bytes.assign(buffer.begin() + offset, buffer.end());

    Bitfield bitfield(num_bits, bitfield_bytes);

    return {root_hash, bitfield};
}

std::vector<uint8_t> serialize_hole_punch_request_payload(const HolePunchRequestPayload& p) {
    std::vector<uint8_t> buffer(sizeof(HolePunchRequestPayload));
    std::memcpy(buffer.data(), &p, sizeof(HolePunchRequestPayload));
    return buffer;
}

HolePunchRequestPayload deserialize_hole_punch_request_payload(const std::vector<uint8_t>& buffer) {
    if (buffer.size() != sizeof(HolePunchRequestPayload)) {
        throw std::runtime_error("Invalid buffer size for hole punch request payload deserialization");
    }
    HolePunchRequestPayload p;
    std::memcpy(&p, buffer.data(), sizeof(HolePunchRequestPayload));
    return p;
}

std::vector<uint8_t> serialize_hole_punch_response_payload(const HolePunchResponsePayload& p) {
    std::vector<uint8_t> buffer(sizeof(HolePunchResponsePayload));
    std::memcpy(buffer.data(), &p, sizeof(HolePunchResponsePayload));
    return buffer;
}

HolePunchResponsePayload deserialize_hole_punch_response_payload(const std::vector<uint8_t>& buffer) {
    if (buffer.size() != sizeof(HolePunchResponsePayload)) {
        throw std::runtime_error("Invalid buffer size for hole punch response payload deserialization");
    }
    HolePunchResponsePayload p;
    std::memcpy(&p, buffer.data(), sizeof(HolePunchResponsePayload));
    return p;
}

} // namespace Serializer