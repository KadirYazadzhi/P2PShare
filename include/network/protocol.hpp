#ifndef P2P_PROTOCOL_HPP
#define P2P_PROTOCOL_HPP

#include <cstdint>
#include <array>
#include <vector>
#include "files/manifest.hpp" // Include the full manifest definition
#include "dht/kademlia.hpp" // Include for dht::NodeID

// Using a fixed-size array for the public key and peer_id for simplicity.
constexpr size_t PUBKEY_SIZE = 32;
constexpr size_t PEER_ID_SIZE = 20;

// Protocol version
constexpr uint16_t PROTOCOL_VERSION = 1;

// Message framing: [len (uint32)][msg_type (uint8)][payload...]
constexpr size_t HEADER_SIZE = sizeof(uint32_t) + sizeof(uint8_t);

enum class MessageType : uint8_t {
    // TCP messages
    HANDSHAKE = 0,
    KEEPALIVE = 1,
    QUERY_SEARCH = 2,
    SEARCH_RESPONSE = 3,
    REQUEST_PIECE = 4,
    PIECE = 5,
    BITFIELD = 6,
    HAVE = 7,

    // DHT (UDP) messages
    DHT_PING = 10,
    DHT_PONG = 11,
    DHT_FIND_NODE = 12,
    DHT_FIND_NODE_RESPONSE = 13,
    DHT_STORE = 14,
    DHT_FIND_VALUE = 15,
    DHT_FIND_VALUE_RESPONSE = 16,

    // NAT Traversal messages (UDP)
    HOLE_PUNCH_REQUEST = 20,
    HOLE_PUNCH_RESPONSE = 21,

    // ... other message types
    ERROR_UNSPECIFIED = 255
};

#pragma pack(push, 1)
struct HandshakePayload {
    std::array<uint8_t, PUBKEY_SIZE> pubkey;
    uint16_t protocol_version;
    uint16_t listen_port;
    dht::NodeID peer_id; // Changed to dht::NodeID
    uint32_t features; // Bitmap for features
};

struct QuerySearchPayload {
    hash_t root_hash;
};

struct RequestPiecePayload {
    hash_t root_hash;
    uint32_t piece_index;
};

struct HavePayload {
    hash_t root_hash;
    uint32_t piece_index;
};

// NAT Traversal Payloads (UDP)
struct HolePunchRequestPayload {
    asio::ip::address_v4::bytes_type sender_external_ip;
    uint16_t sender_external_port;
};

struct HolePunchResponsePayload {
    asio::ip::address_v4::bytes_type sender_external_ip;
    uint16_t sender_external_port;
};

// DHT Payloads
struct DhtPingPayload {
    dht::NodeID sender_id;
    uint16_t sender_port; // Port on which sender is listening for UDP
    asio::ip::address_v4::bytes_type sender_external_ip; // External IP
    uint16_t sender_external_port; // External port
};

struct DhtPongPayload {
    dht::NodeID sender_id;
};

struct DhtFindNodePayload {
    dht::NodeID target_id;
};

// DhtFindNodeResponsePayload will be variable size, containing a count and then NodeInfo structs
// For serialization, it will be: [count (uint32)][NodeInfo1][NodeInfo2]...
// NodeInfo: [NodeID (32 bytes)][IP (4/16 bytes)][Port (2 bytes)]

struct DhtStorePayload {
    dht::NodeID key;
    // Value is variable length, will be serialized as [len (uint32)][data...]
};

struct DhtFindValuePayload {
    dht::NodeID key;
};

struct DhtFindNodeResponsePayload {
    dht::NodeID target_id; // The ID that was searched for
    // Followed by variable length list of NodeInfo
};

struct DhtFindValueResponsePayload {
    dht::NodeID key; // The key that was searched for
    // Followed by variable length: [found (uint8)][value_len (uint32)][value_data...] OR [found (uint8)][node_count (uint32)][NodeInfo1][NodeInfo2]...
};

#pragma pack(pop)

// Note: SEARCH_RESPONSE, PIECE, and BITFIELD messages have variable-sized payloads.
// We will handle their serialization/deserialization manually.

#endif //P2P_PROTOCOL_HPP
