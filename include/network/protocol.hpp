#ifndef P2P_PROTOCOL_HPP
#define P2P_PROTOCOL_HPP

#include <cstdint>
#include <array>
#include <vector>
#include "files/manifest.hpp" // Include the full manifest definition

// Using a fixed-size array for the public key and peer_id for simplicity.
constexpr size_t PUBKEY_SIZE = 32;
constexpr size_t PEER_ID_SIZE = 20;

// Protocol version
constexpr uint16_t PROTOCOL_VERSION = 1;

// Message framing: [len (uint32)][msg_type (uint8)][payload...]
constexpr size_t HEADER_SIZE = sizeof(uint32_t) + sizeof(uint8_t);

enum class MessageType : uint8_t {
    HANDSHAKE = 0,
    KEEPALIVE = 1,
    QUERY_SEARCH = 2,
    SEARCH_RESPONSE = 3,
    REQUEST_PIECE = 4,
    PIECE = 5,
    BITFIELD = 6,
    HAVE = 7,
    // ... other message types
    ERROR_UNSPECIFIED = 255
};

#pragma pack(push, 1)
struct HandshakePayload {
    std::array<uint8_t, PUBKEY_SIZE> pubkey;
    uint16_t protocol_version;
    uint16_t listen_port;
    std::array<uint8_t, PEER_ID_SIZE> peer_id;
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
#pragma pack(pop)

// Note: SEARCH_RESPONSE, PIECE, and BITFIELD messages have variable-sized payloads.
// We will handle their serialization/deserialization manually.

#endif //P2P_PROTOCOL_HPP
