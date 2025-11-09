#include "common/serializer.hpp"
#include <cstring> // For std::memcpy

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

} // namespace Serializer
