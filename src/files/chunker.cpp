#include "files/chunker.hpp"
#include "crypto/hasher.hpp"
#include <fstream>
#include <stdexcept>
#include <vector>
#include <cmath>

Manifest Chunker::create_manifest_from_file(const fs::path& file_path, uint32_t piece_size) {
    if (!fs::exists(file_path) || !fs::is_regular_file(file_path)) {
        throw std::runtime_error("File does not exist or is not a regular file: " + file_path.string());
    }

    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + file_path.string());
    }

    Manifest manifest;
    manifest.file_name = file_path.filename().string();
    manifest.file_size = fs::file_size(file_path);
    manifest.piece_size = piece_size;
    manifest.pieces_count = static_cast<uint32_t>(std::ceil(static_cast<double>(manifest.file_size) / piece_size));

    std::vector<uint8_t> piece_buffer(piece_size);
    std::string all_piece_hashes_concatenated;
    all_piece_hashes_concatenated.reserve(manifest.pieces_count * HASH_SIZE);

    for (uint32_t i = 0; i < manifest.pieces_count; ++i) {
        file.read(reinterpret_cast<char*>(piece_buffer.data()), piece_size);
        std::streamsize bytes_read = file.gcount();

        // If we read less than a full piece, resize the buffer for hashing
        if (bytes_read < piece_size) {
            piece_buffer.resize(bytes_read);
        }

        hash_t piece_hash = Hasher::sha256(piece_buffer);
        manifest.piece_hashes.push_back(piece_hash);
        all_piece_hashes_concatenated.append(reinterpret_cast<const char*>(piece_hash.data()), HASH_SIZE);
    }

    // Calculate root hash (as SHA-256 of concatenated piece hashes)
    manifest.root_hash = Hasher::sha256(all_piece_hashes_concatenated);

    return manifest;
}
