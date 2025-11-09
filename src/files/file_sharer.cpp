#include "files/file_sharer.hpp"
#include "files/chunker.hpp"
#include <fstream>

Manifest& FileSharer::share_file(const std::filesystem::path& file_path) {
    Manifest manifest = Chunker::create_manifest_from_file(file_path);
    
    std::lock_guard<std::mutex> lock(mutex_);
    const auto& root_hash = manifest.root_hash;
    file_paths_[root_hash] = file_path;
    auto [it, success] = shared_manifests_.emplace(root_hash, std::move(manifest));
    
    return it->second;
}

std::optional<Manifest> FileSharer::get_manifest(const hash_t& root_hash) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = shared_manifests_.find(root_hash);
    if (it != shared_manifests_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<uint8_t> FileSharer::get_piece(const hash_t& root_hash, uint32_t piece_index) {
    std::optional<Manifest> manifest_opt;
    std::filesystem::path file_path;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto manifest_it = shared_manifests_.find(root_hash);
        if (manifest_it == shared_manifests_.end()) {
            throw std::runtime_error("File not shared.");
        }
        manifest_opt = manifest_it->second;

        auto path_it = file_paths_.find(root_hash);
        if (path_it == file_paths_.end()) {
            throw std::runtime_error("File path not found for shared file.");
        }
        file_path = path_it->second;
    }

    const auto& manifest = *manifest_opt;
    if (piece_index >= manifest.pieces_count) {
        throw std::runtime_error("Piece index out of bounds.");
    }

    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open shared file for reading.");
    }

    uint64_t offset = static_cast<uint64_t>(piece_index) * manifest.piece_size;
    file.seekg(offset);

    uint64_t bytes_to_read = manifest.piece_size;
    // Adjust for the last piece, which might be smaller
    if (piece_index == manifest.pieces_count - 1) {
        bytes_to_read = manifest.file_size - offset;
    }

    std::vector<uint8_t> piece_data(bytes_to_read);
    file.read(reinterpret_cast<char*>(piece_data.data()), bytes_to_read);

    if (static_cast<uint64_t>(file.gcount()) != bytes_to_read) {
        throw std::runtime_error("Failed to read the full piece from file.");
    }

    return piece_data;
}
