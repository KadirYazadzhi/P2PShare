#ifndef P2P_FILE_SHARER_HPP
#define P2P_FILE_SHARER_HPP

#include "manifest.hpp"
#include <unordered_map>
#include <string>
#include <vector>
#include <mutex>
#include <optional>
#include <filesystem>

#include "../storage/storage_manager.hpp" // Added for StorageManager

// A custom hash function for std::array
namespace std {
    template<size_t N>
    struct hash<array<uint8_t, N>> {
        size_t operator()(const array<uint8_t, N>& a) const {
            size_t h = 0;
            for (size_t i = 0; i < N; ++i) {
                h = (h << 1) ^ a[i];
            }
            return h;
        }
    };
}

class FileSharer {
public:
    static FileSharer& instance() {
        static FileSharer inst;
        return inst;
    }

    void set_storage_manager(StorageManager* sm) {
        storage_manager_ = sm;
    }

    // Add a file to be shared. This method now takes the manifest directly.
    void add_share(const Manifest& manifest, const std::filesystem::path& file_path);

    // Get the manifest for a shared file.
    std::optional<Manifest> get_manifest(const hash_t& root_hash) const;

    // Read a piece from a shared file.
    std::vector<uint8_t> get_piece(const hash_t& root_hash, uint32_t piece_index);

private:
    FileSharer() = default;
    ~FileSharer() = default;
    FileSharer(const FileSharer&) = delete;
    FileSharer& operator=(const FileSharer&) = delete;

    mutable std::mutex mutex_;
    std::unordered_map<hash_t, Manifest> shared_manifests_;
    std::unordered_map<hash_t, std::filesystem::path> file_paths_;
    StorageManager* storage_manager_ = nullptr; // Added StorageManager member
};

#endif //P2P_FILE_SHARER_HPP
