#ifndef P2P_CHUNKER_HPP
#define P2P_CHUNKER_HPP

#include "manifest.hpp"
#include <string>
#include <filesystem>

namespace fs = std::filesystem;

class Chunker {
public:
    // Default piece size to 256 KiB as suggested
    static constexpr uint32_t DEFAULT_PIECE_SIZE = 256 * 1024;

    /**
     * @brief Creates a manifest for a given file.
     *
     * Reads the file, splits it into pieces, calculates the hash for each piece,
     * and computes the root hash.
     *
     * @param file_path The path to the file to share.
     * @param piece_size The size of each piece in bytes.
     * @return A Manifest object for the file.
     * @throws std::runtime_error if the file cannot be opened or read.
     */
    static Manifest create_manifest_from_file(const fs::path& file_path, uint32_t piece_size = DEFAULT_PIECE_SIZE);
};

#endif //P2P_CHUNKER_HPP
