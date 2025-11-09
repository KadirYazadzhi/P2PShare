#ifndef P2P_MANIFEST_HPP
#define P2P_MANIFEST_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <array>
#include <iostream>
#include <iomanip>

// Use a fixed-size array for hashes for simplicity and performance.
// SHA-256 produces a 32-byte hash.
constexpr size_t HASH_SIZE = 32;
using hash_t = std::array<uint8_t, HASH_SIZE>;

struct Manifest {
    std::string file_name;
    uint64_t file_size;
    uint32_t piece_size;
    uint32_t pieces_count;
    std::vector<hash_t> piece_hashes;
    hash_t root_hash; // Merkle root or hash of concatenated piece hashes

    // Helper function to print the manifest details
    void print() const {
        auto print_hash = [](const hash_t& h) {
            std::ios_base::fmtflags f(std::cout.flags());
            for (const auto& byte : h) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
            }
            std::cout.flags(f);
        };

        std::cout << "--- Manifest ---\\n"
                  << "File Name:    " << file_name << "\\n"
                  << "File Size:    " << file_size << " bytes\\n"
                  << "Piece Size:   " << piece_size << " bytes\\n"
                  << "Piece Count:  " << pieces_count << "\\n"
                  << "Root Hash:    ";
        print_hash(root_hash);
        std::cout << "\\n"
                  << "Piece Hashes: (" << piece_hashes.size() << ")\\n";
        for (size_t i = 0; i < piece_hashes.size(); ++i) {
            std::cout << "  [" << std::setw(4) << std::setfill(' ') << i << "]: ";
            print_hash(piece_hashes[i]);
            std::cout << "\\n";
        }
        std::cout << "----------------\\n";
    }
};

#endif //P2P_MANIFEST_HPP
