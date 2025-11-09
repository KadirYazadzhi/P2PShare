#ifndef P2P_BITFIELD_HPP
#define P2P_BITFIELD_HPP

#include <vector>
#include <cstdint>
#include <cmath>

class Bitfield {
public:
    // Default constructor
    Bitfield() = default;

    // Constructor to initialize with a certain number of bits
    Bitfield(size_t num_bits) {
        resize(num_bits);
    }

    // Initialize from a raw byte vector
    Bitfield(size_t num_bits, const std::vector<uint8_t>& bytes) 
        : num_bits_(num_bits), bytes_(bytes) {}

    void resize(size_t num_bits) {
        num_bits_ = num_bits;
        size_t num_bytes = static_cast<size_t>(std::ceil(static_cast<double>(num_bits) / 8.0));
        bytes_.assign(num_bytes, 0);
    }

    void set_piece(size_t piece_index) {
        if (piece_index >= num_bits_) return;
        size_t byte_index = piece_index / 8;
        uint8_t bit_index = piece_index % 8;
        bytes_[byte_index] |= (1 << (7 - bit_index));
    }

    void clear_piece(size_t piece_index) {
        if (piece_index >= num_bits_) return;
        size_t byte_index = piece_index / 8;
        uint8_t bit_index = piece_index % 8;
        bytes_[byte_index] &= ~(1 << (7 - bit_index));
    }

    bool has_piece(size_t piece_index) const {
        if (piece_index >= num_bits_) return false;
        size_t byte_index = piece_index / 8;
        uint8_t bit_index = piece_index % 8;
        return (bytes_[byte_index] & (1 << (7 - bit_index))) != 0;
    }

    const std::vector<uint8_t>& get_bytes() const {
        return bytes_;
    }
    
    size_t get_num_bits() const {
        return num_bits_;
    }

    // Set all bits to 1
    void set_all() {
        for(size_t i = 0; i < num_bits_; ++i) {
            set_piece(i);
        }
    }

private:
    size_t num_bits_ = 0;
    std::vector<uint8_t> bytes_;
};

#endif //P2P_BITFIELD_HPP
