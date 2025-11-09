#include "storage/share_state.hpp"
#include "nlohmann/json.hpp"
#include <fstream>
#include <iostream>
#include <filesystem> // <--- Added this include

namespace fs = std::filesystem; // <--- Added this using directive
using json = nlohmann::json;

// Helper to convert binary hash to hex string and back
namespace {
    std::string hash_to_hex(const hash_t& hash) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (const auto& byte : hash) {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        return ss.str();
    }

    hash_t hex_to_hash(const std::string& hex) {
        hash_t hash;
        for (size_t i = 0; i < HASH_SIZE; ++i) {
            hash[i] = std::stoi(hex.substr(i * 2, 2), nullptr, 16);
        }
        return hash;
    }
}

// JSON serialization for Manifest
void to_json(json& j, const Manifest& m) {
    j = json{
        {"file_name", m.file_name},
        {"file_size", m.file_size},
        {"piece_size", m.piece_size},
        {"root_hash", hash_to_hex(m.root_hash)}
    };
    for(const auto& piece_hash : m.piece_hashes) {
        j["piece_hashes"].push_back(hash_to_hex(piece_hash));
    }
}

void from_json(const json& j, Manifest& m) {
    j.at("file_name").get_to(m.file_name);
    j.at("file_size").get_to(m.file_size);
    j.at("piece_size").get_to(m.piece_size);
    m.root_hash = hex_to_hash(j.at("root_hash").get<std::string>());
    for(const auto& hex_hash : j.at("piece_hashes")) {
        m.piece_hashes.push_back(hex_to_hash(hex_hash.get<std::string>()));
    }
    m.pieces_count = m.piece_hashes.size();
}


ShareState::ShareState(std::string state_file_path) : state_file_path_(std::move(state_file_path)) {}

void ShareState::add_share(const Manifest& manifest, const std::filesystem::path& absolute_file_path) {
    json state_json;
    // Read existing state if file exists
    std::ifstream read_file(state_file_path_);
    if (read_file.is_open() && read_file.peek() != std::ifstream::traits_type::eof()) {
        try {
            state_json = json::parse(read_file);
        } catch (json::parse_error& e) {
            std::cerr << "Warning: Could not parse state file. Starting fresh. Error: " << e.what() << std::endl;
            state_json = json::object();
        }
    }
    read_file.close();

    if (!state_json.is_object()) {
        state_json = json::object();
    }

    // Add new share
    std::string root_hash_hex = hash_to_hex(manifest.root_hash);
    state_json[root_hash_hex]["manifest"] = manifest;
    state_json[root_hash_hex]["path"] = absolute_file_path.string();

    // Write back to file
    std::ofstream write_file(state_file_path_);
    write_file << state_json.dump(4); // pretty print with 4 spaces
}

void ShareState::load_shares_into(FileSharer& sharer) {
    std::ifstream read_file(state_file_path_);
    if (!read_file.is_open()) {
        std::cout << "No state file found. Starting with no shared files." << std::endl;
        return;
    }

    json state_json;
    try {
        state_json = json::parse(read_file);
    } catch (json::parse_error& e) {
        std::cerr << "Error parsing state file: " << e.what() << std::endl;
        return;
    }

    if (!state_json.is_object()) return;

    for (auto& [hash_str, share_info] : state_json.items()) {
        try {
            // Manifest m = share_info.at("manifest").get<Manifest>(); // Not needed for now
            std::filesystem::path p = share_info.at("path").get<std::string>();
            
            if (fs::exists(p)) {
                sharer.share_file(p);
                std::cout << "Loaded shared file: " << p.filename() << std::endl;
            } else {
                std::cerr << "Warning: Path for shared file not found, skipping: " << p << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "Error loading share for hash " << hash_str << ": " << e.what() << std::endl;
        }
    }
}