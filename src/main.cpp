#include <iostream>
#include <string>
#include <asio.hpp>
#include <filesystem>
#include <map>
#include <vector>
#include <regex>

#include "network/protocol.hpp"
#include "network/server.hpp"
#include "network/client.hpp"
#include "files/chunker.hpp"
#include "files/manifest.hpp"
#include "files/file_sharer.hpp"
#include "storage/share_state.hpp"
#include "files/download_manager.hpp"

// A global map to hold active download managers for the client
std::map<hash_t, std::shared_ptr<DownloadManager>> g_download_managers;

void print_usage() {
    std::cout << "Usage: p2p_app <mode> [options]\n"
              << "Modes:\n"
              << "  server <port>                      - Run as a server, loading shared files.\n"
              << "  share <file_path>                  - Add a file to the list of shares.\n"
              << "  download <hash> <host1:port1> [<host2:port2>...] - Download a file from one or more peers.\n";
}

// Helper to convert hex string to hash_t
hash_t hex_to_hash(const std::string& hex) {
    if (hex.length() != HASH_SIZE * 2) {
        throw std::runtime_error("Invalid hash string length.");
    }
    hash_t hash;
    for (size_t i = 0; i < HASH_SIZE; ++i) {
        hash[i] = std::stoi(hex.substr(i * 2, 2), nullptr, 16);
    }
    return hash;
}

void share_file(const std::string& file_path_str) {
    try {
        std::filesystem::path file_path(file_path_str);
        if (!std::filesystem::exists(file_path)) {
            throw std::runtime_error("File does not exist: " + file_path_str);
        }
        std::filesystem::path absolute_path = std::filesystem::absolute(file_path);

        std::cout << "Generating manifest for: " << absolute_path << std::endl;
        Manifest manifest = Chunker::create_manifest_from_file(absolute_path);
        
        ShareState state_manager;
        state_manager.add_share(manifest, absolute_path);

        std::cout << "File added to shares. Root hash:\n";
        for(uint8_t byte : manifest.root_hash) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
        }
        std::cout << std::dec << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error sharing file: " << e.what() << std::endl;
    }
}

// Generic message handler for the client
void client_message_handler(const Message& msg, std::shared_ptr<Connection> conn) {
    hash_t msg_hash;

    if (msg.type == MessageType::SEARCH_RESPONSE) {
        for(auto const& [hash, dm] : g_download_managers) {
            dm->handle_message(msg, conn);
        }
        return;
    } 
    else if (msg.type == MessageType::PIECE || msg.type == MessageType::BITFIELD) {
        if (msg.payload.size() < HASH_SIZE) {
            return;
        }
        std::memcpy(msg_hash.data(), msg.payload.data(), HASH_SIZE);
        if (g_download_managers.count(msg_hash)) {
            g_download_managers[msg_hash]->handle_message(msg, conn);
        } else {
            std::cerr << "Received message for unknown download: " << static_cast<int>(msg.type) << std::endl;
        }
        return;
    }
}


int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    std::string mode = argv[1];

    if (mode == "share" && argc == 3) {
        share_file(argv[2]);
        return 0;
    }

    asio::io_context io_context;

    if (mode == "server" && argc == 3) {
        ShareState state_manager;
        state_manager.load_shares_into(FileSharer::instance());

        uint16_t port = std::stoi(argv[2]);
        Server s(io_context, port);
        io_context.run();
    } else if (mode == "download" && argc >= 4) {
        hash_t root_hash = hex_to_hash(argv[2]);
        
        if (g_download_managers.find(root_hash) == g_download_managers.end()) {
            g_download_managers[root_hash] = std::make_shared<DownloadManager>(root_hash);
        }
        auto dm = g_download_managers[root_hash];

        int valid_peers_found = 0; // <-- FIX: Counter for valid peer arguments
        std::regex peer_regex(R"(([^:]+):(\d+))");
        for (int i = 3; i < argc; ++i) {
            std::string peer_str = argv[i];
            std::smatch matches;
            if (std::regex_match(peer_str, matches, peer_regex) && matches.size() == 3) {
                valid_peers_found++; // <-- FIX: Increment counter
                std::string host = matches[1].str();
                uint16_t port = std::stoi(matches[2].str());

                // Client must be heap-allocated to exist for the duration of the async operation
                auto c = std::make_shared<Client>(io_context, &client_message_handler);
                c->connect(host, port, [dm](std::shared_ptr<Connection> conn){
                    dm->add_peer(conn);
                    dm->start(); 
                });
            } else {
                std::cerr << "Invalid peer address format: " << peer_str << ". Expected host:port." << std::endl;
            }
        }

        if (valid_peers_found == 0) { // <-- FIX: Check the counter
            std::cerr << "No valid peers provided for download." << std::endl;
            return 1;
        }

        io_context.run();
    }
    else {
        print_usage();
        return 1;
    }

    return 0;
}
