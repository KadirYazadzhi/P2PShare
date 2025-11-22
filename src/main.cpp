#include <iostream>
#include <string>
#include <asio.hpp>
#include <asio/ip/address.hpp>
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
// #include "storage/share_state.hpp" // Removed, replaced by StorageManager
#include "files/download_manager.hpp"
#include "dht/dht_node.hpp"
#include "storage/storage_manager.hpp" // Added for persistence

// A global map to hold active download managers for the client
std::map<hash_t, std::shared_ptr<DownloadManager>> g_download_managers;

void print_usage() {
    std::cout << "Usage: p2p_app <mode> [options]\n"
              << "Modes:\n"
              << "  server <port>                      - Run as a server, loading shared files.\n"
              << "  share <file_path>                  - Add a file to the list of shares.\n"
              << "  download <hash> <host1:port1> [<host2:port2>...] - Download a file from one or more peers.\n"
              << "  dht_node <port> [--bootstrap <host>:<port>]    - Run a standalone DHT node.\n";
}



void share_file(const std::string& file_path_str, StorageManager& storage_manager) {
    try {
        std::filesystem::path file_path(file_path_str);
        if (!std::filesystem::exists(file_path)) {
            throw std::runtime_error("File does not exist: " + file_path_str);
        }
        std::filesystem::path absolute_path = std::filesystem::absolute(file_path);

        std::cout << "Generating manifest for: " << absolute_path << std::endl;
        Manifest manifest = Chunker::create_manifest_from_file(absolute_path);
        
        // Save manifest to storage
        if (storage_manager.save_manifest(manifest)) {
            std::cout << "Manifest saved to database. Root hash:\n";
            for(uint8_t byte : manifest.root_hash) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
            }
            std::cout << std::dec << std::endl;
        } else {
            std::cerr << "Failed to save manifest to database." << std::endl;
        }

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
    else if (msg.type == MessageType::PIECE || msg.type == MessageType::BITFIELD || msg.type == MessageType::HAVE) {
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

    asio::io_context io_context;
    asio::ssl::context ssl_context(asio::ssl::context::tlsv12); // Global SSL context (client side)

    // Server-side SSL context setup needs to happen in Server constructor
    // Client-side can load trusted certs if needed

    StorageManager storage_manager("p2pshare.db"); // Initialize StorageManager

    if (mode == "share" && argc == 3) {
        share_file(argv[2], storage_manager); // Pass storage_manager
        return 0;
    }

    if (mode == "server" && argc == 3) {
        // Load shares from StorageManager
        for (const auto& manifest : storage_manager.get_all_manifests()) {
            // This assumes manifest.file_name is the actual path to the file.
            // In a real application, you might store absolute_path in DB.
            FileSharer::instance().add_share(manifest, std::filesystem::path(manifest.file_name)); 
        }

        uint16_t port = std::stoi(argv[2]);
        Server s(io_context, port); // Pass ssl_context to Server
        io_context.run();
    } else if (mode == "download" && argc >= 4) {
        hash_t root_hash = hex_to_hash(argv[2]);
        
        if (g_download_managers.find(root_hash) == g_download_managers.end()) {
            g_download_managers[root_hash] = std::make_shared<DownloadManager>(root_hash, storage_manager); // Pass storage_manager
        }
        auto dm = g_download_managers[root_hash];

        std::vector<std::shared_ptr<Client>> clients; // <-- Keep client objects alive
        int valid_peers_found = 0;
        std::regex peer_regex(R"(([^:]+):(\d+))");
        for (int i = 3; i < argc; ++i) {
            std::string peer_str = argv[i];
            std::smatch matches;
            if (std::regex_match(peer_str, matches, peer_regex) && matches.size() == 3) {
                valid_peers_found++;
                std::string host = matches[1].str();
                uint16_t port = std::stoi(matches[2].str());

                auto c = std::make_shared<Client>(io_context, client_message_handler, ssl_context); // Pass ssl_context
                clients.push_back(c); // <-- Store the shared_ptr

                c->connect(host, port, [dm](std::shared_ptr<Connection> conn){
                    dm->add_peer(conn);
                    dm->start(); 
                });
            } else {
                std::cerr << "Invalid peer address format: " << peer_str << ". Expected host:port." << std::endl;
            }
        }

        if (valid_peers_found == 0) {
            std::cerr << "No valid peers provided for download." << std::endl;
            return 1;
        }

        io_context.run();
    }
    else if (mode == "dht_node" && argc >= 3) {
        uint16_t port = std::stoi(argv[2]);
        dht::DhtNode node(io_context, port, storage_manager); // Pass storage_manager

        if (argc >= 5 && std::string(argv[3]) == "--bootstrap") {
            std::string bootstrap_peer_str = argv[4];
            std::smatch matches;
            std::regex peer_regex(R"(([^:]+):(\d+))");
            if (std::regex_match(bootstrap_peer_str, matches, peer_regex) && matches.size() == 3) {
                std::string host = matches[1].str();
                uint16_t bootstrap_port = std::stoi(matches[2].str());
                asio::ip::udp::endpoint bootstrap_endpoint(asio::ip::make_address(host), bootstrap_port);
                node.bootstrap(bootstrap_endpoint);
            } else {
                std::cerr << "Invalid bootstrap peer address format: " << bootstrap_peer_str << ". Expected host:port." << std::endl;
                return 1;
            }
        }
        node.start();
        io_context.run();
    }
    else {
        print_usage();
        return 1;
    }

    return 0;
}