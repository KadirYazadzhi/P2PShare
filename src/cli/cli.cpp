#include "cli/cli.hpp"
#include "files/chunker.hpp"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <filesystem>

namespace fs = std::filesystem;

// Helper: Hex string to hash_t
hash_t hex_to_hash_cli(const std::string& hex) {
    hash_t h;
    for (size_t i = 0; i < HASH_SIZE; ++i) {
        h[i] = static_cast<uint8_t>(std::stoul(hex.substr(i * 2, 2), nullptr, 16));
    }
    return h;
}

// Helper: hash_t to Hex string
std::string hash_to_hex_cli(const hash_t& h) {
    std::stringstream ss;
    for (uint8_t b : h) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return ss.str();
}

CLI::CLI(StorageManager& sm, Server& server)
    : storage_manager_(sm), server_(server), running_(false) {}

CLI::~CLI() {}

void CLI::run() {
    running_ = true;
    print_help();

    std::string line;
    while (running_ && std::getline(std::cin, line)) {
        if (line.empty()) continue;
        handle_command(line);
    }
}

void CLI::print_help() {
    std::cout << "Available commands:\n"
              << "  share <file_path>       - Share a file\n"
              << "  download <file_id>      - Download a file by ID\n"
              << "  connect <host> <port>   - Connect to a peer (TCP)\n"
              << "  peers                   - List connected peers\n"
              << "  status                  - Show active downloads/shares\n"
              << "  dht_bootstrap <ip> <port> - Bootstrap DHT node\n"
              << "  dht_peers             - List known DHT peers (from storage)\n"
              << "  dht_put <key> <val>   - Store value in DHT\n"
              << "  dht_get <key>         - Find value in DHT\n"
              << "  help                    - Show this help\n"
              << "  quit / exit             - Exit\n"
              << std::endl;
}

void CLI::handle_command(const std::string& line) {
    std::istringstream iss(line);
    std::string cmd;
    iss >> cmd;
    
    std::vector<std::string> args;
    std::string arg;
    while (iss >> arg) args.push_back(arg);

    if (cmd == "share") cmd_share(args);
    else if (cmd == "download") cmd_download(args);
    else if (cmd == "connect") cmd_connect(args);
    else if (cmd == "peers") cmd_peers(args);
    else if (cmd == "status") cmd_status(args);
    else if (cmd == "dht_bootstrap") cmd_dht_bootstrap(args);
    else if (cmd == "dht_peers") cmd_dht_peers(args);
    else if (cmd == "dht_put") cmd_dht_put(args);
    else if (cmd == "dht_get") cmd_dht_get(args);
    else if (cmd == "help") print_help();
    else if (cmd == "quit" || cmd == "exit") running_ = false;
    else std::cout << "Unknown command: " << cmd << std::endl;
}

void CLI::cmd_share(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cout << "Usage: share <file_path>" << std::endl;
        return;
    }
    std::string path = args[0];
    if (!fs::exists(path)) {
        std::cout << "File not found: " << path << std::endl;
        return;
    }
    
    try {
        // Default piece size 256KB
        Manifest m = Chunker::create_manifest_from_file(path, 256 * 1024); 
        storage_manager_.save_manifest(m);
        FileSharer::instance().add_share(m, path);
        
        std::cout << "File shared successfully!\n"
                  << "Root Hash (ID): " << hash_to_hex_cli(m.root_hash) << "\n"
                  << "Size: " << m.file_size << " bytes\n"
                  << "Pieces: " << m.pieces_count << std::endl;

        // Announce to DHT
        std::string ip = server_.get_dht_node().get_external_ip();
        if(ip.empty()) ip = "127.0.0.1"; // Fallback
        
        uint16_t port = server_.get_dht_node().get_external_port(); 
        if(port == 0) port = 8080; // Fallback

        std::stringstream ss;
        ss << ip << ":" << port; 
        std::string contact_info = ss.str();
        std::vector<uint8_t> val(contact_info.begin(), contact_info.end());

        std::cout << "Announcing to DHT as: " << contact_info << "..." << std::endl;
        server_.get_dht_node().start_find_node_lookup(m.root_hash, [this, m, val](const std::vector<dht::NodeInfo>& closest) {
             for(const auto& node : closest) {
                 server_.get_dht_node().send_store(node.endpoint, m.root_hash, val);
             }
             std::cout << "DHT Announce complete." << std::endl;
        });

    } catch (const std::exception& e) {
        std::cerr << "Error sharing file: " << e.what() << std::endl;
    }
}

void CLI::cmd_download(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cout << "Usage: download <file_id_hex>" << std::endl;
        return;
    }
    std::string hex = args[0];
    if (hex.length() != HASH_SIZE * 2) {
        std::cout << "Invalid hash length." << std::endl;
        return;
    }
    
    try {
        hash_t root_hash = hex_to_hash_cli(hex);
        server_.start_download(root_hash);
        std::cout << "Download started for " << hex << std::endl;
        
        // Query DHT for peers
        std::cout << "Querying DHT for peers..." << std::endl;
        server_.get_dht_node().start_find_value_lookup(root_hash, [this](const std::optional<std::vector<uint8_t>>& val, const std::vector<dht::NodeInfo>&) {
            if (val) {
                std::string s(val->begin(), val->end());
                std::cout << "DHT Found Peer: " << s << std::endl;
                auto pos = s.find(':');
                if (pos != std::string::npos) {
                    std::string ip = s.substr(0, pos);
                    uint16_t port = static_cast<uint16_t>(std::stoi(s.substr(pos + 1)));
                    server_.connect(ip, port);
                }
            } else {
                std::cout << "DHT: No peers found immediately. (Wait for propagation or manual connect)" << std::endl;
            }
        });

    } catch (const std::exception& e) {
        std::cerr << "Error starting download: " << e.what() << std::endl;
    }
}

void CLI::cmd_connect(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << "Usage: connect <host> <port>" << std::endl;
        return;
    }
    std::string host = args[0];
    uint16_t port = 0;
    try {
        port = static_cast<uint16_t>(std::stoi(args[1]));
        server_.connect(host, port);
        std::cout << "Initiating connection to " << host << ":" << port << "..." << std::endl;
    } catch (const std::exception& e) {
        std::cout << "Invalid port or error: " << e.what() << std::endl;
    }
}

void CLI::cmd_peers(const std::vector<std::string>& args) {
    std::cout << "Peer listing not fully implemented yet." << std::endl;
}

void CLI::cmd_status(const std::vector<std::string>& args) {
    auto downloads = server_.get_active_downloads();
    std::cout << "Active Downloads: " << downloads.size() << std::endl;
    for (auto& dm : downloads) {
        std::cout << " - Download active." << std::endl;
    }
    
    auto manifests = storage_manager_.get_all_manifests();
    std::cout << "Shared Files: " << manifests.size() << std::endl;
    for (auto& m : manifests) {
        std::cout << " - " << m.file_name << " (" << hash_to_hex_cli(m.root_hash) << ")" << std::endl;
    }
}

void CLI::cmd_dht_bootstrap(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << "Usage: dht_bootstrap <ip> <port>" << std::endl;
        return;
    }
    try {
        asio::ip::udp::endpoint ep(asio::ip::make_address(args[0]), std::stoi(args[1]));
        server_.get_dht_node().bootstrap(ep);
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
    }
}

void CLI::cmd_dht_peers(const std::vector<std::string>& args) {
    auto peers = storage_manager_.get_peers();
    std::cout << "Known DHT Peers: " << peers.size() << std::endl;
    for (const auto& p : peers) {
        std::cout << " - ID: " << hash_to_hex_cli(p.id) << " Endpoint: " << p.endpoint << std::endl;
    }
}

void CLI::cmd_dht_put(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << "Usage: dht_put <key_hex> <value>" << std::endl;
        return;
    }
    dht::NodeID key = hex_to_hash_cli(args[0]);
    std::string val = args[1];
    std::vector<uint8_t> val_bytes(val.begin(), val.end());
    
    std::cout << "Starting PUT (lookup then store)..." << std::endl;
    server_.get_dht_node().start_find_node_lookup(key, [this, key, val_bytes](const std::vector<dht::NodeInfo>& closest) {
        std::cout << "Found " << closest.size() << " closest nodes. Storing..." << std::endl;
        for(const auto& node : closest) {
            server_.get_dht_node().send_store(node.endpoint, key, val_bytes);
        }
    });
}

void CLI::cmd_dht_get(const std::vector<std::string>& args) {
    if (args.empty()) {
         std::cout << "Usage: dht_get <key_hex>" << std::endl;
         return;
    }
    dht::NodeID key = hex_to_hash_cli(args[0]);
    server_.get_dht_node().start_find_value_lookup(key, [](const std::optional<std::vector<uint8_t>>& val, const std::vector<dht::NodeInfo>& nodes) {
        if (val) {
            std::string s(val->begin(), val->end());
            std::cout << "DHT GET Result: FOUND: " << s << std::endl;
        } else {
            std::cout << "DHT GET Result: NOT FOUND. Closest nodes: " << nodes.size() << std::endl;
        }
    });
}