#include "cli/cli.hpp"
#include "files/chunker.hpp"
#include "crypto/signature.hpp"
#include "crypto/hasher.hpp" // Added
#include <iostream>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

CLI::CLI(StorageManager& sm, Server& server)
    : storage_manager_(sm), server_(server), running_(false) {
    load_or_generate_identity();
}

CLI::~CLI() {}

void CLI::load_or_generate_identity() {
    if (fs::exists("identity.pem") && fs::exists("identity.pub")) {
        std::ifstream priv_file("identity.pem");
        std::stringstream buffer;
        buffer << priv_file.rdbuf();
        private_key_pem_ = buffer.str();
        
        std::ifstream pub_file("identity.pub", std::ios::binary);
        public_key_der_ = std::vector<uint8_t>((std::istreambuf_iterator<char>(pub_file)), std::istreambuf_iterator<char>());
        std::cout << "Loaded identity." << std::endl;
    } else {
        std::cout << "Generating new identity (Keypair)..." << std::endl;
        auto keypair = Signature::generate_keypair();
        if (!keypair.first.empty()) {
            private_key_pem_ = keypair.first;
            public_key_der_ = keypair.second;
            
            std::ofstream priv_file("identity.pem");
            priv_file << private_key_pem_;
            
            std::ofstream pub_file("identity.pub", std::ios::binary);
            pub_file.write(reinterpret_cast<const char*>(public_key_der_.data()), public_key_der_.size());
            
            std::cout << "Identity generated and saved." << std::endl;
        } else {
            std::cerr << "Failed to generate identity!" << std::endl;
        }
    }
}

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
              << "  limit <up|down> <rate>  - Set global limit (e.g., 100KB, 5MB)\n"
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
    else if (cmd == "limit") cmd_limit(args);
    else if (cmd == "help") print_help();
    else if (cmd == "quit" || cmd == "exit") running_ = false;
    else std::cout << "Unknown command: " << cmd << std::endl;
}

// Helper for parsing size strings
size_t parse_size(std::string s) {
    size_t multiplier = 1;
    if (s.size() > 2) {
        std::string suffix = s.substr(s.size() - 2);
        std::transform(suffix.begin(), suffix.end(), suffix.begin(), ::toupper);
        
        if (suffix == "KB") {
            multiplier = 1024;
            s = s.substr(0, s.size() - 2);
        } else if (suffix == "MB") {
            multiplier = 1024 * 1024;
            s = s.substr(0, s.size() - 2);
        }
    }
    else if (s.size() > 1) {
        char suffix = toupper(s.back());
         if (suffix == 'K') {
            multiplier = 1024;
            s.pop_back();
        } else if (suffix == 'M') {
            multiplier = 1024 * 1024;
            s.pop_back();
        }
    }
    
    return std::stoull(s) * multiplier;
}

void CLI::cmd_limit(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << "Usage: limit <up|down> <rate> (e.g., 500KB)" << std::endl;
        return;
    }
    std::string type = args[0];
    std::string rate_str = args[1];
    
    try {
        size_t rate = parse_size(rate_str);
        if (type == "up") {
            server_.set_global_upload_limit(rate);
            std::cout << "Global upload limit set to " << rate << " bytes/sec." << std::endl;
        } else if (type == "down") {
            server_.set_global_download_limit(rate);
             std::cout << "Global download limit set to " << rate << " bytes/sec." << std::endl;
        } else {
            std::cout << "Invalid type. Use 'up' or 'down'." << std::endl;
        }
    } catch (...) {
        std::cout << "Invalid rate format." << std::endl;
    }
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
        
        // Sign the manifest
        if (!private_key_pem_.empty()) {
            std::vector<uint8_t> data_to_sign(m.root_hash.begin(), m.root_hash.end());
            m.signature = Signature::sign(data_to_sign, private_key_pem_);
            m.signer_pubkey = public_key_der_;
            std::cout << "Manifest signed." << std::endl;
        }
        
        storage_manager_.save_manifest(m);
        FileSharer::instance().add_share(m, path);
        
        std::cout << "File shared successfully!\n"
                  << "Root Hash (ID): " << Hasher::hash_to_hex(m.root_hash) << "\n"
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
        hash_t root_hash = Hasher::hex_to_hash(hex);
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
        std::cout << " - " << m.file_name << " (" << Hasher::hash_to_hex(m.root_hash) << ")" << std::endl;
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
        std::cout << " - ID: " << Hasher::hash_to_hex(p.id) << " Endpoint: " << p.endpoint << std::endl;
    }
}

void CLI::cmd_dht_put(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::cout << "Usage: dht_put <key_hex> <value>" << std::endl;
        return;
    }
    dht::NodeID key = Hasher::hex_to_hash(args[0]);
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
    dht::NodeID key = Hasher::hex_to_hash(args[0]);
    server_.get_dht_node().start_find_value_lookup(key, [](const std::optional<std::vector<uint8_t>>& val, const std::vector<dht::NodeInfo>& nodes) {
        if (val) {
            std::string s(val->begin(), val->end());
            std::cout << "DHT GET Result: FOUND: " << s << std::endl;
        } else {
            std::cout << "DHT GET Result: NOT FOUND. Closest nodes: " << nodes.size() << std::endl;
        }
    });
}