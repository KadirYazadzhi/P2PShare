#ifndef P2P_CLI_HPP
#define P2P_CLI_HPP

#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <iostream>

#include "../storage/storage_manager.hpp"
#include "../files/file_sharer.hpp"
#include "../files/download_manager.hpp"
#include "../network/server.hpp"

class CLI {
public:
    CLI(StorageManager& storage_manager, Server& server);
    ~CLI();

    void run();

private:
    void print_help();
    void handle_command(const std::string& line);
    
    void cmd_share(const std::vector<std::string>& args);
    void cmd_download(const std::vector<std::string>& args);
    void cmd_connect(const std::vector<std::string>& args);
    void cmd_peers(const std::vector<std::string>& args);
    void cmd_status(const std::vector<std::string>& args);
    
    // DHT Commands
    void cmd_dht_bootstrap(const std::vector<std::string>& args);
    void cmd_dht_peers(const std::vector<std::string>& args);
    void cmd_dht_put(const std::vector<std::string>& args);
    void cmd_dht_get(const std::vector<std::string>& args);

    // Bandwidth
    void cmd_limit(const std::vector<std::string>& args);

    void load_or_generate_identity();

    StorageManager& storage_manager_;
    Server& server_;
    bool running_;
    
    std::string private_key_pem_;
    std::vector<uint8_t> public_key_der_;
    
    // Keep track of active downloads
    // key: root_hash (as hex string for simplicity in map, or hash_t)
    std::map<std::string, std::shared_ptr<DownloadManager>> active_downloads_;
};

#endif // P2P_CLI_HPP
