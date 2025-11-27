#ifndef P2P_STORAGE_MANAGER_HPP
#define P2P_STORAGE_MANAGER_HPP

#include <string>
#include <vector>
#include <memory>
#include <sqlite3.h>

#include "../crypto/hasher.hpp" // For hash_t
#include "../dht/kademlia.hpp"   // For dht::NodeID, dht::NodeInfo
#include "../files/manifest.hpp" // For Manifest
#include <optional>

// Forward declarations for SQLite types
struct sqlite3;
struct sqlite3_stmt;

class StorageManager {
public:
    StorageManager(const std::string& db_path);
    ~StorageManager();

    bool open();
    void close();
    bool create_tables();

    // Peer operations
    bool save_peer(const dht::NodeInfo& peer);
    std::vector<dht::NodeInfo> get_peers();
    bool delete_peer(const dht::NodeID& peer_id);

    // Manifest operations
    bool save_manifest(const Manifest& manifest);
    std::optional<Manifest> get_manifest(const hash_t& root_hash);
    std::vector<Manifest> get_all_manifests();
    bool delete_manifest(const hash_t& root_hash);

    // Download operations (simplified for now)
    // More complex download state will be added later
    bool save_download_state(const hash_t& root_hash, const std::string& file_path, uint32_t progress);
    std::tuple<std::string, uint32_t> get_download_state(const hash_t& root_hash); // file_path, progress
    std::vector<std::pair<hash_t, std::string>> get_all_downloads();
    bool delete_download_state(const hash_t& root_hash);

private:
    std::string db_path_;
    sqlite3* db_;

    // Helper for executing SQL statements
    bool execute_sql(const std::string& sql);
};

#endif // P2P_STORAGE_MANAGER_HPP
