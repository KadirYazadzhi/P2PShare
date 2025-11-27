#include "storage/storage_manager.hpp"
#include "crypto/hasher.hpp" // Added
#include <iostream>
#include <sstream>
#include <iomanip> // For std::hex, std::setw, std::setfill
#include <ctime>   // For std::time
#include <optional>

// Helper function to convert NodeID to hex string

std::string node_id_to_hex(const dht::NodeID& id) {

    std::stringstream ss;

    for (uint8_t byte : id) {

        ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;

    }

    return ss.str();

}



// Helper function to convert hex string to NodeID

dht::NodeID hex_to_node_id(const std::string& hex_str) {

    dht::NodeID id;

    for (size_t i = 0; i < dht::NODE_ID_SIZE; ++i) {

        id[i] = static_cast<uint8_t>(std::stoul(hex_str.substr(i * 2, 2), nullptr, 16));

    }

    return id;

}



StorageManager::StorageManager(const std::string& db_path)

    : db_path_(db_path), db_(nullptr) {
    // Open the database immediately
    if (!open()) {
        std::cerr << "Failed to open database: " << db_path << std::endl;
        // Handle error, perhaps throw an exception
    }
    if (!create_tables()) {
        std::cerr << "Failed to create tables in database: " << db_path << std::endl;
        // Handle error
    }
}

StorageManager::~StorageManager() {
    close();
}

bool StorageManager::open() {
    int rc = sqlite3_open(db_path_.c_str(), &db_);
    if (rc) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db_) << std::endl;
        return false;
    }
    std::cout << "Opened database successfully: " << db_path_ << std::endl;
    return true;
}

void StorageManager::close() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
        std::cout << "Closed database successfully." << std::endl;
    }
}

bool StorageManager::execute_sql(const std::string& sql) {
    char* err_msg = nullptr;
    int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << err_msg << std::endl;
        sqlite3_free(err_msg);
        return false;
    }
    return true;
}

bool StorageManager::create_tables() {
    std::string create_peers_sql = R"(
        CREATE TABLE IF NOT EXISTS peers (
            id TEXT PRIMARY KEY NOT NULL,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            last_seen INTEGER
        );
    )";

    std::string create_manifests_sql = R"(
        CREATE TABLE IF NOT EXISTS manifests (
            root_hash TEXT PRIMARY KEY NOT NULL,
            file_name TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            piece_size INTEGER NOT NULL,
            pieces_count INTEGER NOT NULL,
            piece_hashes BLOB NOT NULL
        );
    )";

    std::string create_downloads_sql = R"(
        CREATE TABLE IF NOT EXISTS downloads (
            root_hash TEXT PRIMARY KEY NOT NULL,
            file_path TEXT NOT NULL,
            progress INTEGER NOT NULL,
            status TEXT NOT NULL
        );
    )";

    bool success = execute_sql(create_peers_sql);
    success &= execute_sql(create_manifests_sql);
    success &= execute_sql(create_downloads_sql);
    return success;
}

// Peer operations
bool StorageManager::save_peer(const dht::NodeInfo& peer) {
    std::string sql = "INSERT OR REPLACE INTO peers (id, ip, port, last_seen) VALUES (?, ?, ?, ?);";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db_) << std::endl;
        return false;
    }

    std::string peer_id_hex = node_id_to_hex(peer.id);
    sqlite3_bind_text(stmt, 1, peer_id_hex.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, peer.endpoint.address().to_string().c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, peer.endpoint.port());
    sqlite3_bind_int64(stmt, 4, std::time(nullptr)); // Current timestamp

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "Failed to execute statement: " << sqlite3_errmsg(db_) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }
    sqlite3_finalize(stmt);
    return true;
}

std::vector<dht::NodeInfo> StorageManager::get_peers() {
    std::vector<dht::NodeInfo> peers;
    std::string sql = "SELECT id, ip, port FROM peers;";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db_) << std::endl;
        return peers;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        std::string id_hex = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        std::string ip_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        int port = sqlite3_column_int(stmt, 2);

        dht::NodeID id = hex_to_node_id(id_hex);
        asio::ip::udp::endpoint endpoint(asio::ip::make_address(ip_str), static_cast<uint16_t>(port));
        peers.push_back({id, endpoint});
    }

    if (rc != SQLITE_DONE) {
        std::cerr << "Failed to execute statement: " << sqlite3_errmsg(db_) << std::endl;
    }
    sqlite3_finalize(stmt);
    return peers;
}

bool StorageManager::delete_peer(const dht::NodeID& peer_id) {
    std::string sql = "DELETE FROM peers WHERE id = ?;";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db_) << std::endl;
        return false;
    }

    std::string peer_id_hex = node_id_to_hex(peer_id);
    sqlite3_bind_text(stmt, 1, peer_id_hex.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "Failed to execute statement: " << sqlite3_errmsg(db_) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }
    sqlite3_finalize(stmt);
    return true;
}

// Manifest operations
bool StorageManager::save_manifest(const Manifest& manifest) {
    std::string sql = "INSERT OR REPLACE INTO manifests (root_hash, file_name, file_size, piece_size, pieces_count, piece_hashes) VALUES (?, ?, ?, ?, ?, ?);";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db_) << std::endl;
        return false;
    }

    std::string root_hash_hex = Hasher::hash_to_hex(manifest.root_hash);
    sqlite3_bind_text(stmt, 1, root_hash_hex.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, manifest.file_name.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, manifest.file_size);
    sqlite3_bind_int(stmt, 4, manifest.piece_size);
    sqlite3_bind_int(stmt, 5, manifest.pieces_count);

    // Serialize piece_hashes into a blob
    std::vector<uint8_t> piece_hashes_blob;
    piece_hashes_blob.reserve(manifest.piece_hashes.size() * HASH_SIZE);
    for (const auto& hash : manifest.piece_hashes) {
        piece_hashes_blob.insert(piece_hashes_blob.end(), hash.begin(), hash.end());
    }
    sqlite3_bind_blob(stmt, 6, piece_hashes_blob.data(), piece_hashes_blob.size(), SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "Failed to execute statement: " << sqlite3_errmsg(db_) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }
    sqlite3_finalize(stmt);
    return true;
}

std::optional<Manifest> StorageManager::get_manifest(const hash_t& root_hash) {
    std::string sql = "SELECT root_hash, file_name, file_size, piece_size, pieces_count, piece_hashes FROM manifests WHERE root_hash = ?;";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db_) << std::endl;
        return std::nullopt;
    }

    std::string root_hash_hex = Hasher::hash_to_hex(root_hash);
    sqlite3_bind_text(stmt, 1, root_hash_hex.c_str(), -1, SQLITE_STATIC);

    if ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        Manifest manifest;
        manifest.root_hash = Hasher::hex_to_hash(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
        manifest.file_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        manifest.file_size = sqlite3_column_int64(stmt, 2);
        manifest.piece_size = sqlite3_column_int(stmt, 3);
        manifest.pieces_count = sqlite3_column_int(stmt, 4);

        // Deserialize piece_hashes from blob
        const void* blob_data = sqlite3_column_blob(stmt, 5);
        int blob_size = sqlite3_column_bytes(stmt, 5);
        
        manifest.piece_hashes.resize(manifest.pieces_count);
        for (uint32_t i = 0; i < manifest.pieces_count; ++i) {
            std::memcpy(manifest.piece_hashes[i].data(), static_cast<const uint8_t*>(blob_data) + (i * HASH_SIZE), HASH_SIZE);
        }
        sqlite3_finalize(stmt);
        return manifest;
    } else if (rc != SQLITE_DONE) {
        std::cerr << "Failed to execute statement: " << sqlite3_errmsg(db_) << std::endl;
    }
    sqlite3_finalize(stmt);
    return std::nullopt;
}

std::vector<Manifest> StorageManager::get_all_manifests() {
    std::vector<Manifest> manifests;
    std::string sql = "SELECT root_hash, file_name, file_size, piece_size, pieces_count, piece_hashes FROM manifests;";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db_) << std::endl;
        return manifests;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        Manifest manifest;
        manifest.root_hash = Hasher::hex_to_hash(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
        manifest.file_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        manifest.file_size = sqlite3_column_int64(stmt, 2);
        manifest.piece_size = sqlite3_column_int(stmt, 3);
        manifest.pieces_count = sqlite3_column_int(stmt, 4);

        const void* blob_data = sqlite3_column_blob(stmt, 5);
        int blob_size = sqlite3_column_bytes(stmt, 5);
        
        manifest.piece_hashes.resize(manifest.pieces_count);
        for (uint32_t i = 0; i < manifest.pieces_count; ++i) {
            std::memcpy(manifest.piece_hashes[i].data(), static_cast<const uint8_t*>(blob_data) + (i * HASH_SIZE), HASH_SIZE);
        }
        manifests.push_back(manifest);
    }

    if (rc != SQLITE_DONE) {
        std::cerr << "Failed to execute statement: " << sqlite3_errmsg(db_) << std::endl;
    }
    sqlite3_finalize(stmt);
    return manifests;
}

bool StorageManager::delete_manifest(const hash_t& root_hash) {
    std::string sql = "DELETE FROM manifests WHERE root_hash = ?;";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db_) << std::endl;
        return false;
    }

    std::string root_hash_hex = Hasher::hash_to_hex(root_hash);
    sqlite3_bind_text(stmt, 1, root_hash_hex.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "Failed to execute statement: " << sqlite3_errmsg(db_) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }
    sqlite3_finalize(stmt);
    return true;
}

// Download operations
bool StorageManager::save_download_state(const hash_t& root_hash, const std::string& file_path, uint32_t progress) {
    std::string sql = "INSERT OR REPLACE INTO downloads (root_hash, file_path, progress, status) VALUES (?, ?, ?, ?);";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db_) << std::endl;
        return false;
    }

    std::string root_hash_hex = Hasher::hash_to_hex(root_hash);
    sqlite3_bind_text(stmt, 1, root_hash_hex.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, file_path.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, progress);
    sqlite3_bind_text(stmt, 4, "active", -1, SQLITE_STATIC); // Default status

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "Failed to execute statement: " << sqlite3_errmsg(db_) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }
    sqlite3_finalize(stmt);
    return true;
}

std::tuple<std::string, uint32_t> StorageManager::get_download_state(const hash_t& root_hash) {
    std::string sql = "SELECT file_path, progress FROM downloads WHERE root_hash = ?;";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db_) << std::endl;
        return {"", 0};
    }

    std::string root_hash_hex = Hasher::hash_to_hex(root_hash);
    sqlite3_bind_text(stmt, 1, root_hash_hex.c_str(), -1, SQLITE_STATIC);

    if ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        std::string file_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        uint32_t progress = sqlite3_column_int(stmt, 1);
        sqlite3_finalize(stmt);
        return {file_path, progress};
    } else if (rc != SQLITE_DONE) {
        std::cerr << "Failed to execute statement: " << sqlite3_errmsg(db_) << std::endl;
    }
    sqlite3_finalize(stmt);
    return {"", 0};
}

std::vector<std::pair<hash_t, std::string>> StorageManager::get_all_downloads() {
    std::vector<std::pair<hash_t, std::string>> downloads;
    std::string sql = "SELECT root_hash, file_path FROM downloads WHERE status = 'active';";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db_) << std::endl;
        return downloads;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        std::string hash_hex = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        std::string file_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        
        downloads.push_back({Hasher::hex_to_hash(hash_hex), file_path});
    }
    sqlite3_finalize(stmt);
    return downloads;
}

bool StorageManager::delete_download_state(const hash_t& root_hash) {
    std::string sql = "DELETE FROM downloads WHERE root_hash = ?;";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db_) << std::endl;
        return false;
    }

    std::string root_hash_hex = Hasher::hash_to_hex(root_hash);
    sqlite3_bind_text(stmt, 1, root_hash_hex.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "Failed to execute statement: " << sqlite3_errmsg(db_) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }
    sqlite3_finalize(stmt);
    return true;
}
