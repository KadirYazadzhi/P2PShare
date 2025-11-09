#ifndef P2P_DOWNLOAD_MANAGER_HPP
#define P2P_DOWNLOAD_MANAGER_HPP

#include "manifest.hpp"
#include "../network/connection.hpp"
#include <memory>
#include <vector>
#include <filesystem>
#include <optional>
#include <set>

namespace fs = std::filesystem;

class DownloadManager {
public:
    explicit DownloadManager(hash_t root_hash);

    // Add a new peer to this download swarm
    void add_peer(std::shared_ptr<Connection> peer_conn);

    // Handles incoming messages relevant to the download from any peer
    void handle_message(const Message& msg, std::shared_ptr<Connection> peer_conn);

    // Starts the download process (can be called after adding the first peer)
    void start();

    size_t get_peer_count() const { return peers_.size(); } // <--- Added this

private:
    void handle_search_response(const Message& msg, std::shared_ptr<Connection> peer_conn);
    void handle_piece_response(const Message& msg, std::shared_ptr<Connection> peer_conn);
    void handle_bitfield_response(const Message& msg, std::shared_ptr<Connection> peer_conn);

    // The main work scheduler
    void schedule_work();
    void request_piece_from_peer(uint32_t piece_index, std::shared_ptr<Connection> peer_conn);

    bool verify_and_write_piece(uint32_t piece_index, const std::vector<uint8_t>& data);
    void finalize_download();

    enum class PieceState {
        Needed,
        Requested,
        Have
    };

    enum class ManagerState {
        IDLE,
        REQUESTING_MANIFEST,
        DOWNLOADING,
        COMPLETED,
        FAILED
    };

    ManagerState state_;
    hash_t root_hash_;
    std::optional<Manifest> manifest_;
    
    // Swarm state
    std::set<std::shared_ptr<Connection>> peers_;

    // Download progress
    std::vector<PieceState> piece_states_;
    
    fs::path temp_file_path_;
    fs::path final_file_path_;
};

#endif //P2P_DOWNLOAD_MANAGER_HPP
