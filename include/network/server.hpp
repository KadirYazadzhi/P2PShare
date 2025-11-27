#ifndef P2P_SERVER_HPP
#define P2P_SERVER_HPP

#include <asio.hpp>
#include <asio/ts/internet.hpp>
#include <asio/ssl.hpp> // Added for SSL
#include <memory>
#include <set>
#include <iostream>

#include "connection.hpp"
#include "protocol.hpp"
#include "../files/download_manager.hpp"
#include "../storage/storage_manager.hpp"
#include "../dht/dht_node.hpp"
#include <map>

class Server {
public:
    Server(asio::io_context& io_context, uint16_t port, StorageManager& storage_manager);

    void start_download(const hash_t& root_hash); // Removed explicit StorageManager arg as we now have it as member
    std::vector<std::shared_ptr<DownloadManager>> get_active_downloads() const;
    
    // Connect to a peer
    void connect(const std::string& host, uint16_t port);
    
    // Advanced NAT Traversal
    void connect_with_hole_punch(const std::string& host, uint16_t port);

    // Access DHT
    dht::DhtNode& get_dht_node() { return dht_node_; }

    // Bandwidth control
    void set_global_upload_limit(size_t bytes_per_sec);
    void set_global_download_limit(size_t bytes_per_sec);

private:
    void start_accept();
    void handle_accept(std::shared_ptr<Connection> new_connection, const asio::error_code& error);
    void handle_message(Message msg, std::shared_ptr<Connection> connection);

    // Specific message handlers
    void handle_handshake(const Message& msg, std::shared_ptr<Connection> connection);
    void handle_query_search(const Message& msg, std::shared_ptr<Connection> connection);
    void handle_request_piece(const Message& msg, std::shared_ptr<Connection> connection);

    void init_ssl_context(); // Helper to initialize SSL context

    asio::io_context& io_context_;
    asio::ip::tcp::acceptor acceptor_;
    asio::ssl::context ssl_context_; // Added SSL context
    std::set<std::shared_ptr<Connection>> connections_; // To keep connections alive
    dht::NodeID peer_id_;
    std::array<uint8_t, PUBKEY_SIZE> pubkey_;
    
    std::map<hash_t, std::shared_ptr<DownloadManager>> active_downloads_;
    
    StorageManager& storage_manager_;
    dht::DhtNode dht_node_;
    
    std::shared_ptr<RateLimiter> global_upload_limiter_;
    std::shared_ptr<RateLimiter> global_download_limiter_;
};
#endif //P2P_SERVER_HPP