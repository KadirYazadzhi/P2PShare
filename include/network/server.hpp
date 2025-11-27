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

class Server {
public:
    Server(asio::io_context& io_context, uint16_t port);

private:
    void start_accept();
    void handle_accept(std::shared_ptr<Connection> new_connection, const asio::error_code& error); // Added handle_accept
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
};

#endif //P2P_SERVER_HPP