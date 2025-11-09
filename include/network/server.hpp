#ifndef P2P_SERVER_HPP
#define P2P_SERVER_HPP

#include <asio.hpp>
#include <asio/ts/internet.hpp>
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
    void handle_message(Message msg, std::shared_ptr<Connection> connection);

    // Specific message handlers
    void handle_query_search(const Message& msg, std::shared_ptr<Connection> connection);
    void handle_request_piece(const Message& msg, std::shared_ptr<Connection> connection);

    asio::io_context& io_context_;
    asio::ip::tcp::acceptor acceptor_;
    std::set<std::shared_ptr<Connection>> connections_; // To keep connections alive
};

#endif //P2P_SERVER_HPP