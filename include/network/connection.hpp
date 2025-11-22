#ifndef P2P_CONNECTION_HPP
#define P2P_CONNECTION_HPP

#include <asio.hpp>
#include <asio/ts/buffer.hpp>
#include <asio/ts/internet.hpp>
#include <asio/ssl.hpp> // Added for SSL
#include <deque>
#include <memory>
#include <iostream>
#include <functional>
#include <map>
#include <optional> // <--- Added this include

#include "protocol.hpp"
#include "../files/bitfield.hpp"
#include "../common/serializer.hpp" // Include serializer for send_have

// Forward declaration for the Connection class
class Connection;

// Define a message structure for easier handling
struct Message {
    MessageType type;
    std::vector<uint8_t> payload;
};

class Connection : public std::enable_shared_from_this<Connection> {
public:
    using ssl_socket = asio::ssl::stream<asio::ip::tcp::socket>; // Changed from tcp_socket
    using message_handler = std::function<void(Message)>;

    Connection(asio::io_context& io_context, asio::ssl::context& ssl_context) // Modified constructor
        : io_context_(io_context), socket_(io_context, ssl_context) {} // Initialized ssl_socket

    void set_message_handler(message_handler handler) {
        message_handler_ = std::move(handler);
    }

    ssl_socket::lowest_layer_type& socket() { // Return lowest_layer_type for raw socket access
        return socket_.lowest_layer();
    }

    void start(asio::ssl::stream_base::handshake_type type) { // Added handshake_type parameter
        socket_.async_handshake(type,
            [self = shared_from_this()](const asio::error_code& error) {
                if (!error) {
                    std::cout << "SSL Handshake successful!" << std::endl;
                    self->read_header(); // Start reading application data
                } else {
                    std::cerr << "SSL Handshake failed: " << error.message() << std::endl;
                    self->socket_.lowest_layer().close();
                }
            });
    }

    void send_message(const Message& msg) {
        asio::post(io_context_,
                   [self = shared_from_this(), msg]() {
                       bool write_in_progress = !self->write_msgs_.empty();
                       self->write_msgs_.push_back(msg);
                       if (!write_in_progress) {
                           self->write_header();
                       }
                   });
    }

    // Bitfield management
    void set_peer_bitfield(const hash_t& root_hash, const Bitfield& bitfield) {
        peer_bitfields_[root_hash] = bitfield;
    }

    std::optional<Bitfield> get_peer_bitfield(const hash_t& root_hash) {
        auto it = peer_bitfields_.find(root_hash);
        if (it != peer_bitfields_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    void send_have(const hash_t& root_hash, uint32_t piece_index) {
        Message have_msg;
        have_msg.type = MessageType::HAVE;
        have_msg.payload = Serializer::serialize_have_payload(root_hash, piece_index);
        send_message(have_msg);
    }


private:
    void read_header() {
        asio::async_read(socket_, asio::buffer(read_header_buffer_, HEADER_SIZE), // Use ssl_socket
            [self = shared_from_this()](const asio::error_code& error, size_t bytes_transferred) {
                if (!error) {
                    uint32_t payload_len;
                    std::memcpy(&payload_len, self->read_header_buffer_.data(), sizeof(uint32_t));
                    payload_len = asio::detail::socket_ops::network_to_host_long(payload_len);

                    MessageType msg_type = static_cast<MessageType>(self->read_header_buffer_[sizeof(uint32_t)]);

                    self->read_body(payload_len, msg_type);
                } else {
                    self->socket_.lowest_layer().close(); // Close lowest_layer
                }
            });
    }

    void read_body(uint32_t payload_len, MessageType msg_type) {
        read_msg_.type = msg_type;
        read_msg_.payload.resize(payload_len);

        asio::async_read(socket_, asio::buffer(read_msg_.payload), // Use ssl_socket
            [self = shared_from_this()](const asio::error_code& error, size_t bytes_transferred) {
                if (!error) {
                    if (self->message_handler_) {
                        self->message_handler_(self->read_msg_);
                    }
                    self->read_header();
                } else {
                    self->socket_.lowest_layer().close(); // Close lowest_layer
                }
            });
    }

    void write_header() {
        if (!write_msgs_.empty()) {
            const Message& msg = write_msgs_.front();
            uint32_t payload_len = static_cast<uint32_t>(msg.payload.size());
            payload_len = asio::detail::socket_ops::host_to_network_long(payload_len);

            std::memcpy(write_header_buffer_.data(), &payload_len, sizeof(uint32_t));
            write_header_buffer_[sizeof(uint32_t)] = static_cast<uint8_t>(msg.type);

            asio::async_write(socket_, asio::buffer(write_header_buffer_, HEADER_SIZE), // Use ssl_socket
                [self = shared_from_this()](const asio::error_code& error, size_t bytes_transferred) {
                    if (!error) {
                        self->write_body();
                    } else {
                        std::cerr << "Error writing header: " << error.message() << std::endl;
                        self->socket_.lowest_layer().close(); // Close lowest_layer
                    }
                });
        }
    }

    void write_body() {
        if (!write_msgs_.empty()) {
            const Message& msg = write_msgs_.front();
            asio::async_write(socket_, asio::buffer(msg.payload), // Use ssl_socket
                [self = shared_from_this()](const asio::error_code& error, size_t bytes_transferred) {
                    if (!error) {
                        self->write_msgs_.pop_front();
                        if (!self->write_msgs_.empty()) {
                            self->write_header();
                        }
                    } else {
                        std::cerr << "Error writing body: " << error.message() << std::endl;
                        self->socket_.lowest_layer().close(); // Close lowest_layer
                    }
                });
        }
    }

private:
    asio::io_context& io_context_;
    ssl_socket socket_; // Changed from tcp_socket
    message_handler message_handler_;
    std::array<uint8_t, HEADER_SIZE> read_header_buffer_;
    std::array<uint8_t, HEADER_SIZE> write_header_buffer_;
    Message read_msg_;
    std::deque<Message> write_msgs_;

    // State for the remote peer
    std::map<hash_t, Bitfield> peer_bitfields_;
};

#endif //P2P_CONNECTION_HPP
