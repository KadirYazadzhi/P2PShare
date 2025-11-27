#ifndef P2P_CLIENT_HPP
#define P2P_CLIENT_HPP

#include <asio.hpp>
#include <asio/ts/internet.hpp>
#include <asio/ssl.hpp> // Added for SSL
#include <memory>
#include <iostream>
#include <functional>

#include "connection.hpp"
#include "protocol.hpp"
#include "../files/download_manager.hpp"
#include "../dht/dht_node.hpp" // For dht::generate_random_id()
#include "../crypto/hasher.hpp" // For hash_t (pubkey type)

class Client {
public:
    using message_handler_t = std::function<void(const Message&, std::shared_ptr<Connection>)>;
    using on_connect_handler_t = std::function<void(std::shared_ptr<Connection>)>;

    Client(asio::io_context& io_context, message_handler_t handler, asio::ssl::context& ssl_context)
        : io_context_(io_context), message_handler_(handler), ssl_context_(ssl_context),
          peer_id_(dht::generate_random_id()),
          pubkey_(),
          upload_limiter_(std::make_shared<RateLimiter>(1024 * 1024 * 10)), // 10 MB/s default
          download_limiter_(std::make_shared<RateLimiter>(1024 * 1024 * 10)) {
        for(size_t i = 0; i < PUBKEY_SIZE; ++i) {
            pubkey_[i] = static_cast<uint8_t>(std::rand() % 256);
        }
    }

private:
    std::shared_ptr<RateLimiter> upload_limiter_;
    std::shared_ptr<RateLimiter> download_limiter_;

    void send_handshake(std::shared_ptr<Connection> connection) {
        HandshakePayload hs_payload;
        hs_payload.pubkey = pubkey_; // Use client's generated pubkey
        hs_payload.protocol_version = PROTOCOL_VERSION;
        hs_payload.listen_port = connection->socket().local_endpoint().port(); // Use actual local port
        hs_payload.peer_id = peer_id_; // Use client's generated peer ID
        hs_payload.features = 0; // No features yet

        Message handshake_msg;
        handshake_msg.type = MessageType::HANDSHAKE;
        handshake_msg.payload = Serializer::serialize_handshake_payload(hs_payload);
        
        connection->send_message(handshake_msg);
        std::cout << "Sent HANDSHAKE message.\n";
    }

public:
    void connect(const std::string& host, uint16_t port, on_connect_handler_t on_connect) {
        auto conn = std::make_shared<Connection>(io_context_, ssl_context_, upload_limiter_, download_limiter_); 
        
        conn->set_message_handler([this, conn_weak = std::weak_ptr<Connection>(conn)](const Message& msg) {
            if (auto conn_shared = conn_weak.lock()) {
                if (message_handler_) {
                    message_handler_(msg, conn_shared);
                }
            }
        });

        asio::ip::tcp::endpoint endpoint(asio::ip::make_address(host), port);

        conn->socket().async_connect(endpoint,
            [this, conn, on_connect](const asio::error_code& error) {
                if (!error) {
                    std::cout << "Connected to " << conn->socket().remote_endpoint() << std::endl;
                    // Start SSL handshake and provide a callback for success
                    conn->start(asio::ssl::stream_base::client, [this, conn, on_connect] {
                        // This code runs AFTER SSL is established
                        send_handshake(conn);
                        if (on_connect) {
                            on_connect(conn);
                        }
                    });
                } else {
                    std::cerr << "Error connecting: " << error.message() << std::endl;
                    // If connection fails, we need to signal the on_connect handler
                    if (on_connect) {
                        on_connect(nullptr);
                    }
                }
            });
    }

private:
    asio::io_context& io_context_;
    message_handler_t message_handler_;
    asio::ssl::context& ssl_context_; // Added SSL context
    dht::NodeID peer_id_;
    std::array<uint8_t, PUBKEY_SIZE> pubkey_; // Assuming PUBKEY_SIZE is defined in protocol.hpp
};

#endif //P2P_CLIENT_HPP