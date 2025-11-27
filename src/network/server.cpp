#include "network/server.hpp"
#include "files/file_sharer.hpp"
#include "files/bitfield.hpp"
#include "common/serializer.hpp"
#include "dht/dht_node.hpp" // For dht::generate_random_id()
#include <iostream>
#include <iomanip> // For std::hex, std::setw, std::setfill

Server::Server(asio::io_context& io_context, uint16_t port)
    : io_context_(io_context),
      acceptor_(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port)),
      ssl_context_(asio::ssl::context::tlsv12_server), // Initialize SSL context
      peer_id_(dht::generate_random_id()), // Generate a random peer ID
      pubkey_() { // Initialize pubkey (will be filled with actual key later)
    // For now, fill pubkey with dummy data
    for(size_t i = 0; i < PUBKEY_SIZE; ++i) {
        pubkey_[i] = static_cast<uint8_t>(std::rand() % 256);
    }
    init_ssl_context(); // Initialize SSL context with certs
    std::cout << "Server listening on port " << port << std::endl;
    start_accept();
}

void Server::init_ssl_context() {
    try {
        ssl_context_.set_options(
            asio::ssl::context::default_workarounds
            | asio::ssl::context::no_sslv2);
        ssl_context_.use_certificate_chain_file("server.crt"); // Placeholder
        ssl_context_.use_private_key_file("server.key", asio::ssl::context::file_format::pem); // Placeholder
    } catch (const asio::system_error& e) {
        std::cerr << "Error initializing SSL context: " << e.what() << std::endl;
        // Handle error appropriately, e.g., exit or throw
    }
}

void Server::start_accept() {
    auto new_connection = std::make_shared<Connection>(io_context_, ssl_context_); // Pass ssl_context_

    new_connection->set_message_handler([this, conn_weak = std::weak_ptr<Connection>(new_connection)](Message msg) {
        if (auto conn_shared = conn_weak.lock()) {
            handle_message(msg, conn_shared);
        }
    });

    acceptor_.async_accept(new_connection->socket(),
        [this, new_connection](const asio::error_code& error) { // Renamed lambda parameter
            if (!error) {
                std::cout << "New connection accepted from " << new_connection->socket().remote_endpoint() << std::endl;
                connections_.insert(new_connection);
                new_connection->start(asio::ssl::stream_base::server); // Start SSL handshake
            } else {
                std::cerr << "Error accepting connection: " << error.message() << std::endl;
            }
            start_accept();
        });
}

void Server::handle_message(Message msg, std::shared_ptr<Connection> connection) {
    switch (msg.type) {
        case MessageType::HANDSHAKE:
            handle_handshake(msg, connection);
            break;
        case MessageType::QUERY_SEARCH:
            handle_query_search(msg, connection);
            break;
        case MessageType::REQUEST_PIECE:
            handle_request_piece(msg, connection);
            break;
        case MessageType::BITFIELD: 
            {
                hash_t root_hash;
                std::memcpy(root_hash.data(), msg.payload.data(), HASH_SIZE);
                auto manifest = FileSharer::instance().get_manifest(root_hash);
                if(manifest) {
                    std::vector<uint8_t> field_bytes(msg.payload.begin() + HASH_SIZE, msg.payload.end());
                    Bitfield bf(manifest->pieces_count, field_bytes);
                    connection->set_peer_bitfield(root_hash, bf);
                    std::cout << "Received bitfield from peer for hash." << std::endl;
                }
            }
            break;
        default:
            std::cerr << "Server received unhandled message type: " << static_cast<int>(msg.type) << std::endl;
            break;
    }
}

void Server::handle_query_search(const Message& msg, std::shared_ptr<Connection> connection) {
    QuerySearchPayload payload;
    std::memcpy(&payload, msg.payload.data(), sizeof(payload));

    std::cout << "Received QUERY_SEARCH for hash." << std::endl;

    auto manifest_opt = FileSharer::instance().get_manifest(payload.root_hash);

    Message response;
    response.type = MessageType::SEARCH_RESPONSE;

    if (manifest_opt) {
        std::cout << "File found. Sending manifest and bitfield." << std::endl;
        
        response.payload.push_back(1); // Found = true
        std::vector<uint8_t> manifest_bytes = Serializer::serialize_manifest(*manifest_opt);
        response.payload.insert(response.payload.end(), manifest_bytes.begin(), manifest_bytes.end());
        connection->send_message(response);

        Bitfield own_bitfield(manifest_opt->pieces_count);
        own_bitfield.set_all();

        Message bitfield_msg;
        bitfield_msg.type = MessageType::BITFIELD;
        bitfield_msg.payload.insert(bitfield_msg.payload.end(), payload.root_hash.begin(), payload.root_hash.end());
        const auto& bf_bytes = own_bitfield.get_bytes();
        bitfield_msg.payload.insert(bitfield_msg.payload.end(), bf_bytes.begin(), bf_bytes.end());
        connection->send_message(bitfield_msg);

    } else {
        std::cout << "File not found." << std::endl;
        response.payload.push_back(0); // Found = false
        connection->send_message(response);
    }
}

void Server::handle_handshake(const Message& msg, std::shared_ptr<Connection> connection) {
    std::cout << "Received HANDSHAKE from " << connection->socket().remote_endpoint() << std::endl;
    HandshakePayload received_hs = Serializer::deserialize_handshake_payload(msg.payload);

    // For now, just print received info
    std::cout << "  Peer ID: ";
    for(uint8_t byte : received_hs.peer_id) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    std::cout << std::dec << ", Port: " << received_hs.listen_port << std::endl;

    // Send our own handshake back
    HandshakePayload own_hs;
    own_hs.pubkey = pubkey_;
    own_hs.protocol_version = PROTOCOL_VERSION;
    own_hs.listen_port = acceptor_.local_endpoint().port();
    own_hs.peer_id = peer_id_;
    own_hs.features = 0;

    Message response_msg;
    response_msg.type = MessageType::HANDSHAKE;
    response_msg.payload = Serializer::serialize_handshake_payload(own_hs);
    connection->send_message(response_msg);
    std::cout << "Sent HANDSHAKE response to " << connection->socket().remote_endpoint() << std::endl;
}

void Server::handle_request_piece(const Message& msg, std::shared_ptr<Connection> connection) {
    RequestPiecePayload payload;
    std::memcpy(&payload, msg.payload.data(), sizeof(payload));

    std::cout << "Received REQUEST_PIECE for piece " << payload.piece_index << std::endl;

    try {
        std::vector<uint8_t> piece_data = FileSharer::instance().get_piece(payload.root_hash, payload.piece_index);

        Message response;
        response.type = MessageType::PIECE;
        response.payload.insert(response.payload.end(), payload.root_hash.begin(), payload.root_hash.end());
        response.payload.insert(response.payload.end(), (uint8_t*)&payload.piece_index, (uint8_t*)&payload.piece_index + sizeof(uint32_t));
        response.payload.insert(response.payload.end(), piece_data.begin(), piece_data.end());
        
        connection->send_message(response);
        std::cout << "Sent piece " << payload.piece_index << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error getting piece: " << e.what() << std::endl;
    }
}