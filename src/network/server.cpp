#include "network/server.hpp"
#include "files/file_sharer.hpp"
#include "files/bitfield.hpp"
#include "common/serializer.hpp"
#include "dht/dht_node.hpp"
#include "common/logger.hpp"
#include <iostream>
#include <iomanip>

Server::Server(asio::io_context& io_context, uint16_t port, StorageManager& storage_manager)
    : io_context_(io_context),
      acceptor_(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port)),
      ssl_context_(asio::ssl::context::tlsv12_server),
      peer_id_(dht::generate_random_id()),
      pubkey_(),
      storage_manager_(storage_manager),
      dht_node_(io_context, port, storage_manager),
      global_upload_limiter_(std::make_shared<RateLimiter>(10 * 1024 * 1024)), 
      global_download_limiter_(std::make_shared<RateLimiter>(10 * 1024 * 1024)),
      unchoke_timer_(io_context) {

    for(size_t i = 0; i < PUBKEY_SIZE; ++i) {
        pubkey_[i] = static_cast<uint8_t>(std::rand() % 256);
    }
    init_ssl_context();
    LOG_INFO("Server listening on TCP port ", port, " and UDP port ", port, " (DHT)");
    
    auto pending_downloads = storage_manager_.get_all_downloads();
    LOG_INFO("Resuming ", pending_downloads.size(), " active downloads...");
    for (const auto& [root_hash, path] : pending_downloads) {
        start_download(root_hash);
    }

    dht_node_.set_on_hole_punch_request([this](const asio::ip::udp::endpoint& target) {
        LOG_INFO("Received Hole Punch Request via DHT. Attempting TCP connect to: ", target);
        connect(target.address().to_string(), target.port());
    });

    dht_node_.start(); 
    start_accept();
    schedule_unchoke_round();
}

void Server::set_global_upload_limit(size_t bytes_per_sec) {
    if (global_upload_limiter_) global_upload_limiter_->set_max_rate(bytes_per_sec);
}

void Server::set_global_download_limit(size_t bytes_per_sec) {
    if (global_download_limiter_) global_download_limiter_->set_max_rate(bytes_per_sec);
}

void Server::init_ssl_context() {
    try {
        ssl_context_.set_options(
            asio::ssl::context::default_workarounds
            | asio::ssl::context::no_sslv2);
        ssl_context_.use_certificate_chain_file("server.crt");
        ssl_context_.use_private_key_file("server.key", asio::ssl::context::file_format::pem);
    } catch (const asio::system_error& e) {
        LOG_ERR("Error initializing SSL context: ", e.what());
    }
}

void Server::start_accept() {
    auto new_connection = std::make_shared<Connection>(io_context_, ssl_context_, global_upload_limiter_, global_download_limiter_);

    new_connection->set_message_handler([this, conn_weak = std::weak_ptr<Connection>(new_connection)](Message msg) {
        if (auto conn_shared = conn_weak.lock()) {
            handle_message(msg, conn_shared);
        }
    });

    acceptor_.async_accept(new_connection->socket(),
        [this, new_connection](const asio::error_code& error) {
            if (!error) {
                LOG_INFO("New connection accepted from ", new_connection->socket().remote_endpoint());
                connections_.insert(new_connection);
                for (auto& [h, dm] : active_downloads_) {
                    dm->add_peer(new_connection);
                }
                new_connection->start(asio::ssl::stream_base::server);
            } else {
                LOG_ERR("Error accepting connection: ", error.message());
            }
            start_accept();
        });
}

void Server::connect(const std::string& host, uint16_t port) {
    auto new_connection = std::make_shared<Connection>(io_context_, ssl_context_, global_upload_limiter_, global_download_limiter_);

    new_connection->set_message_handler([this, conn_weak = std::weak_ptr<Connection>(new_connection)](Message msg) {
        if (auto conn_shared = conn_weak.lock()) {
            handle_message(msg, conn_shared);
        }
    });

    asio::ip::tcp::endpoint endpoint(asio::ip::make_address(host), port);

    new_connection->socket().async_connect(endpoint,
        [this, new_connection, endpoint](const asio::error_code& error) {
            if (!error) {
                LOG_INFO("Connected to ", endpoint);
                connections_.insert(new_connection);
                for (auto& [h, dm] : active_downloads_) {
                    dm->add_peer(new_connection);
                }
                
                new_connection->start(asio::ssl::stream_base::client, [this, new_connection]() {
                     HandshakePayload hs;
                     hs.pubkey = pubkey_;
                     hs.protocol_version = PROTOCOL_VERSION;
                     hs.listen_port = acceptor_.local_endpoint().port();
                     hs.peer_id = peer_id_;
                     hs.features = 0;
                     
                     Message msg;
                     msg.type = MessageType::HANDSHAKE;
                     msg.payload = Serializer::serialize_handshake_payload(hs);
                     new_connection->send_message(msg);
                     LOG_INFO("Sent HANDSHAKE to ", new_connection->socket().remote_endpoint());
                });
            } else {
                LOG_ERR("Error connecting to ", endpoint, ": ", error.message());
            }
        });
}

void Server::connect_with_hole_punch(const std::string& host, uint16_t port) {
    LOG_INFO("Initiating TCP Hole Punch to ", host, ":", port);
    
    asio::ip::udp::endpoint target_ep(asio::ip::make_address(host), port);
    
    std::string my_ip = dht_node_.get_external_ip();
    uint16_t my_port = dht_node_.get_external_port();
    if (my_ip.empty()) { 
        my_ip = "0.0.0.0";
    }
    asio::ip::udp::endpoint my_ep(asio::ip::make_address(my_ip), my_port);

    dht_node_.send_hole_punch_request(target_ep, my_ep);

    auto timer = std::make_shared<asio::steady_timer>(io_context_);
    timer->expires_after(std::chrono::milliseconds(100));
    timer->async_wait([this, host, port, timer](const asio::error_code& error){
        if (!error) {
             LOG_INFO("Hole Punch: Executing Simultaneous TCP Connect to ", host, ":", port);
             connect(host, port);
        }
    });
}

void Server::start_download(const hash_t& root_hash) {
    if (active_downloads_.find(root_hash) == active_downloads_.end()) {
        auto dm = std::make_shared<DownloadManager>(root_hash, storage_manager_);
        active_downloads_[root_hash] = dm;
        for (auto& conn : connections_) {
            dm->add_peer(conn);
        }
        dm->start();
    }
}

std::vector<std::shared_ptr<DownloadManager>> Server::get_active_downloads() const {
    std::vector<std::shared_ptr<DownloadManager>> ret;
    for(auto const& [hash, dm] : active_downloads_) {
        ret.push_back(dm);
    }
    return ret;
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
        case MessageType::SEARCH_RESPONSE:
            for(auto& [h, dm] : active_downloads_) {
                 dm->handle_message(msg, connection);
            }
            break;
        case MessageType::PIECE:
        case MessageType::HAVE:
        {
             if (msg.payload.size() < HASH_SIZE) break;
             hash_t root_hash;
             std::memcpy(root_hash.data(), msg.payload.data(), HASH_SIZE);
             if(active_downloads_.count(root_hash)) {
                 active_downloads_[root_hash]->handle_message(msg, connection);
             }
             break;
        }
        case MessageType::BITFIELD: 
            {
                if (msg.payload.size() < HASH_SIZE) break;
                hash_t root_hash;
                std::memcpy(root_hash.data(), msg.payload.data(), HASH_SIZE);
                
                if(active_downloads_.count(root_hash)) {
                    active_downloads_[root_hash]->handle_message(msg, connection);
                }

                auto manifest = FileSharer::instance().get_manifest(root_hash);
                if(manifest) {
                    std::vector<uint8_t> field_bytes(msg.payload.begin() + HASH_SIZE, msg.payload.end());
                    Bitfield bf(manifest->pieces_count, field_bytes);
                    connection->set_peer_bitfield(root_hash, bf);
                }
            }
            break;
        case MessageType::CHOKE:
            connection->set_peer_choking(true);
            LOG_INFO("Peer ", connection->socket().remote_endpoint(), " CHOKED us.");
            break;
        case MessageType::UNCHOKE:
            connection->set_peer_choking(false);
            LOG_INFO("Peer ", connection->socket().remote_endpoint(), " UNCHOKED us.");
            break;
        case MessageType::RELAY_REGISTER:
            handle_relay_register(connection);
            break;
        case MessageType::RELAY_CONNECT:
            handle_relay_connect(msg, connection);
            break;
        case MessageType::RELAY_DATA:
            handle_relay_data(msg, connection);
            break;
        default:
            LOG_ERR("Server received unhandled message type: ", static_cast<int>(msg.type));
            break;
    }
}

void Server::handle_query_search(const Message& msg, std::shared_ptr<Connection> connection) {
    QuerySearchPayload payload;
    std::memcpy(&payload, msg.payload.data(), sizeof(payload));

    auto manifest_opt = FileSharer::instance().get_manifest(payload.root_hash);
    Message response;
    response.type = MessageType::SEARCH_RESPONSE;

    if (manifest_opt) {
        response.payload.push_back(1);
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
        response.payload.push_back(0); 
        connection->send_message(response);
    }
}

void Server::handle_handshake(const Message& msg, std::shared_ptr<Connection> connection) {
    LOG_INFO("Received HANDSHAKE from ", connection->socket().remote_endpoint());
    
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
    LOG_INFO("Sent HANDSHAKE response to ", connection->socket().remote_endpoint());
}

void Server::handle_request_piece(const Message& msg, std::shared_ptr<Connection> connection) {
    if (connection->is_am_choking()) return;

    RequestPiecePayload payload;
    std::memcpy(&payload, msg.payload.data(), sizeof(payload));

    try {
        std::vector<uint8_t> piece_data = FileSharer::instance().get_piece(payload.root_hash, payload.piece_index);

        Message response;
        response.type = MessageType::PIECE;
        response.payload.insert(response.payload.end(), payload.root_hash.begin(), payload.root_hash.end());
        response.payload.insert(response.payload.end(), (uint8_t*)&payload.piece_index, (uint8_t*)&payload.piece_index + sizeof(uint32_t));
        response.payload.insert(response.payload.end(), piece_data.begin(), piece_data.end());
        
        connection->send_message(response);
    } catch (const std::exception& e) {
        LOG_ERR("Error getting piece: ", e.what());
    }
}

void Server::handle_relay_register(std::shared_ptr<Connection> connection) {
    uint32_t session_id = next_session_id_++;
    relay_sessions_[session_id] = {connection, nullptr};
    conn_to_session_id_[connection] = session_id;
    
    LOG_INFO("Relay: Allocated Session ID ", session_id, " for peer ", connection->socket().remote_endpoint());
    
    std::vector<uint8_t> payload = Serializer::serialize_relay_register_response(session_id);
    Message response;
    response.type = MessageType::RELAY_REGISTER_RESPONSE;
    response.payload = payload;
    connection->send_message(response);
}

void Server::handle_relay_connect(const Message& msg, std::shared_ptr<Connection> connection) {
    uint32_t session_id = Serializer::deserialize_relay_connect(msg.payload);
    
    if (relay_sessions_.find(session_id) != relay_sessions_.end()) {
        RelaySession& session = relay_sessions_[session_id];
        if (session.peer == nullptr) {
            session.peer = connection;
            conn_to_session_id_[connection] = session_id;
            LOG_INFO("Relay: Peer connected to Session ID ", session_id, ". Bridge established.");
        } else {
            LOG_WARN("Relay: Session ID ", session_id, " is already full.");
        }
    } else {
        LOG_WARN("Relay: Connection attempt to invalid Session ID ", session_id);
    }
}

void Server::handle_relay_data(const Message& msg, std::shared_ptr<Connection> connection) {
    if (conn_to_session_id_.count(connection)) {
        uint32_t session_id = conn_to_session_id_[connection];
        if (relay_sessions_.count(session_id)) {
            RelaySession& session = relay_sessions_[session_id];
            std::shared_ptr<Connection> target = (session.initiator == connection) ? session.peer : session.initiator;
            
            if (target) {
                target->send_message(msg); 
            }
        }
        return;
    }
    
    if (msg.payload.empty()) return;
    
    MessageType inner_type = static_cast<MessageType>(msg.payload[0]);
    std::vector<uint8_t> inner_payload(msg.payload.begin() + 1, msg.payload.end());
    
    Message inner_msg;
    inner_msg.type = inner_type;
    inner_msg.payload = inner_payload;
    
    handle_message(inner_msg, connection);
}

void Server::connect_via_relay(const std::string& relay_host, uint16_t relay_port, uint32_t session_id) {
    auto new_connection = std::make_shared<Connection>(io_context_, ssl_context_, global_upload_limiter_, global_download_limiter_);

    new_connection->set_message_handler([this, conn_weak = std::weak_ptr<Connection>(new_connection)](Message msg) {
        if (auto conn_shared = conn_weak.lock()) {
            handle_message(msg, conn_shared);
        }
    });

    asio::ip::tcp::endpoint endpoint(asio::ip::make_address(relay_host), relay_port);

    new_connection->socket().async_connect(endpoint,
        [this, new_connection, session_id](const asio::error_code& error) {
            if (!error) {
                LOG_INFO("Connected to Relay Server. Joining Session ID ", session_id);
                connections_.insert(new_connection);
                
                new_connection->start(asio::ssl::stream_base::client, [this, new_connection, session_id]() {
                     std::vector<uint8_t> payload = Serializer::serialize_relay_connect(session_id);
                     Message msg;
                     msg.type = MessageType::RELAY_CONNECT;
                     msg.payload = payload;
                     new_connection->send_message(msg);
                     
                     HandshakePayload hs;
                     hs.pubkey = pubkey_;
                     hs.protocol_version = PROTOCOL_VERSION;
                     hs.listen_port = acceptor_.local_endpoint().port();
                     hs.peer_id = peer_id_;
                     hs.features = 0;
                     
                     std::vector<uint8_t> inner_payload = Serializer::serialize_handshake_payload(hs);
                     std::vector<uint8_t> wrapper_payload;
                     wrapper_payload.push_back(static_cast<uint8_t>(MessageType::HANDSHAKE));
                     wrapper_payload.insert(wrapper_payload.end(), inner_payload.begin(), inner_payload.end());
                     
                     Message relay_msg;
                     relay_msg.type = MessageType::RELAY_DATA;
                     relay_msg.payload = wrapper_payload;
                     new_connection->send_message(relay_msg);
                     
                     LOG_INFO("Sent Wrapped HANDSHAKE via Relay.");
                });
            } else {
                LOG_ERR("Error connecting to Relay: ", error.message());
            }
        });
}

void Server::register_on_relay(const std::string& relay_host, uint16_t relay_port) {
    auto new_connection = std::make_shared<Connection>(io_context_, ssl_context_, global_upload_limiter_, global_download_limiter_);

    new_connection->set_message_handler([this, conn_weak = std::weak_ptr<Connection>(new_connection)](Message msg) {
        if (auto conn_shared = conn_weak.lock()) {
            handle_message(msg, conn_shared);
        }
    });

    asio::ip::tcp::endpoint endpoint(asio::ip::make_address(relay_host), relay_port);

    new_connection->socket().async_connect(endpoint,
        [this, new_connection](const asio::error_code& error) {
            if (!error) {
                LOG_INFO("Connected to Relay Server. Registering...");
                connections_.insert(new_connection);
                
                new_connection->start(asio::ssl::stream_base::client, [this, new_connection]() {
                     Message msg;
                     msg.type = MessageType::RELAY_REGISTER;
                     new_connection->send_message(msg);
                     LOG_INFO("Sent RELAY_REGISTER.");
                });
            } else {
                LOG_ERR("Error connecting to Relay: ", error.message());
            }
        });
}

void Server::schedule_unchoke_round() {
    unchoke_timer_.expires_after(std::chrono::seconds(10));
    unchoke_timer_.async_wait([this](const asio::error_code& error) {
        if (!error) {
            recalculate_unchoked_peers();
            schedule_unchoke_round();
        }
    });
}

void Server::recalculate_unchoked_peers() {
    std::vector<std::shared_ptr<Connection>> active_peers(connections_.begin(), connections_.end());
    if (active_peers.empty()) return;

    std::sort(active_peers.begin(), active_peers.end(), [](const auto& a, const auto& b) {
        return a->get_download_speed() > b->get_download_speed();
    });

    std::set<std::shared_ptr<Connection>> to_unchoke;
    for (size_t i = 0; i < 3 && i < active_peers.size(); ++i) {
        to_unchoke.insert(active_peers[i]);
    }

    std::vector<std::shared_ptr<Connection>> choked_peers;
    for (const auto& peer : active_peers) {
        if (to_unchoke.find(peer) == to_unchoke.end()) {
            choked_peers.push_back(peer);
        }
    }

    if (!choked_peers.empty()) {
        size_t idx = std::rand() % choked_peers.size();
        optimistic_unchoke_peer_ = choked_peers[idx];
        to_unchoke.insert(optimistic_unchoke_peer_);
    } else {
        optimistic_unchoke_peer_.reset();
    }

    for (auto& peer : active_peers) {
        if (to_unchoke.count(peer)) {
            peer->unchoke_peer();
        } else {
            peer->choke_peer();
        }
    }
}
