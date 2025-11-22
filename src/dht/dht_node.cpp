#include "dht/dht_node.hpp"
#include "network/protocol.hpp"
#include "common/serializer.hpp" // Added this line
#include <iostream>
#include <iomanip> // For std::setw, std::setfill
#include <random>
#include <algorithm> // For std::sort

namespace dht {

// Helper to generate a random NodeID
NodeID generate_random_id() {
    NodeID id;
    for (size_t i = 0; i < NODE_ID_SIZE; ++i) {
        id[i] = rand() % 256;
    }
    return id;
}

DhtNode::DhtNode(asio::io_context& io_context, uint16_t port, StorageManager& storage_manager)
    : io_context_(io_context),
      socket_(io_context, asio::ip::udp::endpoint(asio::ip::udp::v4(), port)),
      self_id_(generate_random_id()),
      routing_table_(self_id_),
      refresh_timer_(io_context),
      nat_traversal_(),
      storage_manager_(storage_manager) { // Initialize NatTraversal and StorageManager
    
    std::cout << "DHT Node created. ID: ";
    for(uint8_t byte : self_id_) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    std::cout << std::dec << " on port " << port << std::endl;
}

DhtNode::~DhtNode() {
    // Remove port mapping on shutdown
    if (!external_ip_.empty() && external_port_ != 0) {
        nat_traversal_.remove_port_mapping(external_port_, "UDP");
    }
}

void DhtNode::start() {
    // Load known peers from storage
    std::vector<NodeInfo> stored_peers = storage_manager_.get_peers();
    for (const auto& peer : stored_peers) {
        routing_table_.add_node(peer);
        std::cout << "Loaded peer " << peer.endpoint << " from storage." << std::endl;
    }

    // Try to discover NAT and map port
    if (nat_traversal_.discover_devices()) {
        external_ip_ = nat_traversal_.get_external_ip();
        if (!external_ip_.empty()) {
            external_port_ = socket_.local_endpoint().port();
            if (nat_traversal_.add_port_mapping(external_port_, external_port_, "P2PShare DHT UDP", "UDP")) {
                std::cout << "Successfully mapped UDP port " << external_port_ << " to external IP " << external_ip_ << std::endl;
            } else {
                std::cerr << "Failed to add UDP port mapping." << std::endl;
            }
        }
    }

    read_message();
    schedule_refresh();
}

void DhtNode::schedule_refresh() {
    refresh_timer_.expires_at(std::chrono::steady_clock::now() + std::chrono::seconds(60)); // Refresh every 60 seconds
    refresh_timer_.async_wait([this](const asio::error_code& error) {
        if (!error) {
            refresh_k_buckets();
            schedule_refresh(); // Reschedule
        } else {
            std::cerr << "DHT refresh timer error: " << error.message() << std::endl;
        }
    });
}

void DhtNode::refresh_k_buckets() {
    std::cout << "Refreshing K-buckets..." << std::endl;
    // For each k-bucket, generate a random ID and perform a FIND_NODE lookup
    // This is a simplified placeholder. A full Kademlia implementation would
    // iterate through k-buckets and generate random IDs within their ranges.
    // For now, we'll just do a FIND_NODE for our own ID to stimulate network activity.
    
    // In a real implementation, you'd iterate through each k-bucket and
    // if it hasn't been "touched" recently, generate a random ID in its range
    // and perform a lookup for that ID.
    
    // For demonstration, let's just find nodes for our own ID to keep the network alive.
    const auto& known_nodes = routing_table_.get_all_nodes();
    if (!known_nodes.empty()) {
        // Simple approach: just send FIND_NODE to the first node in the table
        // A more robust approach would involve selecting alpha closest nodes
        // to a random ID in a bucket that needs refreshing.
        send_find_node(known_nodes[0].endpoint, self_id_);
    }
}

void DhtNode::read_message() {
    read_buffer_.resize(4096); // Max UDP message size
    socket_.async_receive_from(
        asio::buffer(read_buffer_), remote_endpoint_,
        [this](const asio::error_code& error, size_t bytes_transferred) {
            if (!error) {
                read_buffer_.resize(bytes_transferred);
                handle_message(read_buffer_, remote_endpoint_);
                read_message(); // Listen for next message
            } else {
                std::cerr << "DHT read error: " << error.message() << std::endl;
            }
        });
}

void DhtNode::handle_message(const std::vector<uint8_t>& data, const asio::ip::udp::endpoint& sender) {
    if (data.empty()) return;

    MessageType type = static_cast<MessageType>(data[0]);
    std::cout << "Received DHT message of type " << (int)type << " from " << sender << std::endl;

    // All DHT messages should contain the sender's NodeID and potentially other info
    // For now, let's assume the first byte is the MessageType and the rest is payload.
    // We need to extract sender_id from the payload for most DHT messages.

    switch (type) {
        case MessageType::DHT_PING: {
            if (data.size() < sizeof(MessageType) + dht::NODE_ID_SIZE + sizeof(uint16_t)) { // Min size for PingPayload
                std::cerr << "Malformed DHT_PING message." << std::endl;
                return;
            }
            std::vector<uint8_t> payload_data(data.begin() + sizeof(MessageType), data.end());
            DhtPingPayload ping_payload = Serializer::deserialize_dht_ping_payload(payload_data);
            
            // Add sender to routing table and save to storage
            NodeInfo sender_node_info = {ping_payload.sender_id, asio::ip::udp::endpoint(sender.address(), ping_payload.sender_port)};
            routing_table_.add_node(sender_node_info);
            storage_manager_.save_peer(sender_node_info);

            // Respond with PONG
            send_pong(sender, ping_payload.sender_id);
            break;
        }
        case MessageType::DHT_PONG: {
            if (data.size() < sizeof(MessageType) + dht::NODE_ID_SIZE) { // Min size for PongPayload
                std::cerr << "Malformed DHT_PONG message." << std::endl;
                return;
            }
            std::vector<uint8_t> payload_data(data.begin() + sizeof(MessageType), data.end());
            DhtPongPayload pong_payload = Serializer::deserialize_dht_pong_payload(payload_data);

            // Add sender to routing table and save to storage
            NodeInfo sender_node_info = {pong_payload.sender_id, sender}; // Use sender's actual port for pong
            routing_table_.add_node(sender_node_info);
            storage_manager_.save_peer(sender_node_info);
            std::cout << "Received PONG from " << sender << ". Added to routing table." << std::endl;
            break;
        }
        case MessageType::DHT_FIND_NODE: {
            if (data.size() < sizeof(MessageType) + dht::NODE_ID_SIZE) {
                std::cerr << "Malformed DHT_FIND_NODE message." << std::endl;
                return;
            }
            std::vector<uint8_t> payload_data(data.begin() + sizeof(MessageType), data.end());
            DhtFindNodePayload find_node_payload = Serializer::deserialize_dht_find_node_payload(payload_data);

            std::vector<NodeInfo> closest_nodes = routing_table_.find_closest_nodes(find_node_payload.target_id);
            send_find_node_response(sender, find_node_payload.target_id, closest_nodes);
            break;
        }
        case MessageType::DHT_FIND_NODE_RESPONSE: {
            if (data.size() < sizeof(MessageType) + dht::NODE_ID_SIZE + sizeof(uint32_t)) { // Min size: MessageType + target_id + count
                std::cerr << "Malformed DHT_FIND_NODE_RESPONSE message." << std::endl;
                return;
            }
            std::vector<uint8_t> payload_data(data.begin() + sizeof(MessageType), data.end());
            auto [target_id_from_response, received_nodes] = Serializer::deserialize_dht_find_node_response_payload(payload_data);

            // Add sender to routing table
            routing_table_.add_node({target_id_from_response, sender}); // Use sender's actual endpoint

            // Process for active lookups
            if (active_lookups_.count(target_id_from_response)) {
                process_find_node_response_for_lookup(target_id_from_response, target_id_from_response, received_nodes);
            } else {
                for (const auto& node : received_nodes) {
                    routing_table_.add_node(node);
                    std::cout << "Added node " << node.endpoint << " to routing table from FIND_NODE_RESPONSE." << std::endl;
                }
            }
            break;
        }
        case MessageType::DHT_STORE: {
            if (data.size() < sizeof(MessageType) + dht::NODE_ID_SIZE + sizeof(uint32_t)) { // Min size: MessageType + key + value_len
                std::cerr << "Malformed DHT_STORE message." << std::endl;
                return;
            }
            std::vector<uint8_t> payload_data(data.begin() + sizeof(MessageType), data.end());
            auto [key, value] = Serializer::deserialize_dht_store_payload(payload_data);
            stored_values_[key] = value;
            std::cout << "Stored value for key " << key[0] << "... from " << sender << std::endl;
            break;
        }
        case MessageType::DHT_FIND_VALUE: {
            if (data.size() < sizeof(MessageType) + dht::NODE_ID_SIZE) {
                std::cerr << "Malformed DHT_FIND_VALUE message." << std::endl;
                return;
            }
            std::vector<uint8_t> payload_data(data.begin() + sizeof(MessageType), data.end());
            DhtFindValuePayload find_value_payload = Serializer::deserialize_dht_find_value_payload(payload_data);

            auto it = stored_values_.find(find_value_payload.key);
            if (it != stored_values_.end()) {
                send_find_value_response(sender, find_value_payload.key, it->second, {});
            } else {
                std::vector<NodeInfo> closest_nodes = routing_table_.find_closest_nodes(find_value_payload.key);
                send_find_value_response(sender, find_value_payload.key, std::nullopt, closest_nodes);
            }
            break;
        }
        case MessageType::DHT_FIND_VALUE_RESPONSE: {
            if (data.size() < sizeof(MessageType) + dht::NODE_ID_SIZE + sizeof(uint8_t)) { // Min size: MessageType + key + found_flag
                std::cerr << "Malformed DHT_FIND_VALUE_RESPONSE message." << std::endl;
                return;
            }
            std::vector<uint8_t> payload_data(data.begin() + sizeof(MessageType), data.end());
            auto [key_from_response, found, value, closest_nodes] = Serializer::deserialize_dht_find_value_response_payload(payload_data);

            // Add sender to routing table
            routing_table_.add_node({key_from_response, sender}); // Use sender's actual endpoint

            // Process for active lookups
            if (active_lookups_.count(key_from_response)) {
                process_find_value_response_for_lookup(key_from_response, key_from_response, value, closest_nodes);
            } else {
                if (found && value) {
                    std::cout << "Received value for key " << key_from_response[0] << "... from FIND_VALUE_RESPONSE (no active lookup)." << std::endl;
                    // Here you would typically process the received value
                } else {
                    for (const auto& node : closest_nodes) {
                        routing_table_.add_node(node);
                        std::cout << "Added node " << node.endpoint << " to routing table from FIND_VALUE_RESPONSE (no value found, no active lookup)." << std::endl;
                    }
                }
            }
            break;
        }
        default:
            std::cerr << "Unknown DHT message type." << std::endl;
            break;
    }
}

void DhtNode::bootstrap(const asio::ip::udp::endpoint& peer) {
    std::cout << "Bootstrapping from " << peer << std::endl;
    send_ping(peer);
    // After ping, send FIND_NODE for our own ID to discover more peers
    send_find_node(peer, self_id_);
}

void DhtNode::send_ping(const asio::ip::udp::endpoint& target_endpoint) {
    DhtPingPayload payload;
    payload.sender_id = self_id_;
    payload.sender_port = socket_.local_endpoint().port(); // Our listening port

    std::vector<uint8_t> message_data;
    message_data.push_back(static_cast<uint8_t>(MessageType::DHT_PING));
    std::vector<uint8_t> serialized_payload = Serializer::serialize_dht_ping_payload(payload);
    message_data.insert(message_data.end(), serialized_payload.begin(), serialized_payload.end());

    socket_.async_send_to(asio::buffer(message_data), target_endpoint,
        [this, target_endpoint](const asio::error_code& error, size_t bytes_transferred) {
            if (!error) {
                std::cout << "Sent PING to " << target_endpoint << std::endl;
            } else {
                std::cerr << "Error sending PING to " << target_endpoint << ": " << error.message() << std::endl;
            }
        });
}

void DhtNode::send_pong(const asio::ip::udp::endpoint& target_endpoint, const NodeID& recipient_id) {
    DhtPongPayload payload;
    payload.sender_id = self_id_;

    std::vector<uint8_t> message_data;
    message_data.push_back(static_cast<uint8_t>(MessageType::DHT_PONG));
    std::vector<uint8_t> serialized_payload = Serializer::serialize_dht_pong_payload(payload);
    message_data.insert(message_data.end(), serialized_payload.begin(), serialized_payload.end());

    socket_.async_send_to(asio::buffer(message_data), target_endpoint,
        [this, target_endpoint](const asio::error_code& error, size_t bytes_transferred) {
            if (!error) {
                std::cout << "Sent PONG to " << target_endpoint << std::endl;
            } else {
                std::cerr << "Error sending PONG to " << target_endpoint << ": " << error.message() << std::endl;
            }
        });
}

void DhtNode::send_find_node(const asio::ip::udp::endpoint& target_endpoint, const NodeID& target_id) {
    DhtFindNodePayload payload;
    payload.target_id = target_id;

    std::vector<uint8_t> message_data;
    message_data.push_back(static_cast<uint8_t>(MessageType::DHT_FIND_NODE));
    std::vector<uint8_t> serialized_payload = Serializer::serialize_dht_find_node_payload(payload);
    message_data.insert(message_data.end(), serialized_payload.begin(), serialized_payload.end());

    socket_.async_send_to(asio::buffer(message_data), target_endpoint,
        [this, target_endpoint, target_id](const asio::error_code& error, size_t bytes_transferred) {
            if (!error) {
                std::cout << "Sent FIND_NODE for " << target_id[0] << "... to " << target_endpoint << std::endl;
            } else {
                std::cerr << "Error sending FIND_NODE to " << target_endpoint << ": " << error.message() << std::endl;
            }
        });
}

void DhtNode::send_find_node_response(const asio::ip::udp::endpoint& target_endpoint, const NodeID& target_id, const std::vector<NodeInfo>& closest_nodes) {
    std::vector<uint8_t> message_data;
    message_data.push_back(static_cast<uint8_t>(MessageType::DHT_FIND_NODE_RESPONSE));
    std::vector<uint8_t> serialized_payload = Serializer::serialize_dht_find_node_response_payload(target_id, closest_nodes); // Pass target_id
    message_data.insert(message_data.end(), serialized_payload.begin(), serialized_payload.end());

    socket_.async_send_to(asio::buffer(message_data), target_endpoint,
        [this, target_endpoint](const asio::error_code& error, size_t bytes_transferred) {
            if (!error) {
                std::cout << "Sent FIND_NODE_RESPONSE to " << target_endpoint << std::endl;
            } else {
                std::cerr << "Error sending FIND_NODE_RESPONSE to " << target_endpoint << ": " << error.message() << std::endl;
            }
        });
}

void DhtNode::send_store(const asio::ip::udp::endpoint& target_endpoint, const NodeID& key, const std::vector<uint8_t>& value) {
    std::vector<uint8_t> message_data;
    message_data.push_back(static_cast<uint8_t>(MessageType::DHT_STORE));
    std::vector<uint8_t> serialized_payload = Serializer::serialize_dht_store_payload(key, value);
    message_data.insert(message_data.end(), serialized_payload.begin(), serialized_payload.end());

    socket_.async_send_to(asio::buffer(message_data), target_endpoint,
        [this, target_endpoint](const asio::error_code& error, size_t bytes_transferred) {
            if (!error) {
                std::cout << "Sent STORE to " << target_endpoint << std::endl;
            } else {
                std::cerr << "Error sending STORE to " << target_endpoint << ": " << error.message() << std::endl;
            }
        });
}

void DhtNode::send_find_value(const asio::ip::udp::endpoint& target_endpoint, const NodeID& key) {
    DhtFindValuePayload payload;
    payload.key = key;

    std::vector<uint8_t> message_data;
    message_data.push_back(static_cast<uint8_t>(MessageType::DHT_FIND_VALUE));
    std::vector<uint8_t> serialized_payload = Serializer::serialize_dht_find_value_payload(payload);
    message_data.insert(message_data.end(), serialized_payload.begin(), serialized_payload.end());

    socket_.async_send_to(asio::buffer(message_data), target_endpoint,
        [this, target_endpoint](const asio::error_code& error, size_t bytes_transferred) {
            if (!error) {
                std::cout << "Sent FIND_VALUE to " << target_endpoint << std::endl;
            } else {
                std::cerr << "Error sending FIND_VALUE to " << target_endpoint << ": " << error.message() << std::endl;
            }
        });
}

void DhtNode::send_find_value_response(const asio::ip::udp::endpoint& target_endpoint, const NodeID& key, const std::optional<std::vector<uint8_t>>& value, const std::vector<NodeInfo>& closest_nodes) {
    std::vector<uint8_t> message_data;
    message_data.push_back(static_cast<uint8_t>(MessageType::DHT_FIND_VALUE_RESPONSE));
    std::vector<uint8_t> serialized_payload = Serializer::serialize_dht_find_value_response_payload(key, value.has_value(), value, closest_nodes); // Pass key
    message_data.insert(message_data.end(), serialized_payload.begin(), serialized_payload.end());

    socket_.async_send_to(asio::buffer(message_data), target_endpoint,
        [this, target_endpoint](const asio::error_code& error, size_t bytes_transferred) {
            if (!error) {
                std::cout << "Sent FIND_VALUE_RESPONSE to " << target_endpoint << std::endl;
            } else {
                std::cerr << "Error sending FIND_VALUE_RESPONSE to " << target_endpoint << ": " << error.message() << std::endl;
            }
        });
}




void dht::DhtNode::start_find_node_lookup(dht::NodeID target_id, std::function<void(const std::vector<dht::NodeInfo>&)> callback) {
    std::cout << "Starting FIND_NODE lookup for target: " << target_id[0] << "..." << std::endl;
    LookupState lookup_state(target_id);
    lookup_state.on_find_node_complete = callback;

    // Initialize candidate nodes with K closest nodes from our routing table
    std::vector<NodeInfo> initial_closest = routing_table_.find_closest_nodes(target_id);
    for (const auto& node : initial_closest) {
        lookup_state.candidate_nodes.insert(node.id);
        lookup_state.all_known_nodes.emplace(node.id, node);
    }
    lookup_state.closest_nodes_found = initial_closest; // Keep track of the K closest

    active_lookups_.emplace(target_id, lookup_state);
    continue_lookup(target_id);
}

void dht::DhtNode::start_find_value_lookup(dht::NodeID key, std::function<void(const std::optional<std::vector<uint8_t>>&, const std::vector<dht::NodeInfo>&)> callback) {
    std::cout << "Starting FIND_VALUE lookup for key: " << key[0] << "..." << std::endl;
    LookupState lookup_state(key);
    lookup_state.on_find_value_complete = callback;

    // Initialize candidate nodes with K closest nodes from our routing table
    std::vector<NodeInfo> initial_closest = routing_table_.find_closest_nodes(key);
    for (const auto& node : initial_closest) {
        lookup_state.candidate_nodes.insert(node.id);
        lookup_state.all_known_nodes[node.id] = node;
    }
    lookup_state.closest_nodes_found = initial_closest; // Keep track of the K closest

    active_lookups_.emplace(key, lookup_state);
    continue_lookup(key);
}

void dht::DhtNode::continue_lookup(dht::NodeID lookup_target_id) {
    if (active_lookups_.find(lookup_target_id) == active_lookups_.end()) {
        std::cerr << "Error: continue_lookup called for non-existent lookup: " << lookup_target_id[0] << "..." << std::endl;
        return;
    }

    LookupState& state = active_lookups_[lookup_target_id];

    if (state.lookup_finished) {
        return;
    }

    // Select ALPHA unqueried nodes from candidates
    std::vector<NodeID> nodes_to_query;
    for (const auto& node_id : state.candidate_nodes) {
        if (state.queried_nodes.find(node_id) == state.queried_nodes.end()) {
            nodes_to_query.push_back(node_id);
            if (nodes_to_query.size() >= ALPHA) {
                break;
            }
        }
    }

    if (nodes_to_query.empty() && state.outstanding_rpcs == 0) {
        // No more nodes to query and no outstanding RPCs, lookup is finished
        state.lookup_finished = true;
        if (state.on_find_node_complete) {
            state.on_find_node_complete(state.closest_nodes_found);
        } else if (state.on_find_value_complete) {
            // For FIND_VALUE, if no value found, return closest nodes
            state.on_find_value_complete(std::nullopt, state.closest_nodes_found);
        }
        active_lookups_.erase(lookup_target_id);
        return;
    }

    for (const auto& node_id : nodes_to_query) {
        state.queried_nodes.insert(node_id);
        state.outstanding_rpcs++;
        NodeInfo target_node_info = state.all_known_nodes[node_id];

        // Determine if it's a FIND_NODE or FIND_VALUE lookup
        if (state.on_find_node_complete) {
            send_find_node(target_node_info.endpoint, state.target_id);
        } else if (state.on_find_value_complete) {
            send_find_value(target_node_info.endpoint, state.target_id);
        }
    }
}

void dht::DhtNode::process_find_node_response_for_lookup(dht::NodeID lookup_target_id, const dht::NodeID& sender_id, const std::vector<dht::NodeInfo>& received_nodes) {
    if (active_lookups_.find(lookup_target_id) == active_lookups_.end()) {
        // Lookup might have finished or was for a different target
        return;
    }

    LookupState& state = active_lookups_[lookup_target_id];
    state.outstanding_rpcs--;

    // Add new nodes to candidates and all_known_nodes
    for (const auto& node : received_nodes) {
        if (state.all_known_nodes.find(node.id) == state.all_known_nodes.end()) {
            state.candidate_nodes.insert(node.id);
            state.all_known_nodes.emplace(node.id, node);
        }
    }

    // Update closest_nodes_found (keep only K closest)
    std::vector<NodeInfo> current_closest = state.closest_nodes_found;
    current_closest.insert(current_closest.end(), received_nodes.begin(), received_nodes.end());
    
    // Sort and unique by NodeID, then take K closest
    std::sort(current_closest.begin(), current_closest.end(), 
              [&](const NodeInfo& a, const NodeInfo& b) {
                  return is_closer(xor_distance(a.id, state.target_id), xor_distance(b.id, state.target_id));
              });
    current_closest.erase(std::unique(current_closest.begin(), current_closest.end(), 
                                      [](const NodeInfo& a, const NodeInfo& b){ return a.id == b.id; }), 
                          current_closest.end());
    
    if (current_closest.size() > K) {
        current_closest.resize(K);
    }
    state.closest_nodes_found = current_closest;

    // Continue lookup if necessary
    continue_lookup(lookup_target_id);
}

void dht::DhtNode::process_find_value_response_for_lookup(dht::NodeID lookup_target_id, const dht::NodeID& sender_id, const std::optional<std::vector<uint8_t>>& value, const std::vector<dht::NodeInfo>& closest_nodes) {
    if (active_lookups_.find(lookup_target_id) == active_lookups_.end()) {
        return;
    }

    LookupState& state = active_lookups_[lookup_target_id];
    state.outstanding_rpcs--;

    if (value) {
        // Value found! Finish lookup.
        state.lookup_finished = true;
        if (state.on_find_value_complete) {
            state.on_find_value_complete(value, {}); // Return value, no closest nodes needed
        }
        active_lookups_.erase(lookup_target_id);
        return;
    }

    // Value not found, add closest_nodes to candidates
    for (const auto& node : closest_nodes) {
        if (state.all_known_nodes.find(node.id) == state.all_known_nodes.end()) {
            state.candidate_nodes.insert(node.id);
            state.all_known_nodes.emplace(node.id, node);
        }
    }

    // Update closest_nodes_found (keep only K closest)
    std::vector<NodeInfo> current_closest = state.closest_nodes_found;
    current_closest.insert(current_closest.end(), closest_nodes.begin(), closest_nodes.end());
    
    std::sort(current_closest.begin(), current_closest.end(), 
              [&](const NodeInfo& a, const NodeInfo& b) {
                  return is_closer(xor_distance(a.id, state.target_id), xor_distance(b.id, state.target_id));
              });
    current_closest.erase(std::unique(current_closest.begin(), current_closest.end(), 
                                      [](const NodeInfo& a, const NodeInfo& b){ return a.id == b.id; }), 
                          current_closest.end());
    
    if (current_closest.size() > K) {
        current_closest.resize(K);
    }
    state.closest_nodes_found = current_closest;

    // Continue lookup
    continue_lookup(lookup_target_id);
}

} // namespace dht
