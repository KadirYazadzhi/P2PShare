#ifndef P2P_DHT_NODE_HPP
#define P2P_DHT_NODE_HPP

#include <asio.hpp>
#include "kademlia.hpp"
#include <map>
#include <set>
#include <functional>
#include <optional>

#include "network/nat_traversal.hpp" // Added for NAT traversal
#include "../storage/storage_manager.hpp" // Added for StorageManager

namespace dht {

// Helper to generate a random NodeID
NodeID generate_random_id();

// Forward declaration
class DhtNode;

struct LookupState {
    NodeID target_id;
    std::vector<NodeInfo> closest_nodes_found; // k closest nodes found so far
    std::set<NodeID> queried_nodes; // Nodes that have been queried
    std::set<NodeID> candidate_nodes; // Nodes to query next
    std::map<NodeID, NodeInfo> all_known_nodes; // All nodes encountered during lookup

    // Callback for when the lookup is complete
    std::function<void(const std::vector<NodeInfo>&)> on_find_node_complete;
    std::function<void(const std::optional<std::vector<uint8_t>>&, const std::vector<NodeInfo>&)> on_find_value_complete;

    // To track outstanding RPCs
    int outstanding_rpcs = 0;
    bool lookup_finished = false;

    LookupState() = default; // Default constructor
    LookupState(NodeID target) : target_id(target) {}
};

class DhtNode {
public:
    DhtNode(asio::io_context& io_context, uint16_t port, StorageManager& storage_manager); // Modified constructor
    ~DhtNode(); // Added destructor

    void start();

    NodeID get_self_id() const { return self_id_; }

    // DHT RPCs
    void send_ping(const asio::ip::udp::endpoint& target_endpoint);
    void send_pong(const asio::ip::udp::endpoint& target_endpoint, const NodeID& recipient_id);
    void send_find_node(const asio::ip::udp::endpoint& target_endpoint, const NodeID& target_id);
    void send_find_node_response(const asio::ip::udp::endpoint& target_endpoint, const NodeID& target_id, const std::vector<NodeInfo>& closest_nodes);
    void send_store(const asio::ip::udp::endpoint& target_endpoint, const NodeID& key, const std::vector<uint8_t>& value);
    void send_find_value(const asio::ip::udp::endpoint& target_endpoint, const NodeID& key);
    void send_find_value_response(const asio::ip::udp::endpoint& target_endpoint, const NodeID& key, const std::optional<std::vector<uint8_t>>& value, const std::vector<NodeInfo>& closest_nodes);

    void bootstrap(const asio::ip::udp::endpoint& peer);

    // Kademlia Lookup methods
    void start_find_node_lookup(NodeID target_id, std::function<void(const std::vector<NodeInfo>&)> callback);
    void start_find_value_lookup(NodeID key, std::function<void(const std::optional<std::vector<uint8_t>>&, const std::vector<NodeInfo>&)> callback);

    // Hole-punching RPCs
    void send_hole_punch_request(const asio::ip::udp::endpoint& target_endpoint, const asio::ip::udp::endpoint& sender_external_endpoint);
    void send_hole_punch_response(const asio::ip::udp::endpoint& target_endpoint, const asio::ip::udp::endpoint& sender_external_endpoint);

    // Callbacks for Server integration
    void set_on_hole_punch_request(std::function<void(const asio::ip::udp::endpoint&)> callback) {
        on_hole_punch_request_ = callback;
    }

    // Public accessors for testing
    std::map<NodeID, std::vector<uint8_t>>& get_stored_values() { return stored_values_; }
    asio::io_context& get_io_context() { return io_context_; }
    std::string get_external_ip() const { return external_ip_; }
    uint16_t get_external_port() const { return external_port_; }

private:
    void read_message();
    void handle_message(const std::vector<uint8_t>& data, const asio::ip::udp::endpoint& sender);

    asio::io_context& io_context_;
    asio::ip::udp::socket socket_;
    NodeID self_id_;
    RoutingTable routing_table_;
    std::vector<uint8_t> read_buffer_;
    asio::ip::udp::endpoint remote_endpoint_;
    asio::steady_timer refresh_timer_;

    std::map<NodeID, std::vector<uint8_t>> stored_values_;
    std::map<NodeID, LookupState> active_lookups_; // Map from target_id to active lookup state

    NatTraversal nat_traversal_; // Added NatTraversal member
    std::string external_ip_;    // Store external IP
    uint16_t external_port_;     // Store external port
    StorageManager& storage_manager_; // Added StorageManager reference
    
    std::function<void(const asio::ip::udp::endpoint&)> on_hole_punch_request_;

    void schedule_refresh();
    void refresh_k_buckets();

    // Helper for Kademlia lookup
    void continue_lookup(NodeID lookup_target_id);
    void process_find_node_response_for_lookup(NodeID lookup_target_id, const NodeID& sender_id, const std::vector<NodeInfo>& received_nodes);
    void process_find_value_response_for_lookup(NodeID lookup_target_id, const NodeID& sender_id, const std::optional<std::vector<uint8_t>>& value, const std::vector<NodeInfo>& closest_nodes);
};

} // namespace dht

#endif // P2P_DHT_NODE_HPP
