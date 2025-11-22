#ifndef P2P_KADEMLIA_HPP
#define P2P_KADEMLIA_HPP

#include <array>
#include <vector>
#include <string>
#include <cstdint>
#include <list>
#include <asio/ip/udp.hpp>

#include "../crypto/hasher.hpp" // For hash_t

namespace dht {

constexpr size_t NODE_ID_SIZE = 32; // 256 bits, same as our hashes
using NodeID = std::array<uint8_t, NODE_ID_SIZE>;

struct NodeInfo {
    NodeID id;
    asio::ip::udp::endpoint endpoint;
    // Could add last_seen timestamp here
};

// Helper to calculate XOR distance
NodeID xor_distance(const NodeID& id1, const NodeID& id2);

// Helper to compare distances
bool is_closer(const NodeID& dist1, const NodeID& dist2);

// Kademlia constants
constexpr int K = 20; // K-bucket size
constexpr int ALPHA = 3; // Kademlia concurrency parameter

class RoutingTable {
public:
    RoutingTable(NodeID self_id);

    // Add a new node to the routing table
    void add_node(const NodeInfo& node);

    // Find the K closest nodes to a given target ID
    std::vector<NodeInfo> find_closest_nodes(const NodeID& target_id, size_t count = K);

    // Get all nodes from all k-buckets
    std::vector<NodeInfo> get_all_nodes() const;

private:
    NodeID self_id_;
    // A k-bucket is a list of nodes. We have 256 k-buckets.
    std::list<NodeInfo> k_buckets_[NODE_ID_SIZE * 8];

    // Calculate the distance (XOR metric) and return the index of the bucket
    size_t get_bucket_index(const NodeID& other_id);
};

} // namespace dht

#endif // P2P_KADEMLIA_HPP
