#include "dht/kademlia.hpp"
#include <algorithm>
#include <vector>
#include <iterator>

namespace dht {

// Helper to calculate XOR distance
NodeID xor_distance(const NodeID& id1, const NodeID& id2) {
    NodeID distance;
    for (size_t i = 0; i < NODE_ID_SIZE; ++i) {
        distance[i] = id1[i] ^ id2[i];
    }
    return distance;
}

// Helper to compare distances
bool is_closer(const NodeID& dist1, const NodeID& dist2) {
    return std::lexicographical_compare(dist1.begin(), dist1.end(), dist2.begin(), dist2.end());
}



RoutingTable::RoutingTable(NodeID self_id) : self_id_(self_id) {}

size_t RoutingTable::get_bucket_index(const NodeID& other_id) {
    NodeID distance = xor_distance(self_id_, other_id);
    for (size_t i = 0; i < NODE_ID_SIZE * 8; ++i) {
        size_t byte_index = i / 8;
        uint8_t bit_index = 7 - (i % 8);
        if ((distance[byte_index] >> bit_index) & 1) {
            return (NODE_ID_SIZE * 8 - 1) - i;
        }
    }
    return 0; // Should not happen unless IDs are identical
}

void RoutingTable::add_node(const NodeInfo& node) {
    if (node.id == self_id_) return;

    size_t bucket_idx = get_bucket_index(node.id);
    auto& bucket = k_buckets_[bucket_idx];

    // Check if node already exists
    for (auto it = bucket.begin(); it != bucket.end(); ++it) {
        if (it->id == node.id) {
            // Move to front (most recently seen)
            bucket.splice(bucket.begin(), bucket, it);
            return;
        }
    }

    if (bucket.size() < K) {
        // Add to front
        bucket.push_front(node);
    } else {
        // Bucket is full. In a full implementation, we would ping the last node
        // in the bucket to see if it's still alive. If not, we replace it.
        // For now, we just ignore the new node.
    }
}

std::vector<NodeInfo> RoutingTable::find_closest_nodes(const NodeID& target_id, size_t count) {
    std::vector<NodeInfo> all_nodes;
    for (const auto& bucket : k_buckets_) {
        all_nodes.insert(all_nodes.end(), bucket.begin(), bucket.end());
    }

    // Sort by distance to target_id
    std::sort(all_nodes.begin(), all_nodes.end(), 
        [&target_id](const NodeInfo& a, const NodeInfo& b) {
            return is_closer(xor_distance(a.id, target_id), xor_distance(b.id, target_id));
        });

    // Truncate to `count`
    if (all_nodes.size() > count) {
        all_nodes.resize(count);
    }

    return all_nodes;
}

std::vector<NodeInfo> RoutingTable::get_all_nodes() const {
    std::vector<NodeInfo> all_nodes;
    for (const auto& bucket : k_buckets_) {
        all_nodes.insert(all_nodes.end(), bucket.begin(), bucket.end());
    }
    return all_nodes;
}

} // namespace dht
