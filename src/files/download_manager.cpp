#include "files/download_manager.hpp"
#include "crypto/hasher.hpp"
#include "common/serializer.hpp"
#include <fstream>
#include <iostream>
#include <vector>
#include <algorithm>

// Helper for serializing/deserializing manifest (should be in a common place)
namespace Serializer {
    std::vector<uint8_t> serialize_manifest(const Manifest& m);
    Manifest deserialize_manifest(const std::vector<uint8_t>& buffer);
}

DownloadManager::DownloadManager(hash_t root_hash)
    : state_(ManagerState::IDLE), root_hash_(root_hash) {
    
    std::string hex_hash;
    for(uint8_t byte : root_hash) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", byte);
        hex_hash += buf;
    }
    temp_file_path_ = fs::temp_directory_path() / (hex_hash + ".tmp");
    std::cout << "DownloadManager created for hash: " << hex_hash << std::endl;
}

void DownloadManager::add_peer(std::shared_ptr<Connection> peer_conn) {
    peers_.insert(peer_conn);
    std::cout << "Peer " << peer_conn->socket().remote_endpoint() << " added to download." << std::endl;
    
    // If we already have the manifest, request bitfield from new peer
    if (manifest_ && state_ == ManagerState::DOWNLOADING) {
        // Send QUERY_SEARCH to get bitfield from new peer
        QuerySearchPayload payload;
        payload.root_hash = root_hash_;

        Message msg;
        msg.type = MessageType::QUERY_SEARCH;
        msg.payload.resize(sizeof(payload));
        std::memcpy(msg.payload.data(), &payload, sizeof(payload));

        peer_conn->send_message(msg);
    }
}

void DownloadManager::start() {
    if (peers_.empty()) {
        std::cerr << "Cannot start download, no peers available." << std::endl;
        return;
    }
    if (state_ != ManagerState::IDLE && state_ != ManagerState::REQUESTING_MANIFEST) return; // Already started or requesting

    if (!manifest_) { // Only request manifest if we don't have it yet
        std::cout << "Starting download by requesting manifest..." << std::endl;
        state_ = ManagerState::REQUESTING_MANIFEST;
        
        // Request manifest from the first peer
        auto first_peer = *peers_.begin();
        QuerySearchPayload payload;
        payload.root_hash = root_hash_;

        Message msg;
        msg.type = MessageType::QUERY_SEARCH;
        msg.payload.resize(sizeof(payload));
        std::memcpy(msg.payload.data(), &payload, sizeof(payload));

        first_peer->send_message(msg);
    } else {
        // If manifest is already available, just schedule work (e.g., if a new peer was added)
        state_ = ManagerState::DOWNLOADING;
        schedule_work();
    }
}

void DownloadManager::handle_message(const Message& msg, std::shared_ptr<Connection> peer_conn) {
    switch (msg.type) {
        case MessageType::SEARCH_RESPONSE:
            handle_search_response(msg, peer_conn);
            break;
        case MessageType::PIECE:
            handle_piece_response(msg, peer_conn);
            break;
        case MessageType::BITFIELD:
            handle_bitfield_response(msg, peer_conn);
            break;
        default:
            break;
    }
}

void DownloadManager::handle_search_response(const Message& msg, std::shared_ptr<Connection> peer_conn) {
    // If we already have the manifest, this is a response to a bitfield request for a new peer
    if (manifest_ && state_ == ManagerState::DOWNLOADING) {
        // Just process the bitfield part if it's a SEARCH_RESPONSE for a new peer
        // This is a bit of a hack, ideally the protocol would have a separate message for requesting bitfield
        if (msg.payload[0]) { // If found
            std::vector<uint8_t> manifest_data(msg.payload.begin() + 1, msg.payload.end());
            Manifest received_manifest = Serializer::deserialize_manifest(manifest_data);
            // We don't need to store the manifest again, but we can use its piece_count
            // to initialize the bitfield for this peer.
            
            // Now, request the bitfield from this peer (which should be sent automatically by server)
            // Or, if the server sends bitfield immediately after search response, it will be handled by handle_bitfield_response
        }
        return;
    }

    if (state_ != ManagerState::REQUESTING_MANIFEST) return;

    bool found = msg.payload[0];
    if (!found) {
        std::cerr << "File not found on peer " << peer_conn->socket().remote_endpoint() << std::endl;
        state_ = ManagerState::FAILED; // Or try next peer
        return;
    }

    std::vector<uint8_t> manifest_data(msg.payload.begin() + 1, msg.payload.end());
    manifest_ = Serializer::deserialize_manifest(manifest_data);
    
    std::cout << "Received manifest for: " << manifest_->file_name << std::endl;
    final_file_path_ = manifest_->file_name;

    std::ofstream(temp_file_path_, std::ios::binary).close();
    fs::resize_file(temp_file_path_, manifest_->file_size);

    piece_states_.assign(manifest_->pieces_count, PieceState::Needed);
    state_ = ManagerState::DOWNLOADING;
    // Wait for BITFIELD message which should follow this one.
}

void DownloadManager::handle_bitfield_response(const Message& msg, std::shared_ptr<Connection> peer_conn) {
    if (!manifest_) return;

    hash_t root_hash;
    std::memcpy(root_hash.data(), msg.payload.data(), HASH_SIZE);
    if (root_hash != root_hash_) return;

    std::vector<uint8_t> field_bytes(msg.payload.begin() + HASH_SIZE, msg.payload.end());
    Bitfield bf(manifest_->pieces_count, field_bytes);
    peer_conn->set_peer_bitfield(root_hash, bf);

    std::cout << "Received bitfield from peer " << peer_conn->socket().remote_endpoint() << std::endl;

    schedule_work();
}

void DownloadManager::schedule_work() {
    if (state_ != ManagerState::DOWNLOADING) return;

    // Simple sequential scheduler
    for (uint32_t i = 0; i < manifest_->pieces_count; ++i) {
        if (piece_states_[i] == PieceState::Needed) {
            for (const auto& peer : peers_) {
                auto bitfield = peer->get_peer_bitfield(root_hash_);
                if (bitfield && bitfield->has_piece(i)) {
                    request_piece_from_peer(i, peer);
                    return; 
                }
            }
        }
    }

    auto it = std::find(piece_states_.begin(), piece_states_.end(), PieceState::Needed);
    auto it2 = std::find(piece_states_.begin(), piece_states_.end(), PieceState::Requested);
    if (it == piece_states_.end() && it2 == piece_states_.end()) {
        finalize_download();
    }
}

void DownloadManager::request_piece_from_peer(uint32_t piece_index, std::shared_ptr<Connection> peer_conn) {
    piece_states_[piece_index] = PieceState::Requested;

    RequestPiecePayload payload;
    payload.root_hash = root_hash_;
    payload.piece_index = piece_index;

    Message msg;
    msg.type = MessageType::REQUEST_PIECE;
    msg.payload.resize(sizeof(payload));
    std::memcpy(msg.payload.data(), &payload, sizeof(payload));

    std::cout << "Requesting piece " << piece_index << " from " << peer_conn->socket().remote_endpoint() << std::endl;
    peer_conn->send_message(msg);
}

void DownloadManager::handle_piece_response(const Message& msg, std::shared_ptr<Connection> peer_conn) {
    if (state_ != ManagerState::DOWNLOADING) return;

    uint32_t piece_index;
    std::memcpy(&piece_index, msg.payload.data() + HASH_SIZE, sizeof(uint32_t));

    if (piece_states_[piece_index] != PieceState::Requested) {
        return;
    }

    std::vector<uint8_t> piece_data(msg.payload.begin() + HASH_SIZE + sizeof(uint32_t), msg.payload.end());

    if (verify_and_write_piece(piece_index, piece_data)) {
        piece_states_[piece_index] = PieceState::Have;
        std::cout << "Piece " << piece_index << " downloaded and verified." << std::endl;
        
        schedule_work();
    } else {
        std::cerr << "Piece " << piece_index << " failed verification." << std::endl;
        piece_states_[piece_index] = PieceState::Needed;
        schedule_work();
    }
}

bool DownloadManager::verify_and_write_piece(uint32_t piece_index, const std::vector<uint8_t>& data) {
    if (!manifest_ || piece_index >= manifest_->pieces_count) return false;
    hash_t received_hash = Hasher::sha256(data);
    if (received_hash != manifest_->piece_hashes[piece_index]) return false;

    std::fstream temp_file(temp_file_path_, std::ios::binary | std::ios::in | std::ios::out);
    if (!temp_file.is_open()) return false;

    uint64_t offset = static_cast<uint64_t>(piece_index) * manifest_->piece_size;
    temp_file.seekp(offset);
    temp_file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return true;
}

void DownloadManager::finalize_download() {
    if (state_ == ManagerState::COMPLETED) return;
    state_ = ManagerState::COMPLETED;
    std::cout << "Download complete! Assembling file." << std::endl;
    
    std::error_code ec;
    fs::rename(temp_file_path_, final_file_path_, ec);

    if (ec) {
        std::cerr << "Failed to rename file: " << ec.message() << ". Attempting copy and delete." << std::endl;
        try {
            fs::copy(temp_file_path_, final_file_path_, fs::copy_options::overwrite_existing);
            fs::remove(temp_file_path_);
            std::cout << "File copied and temporary file deleted." << std::endl;
        } catch (const fs::filesystem_error& e) {
            std::cerr << "Error during copy/delete fallback: " << e.what() << std::endl;
            state_ = ManagerState::FAILED;
            return;
        }
    }
    std::cout << "File saved as: " << final_file_path_ << std::endl;
}