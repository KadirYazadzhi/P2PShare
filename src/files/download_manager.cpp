#include "files/download_manager.hpp"
#include "crypto/hasher.hpp"
#include "crypto/signature.hpp" // Added for Signature verification
#include "common/serializer.hpp"
#include <fstream>
#include <iostream>
#include <vector>
#include <algorithm>
#include <map>
#include <sstream>
#include <iomanip>

// Helper for serializing/deserializing manifest (should be in a common place)
namespace Serializer {
    std::vector<uint8_t> serialize_manifest(const Manifest& m);
    Manifest deserialize_manifest(const std::vector<uint8_t>& buffer);
}

DownloadManager::DownloadManager(hash_t root_hash, StorageManager& storage_manager)
    : state_(ManagerState::IDLE), root_hash_(root_hash), storage_manager_(storage_manager) { // Initialize storage_manager_ and root_hash_
    
    std::string hex_hash_str = Hasher::hash_to_hex(root_hash_);
    temp_file_path_ = fs::temp_directory_path() / (hex_hash_str + ".tmp");
    final_file_path_ = fs::current_path() / hex_hash_str; // Default final path

    std::cout << "DownloadManager created for hash: " << hex_hash_str << std::endl;
    load_download_state(); // Load existing state from storage
}

void DownloadManager::load_download_state() {
    auto dm_state = storage_manager_.get_download_state(root_hash_);
    if (!std::get<0>(dm_state).empty()) {
        final_file_path_ = std::get<0>(dm_state);
        // progress = std::get<1>(dm_state); // Currently, progress is just a piece_states_ count.
                                            // Need to enhance storage to save piece_states_ as BLOB.
                                            // For now, it will restart from scratch, but manifest is loaded.
        std::cout << "Loaded download state for " << Hasher::hash_to_hex(root_hash_) << " from storage." << std::endl;
        // Also load manifest if available
        manifest_ = storage_manager_.get_manifest(root_hash_);
        if (manifest_) {
            piece_states_.assign(manifest_->pieces_count, PieceState::Needed); // Reset pieces states for now
            piece_availability_.assign(manifest_->pieces_count, 0);
            std::cout << "Manifest loaded from storage." << std::endl;
            state_ = ManagerState::DOWNLOADING; // Ready to continue download
        }
    }
}

void DownloadManager::save_download_state() {
    if (manifest_) {
        // Here, 'progress' is simplified to piece_states_ size,
        // but should ideally be the number of 'Have' pieces.
        uint32_t progress = 0;
        for(PieceState ps : piece_states_) {
            if (ps == PieceState::Have) {
                progress++;
            }
        }
        storage_manager_.save_download_state(root_hash_, final_file_path_.string(), progress);
    }
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
    if (state_ != ManagerState::IDLE && state_ != ManagerState::REQUESTING_MANIFEST) return;

    if (!manifest_) {
        std::cout << "Starting download by requesting manifest..." << std::endl;
        state_ = ManagerState::REQUESTING_MANIFEST;
        
        auto first_peer = *peers_.begin();
        QuerySearchPayload payload;
        payload.root_hash = root_hash_;

        Message msg;
        msg.type = MessageType::QUERY_SEARCH;
        msg.payload.resize(sizeof(payload));
        std::memcpy(msg.payload.data(), &payload, sizeof(payload));

        first_peer->send_message(msg);
    } else {
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
        case MessageType::HAVE:
            handle_have_response(msg, peer_conn);
            break;
        default:
            break;
    }
}

void DownloadManager::handle_search_response(const Message& msg, std::shared_ptr<Connection> peer_conn) {
    // If we already have the manifest, this is a response to a bitfield request for a new peer
    if (manifest_ && state_ == ManagerState::DOWNLOADING) {
        // The server sends BITFIELD right after SEARCH_RESPONSE, so this SEARCH_RESPONSE
        // for an already known manifest is effectively just a confirmation.
        // The BITFIELD will be handled by handle_bitfield_response.
        return;
    }

    if (state_ != ManagerState::REQUESTING_MANIFEST) return;

    bool found = msg.payload[0];
    if (!found) {
        std::cerr << "File not found on peer " << peer_conn->socket().remote_endpoint() << std::endl;
        state_ = ManagerState::FAILED;
        return;
    }

    std::vector<uint8_t> manifest_data(msg.payload.begin() + 1, msg.payload.end());
    manifest_ = Serializer::deserialize_manifest(manifest_data);
    
    // Verify Signature if present
    if (!manifest_->signer_pubkey.empty() && !manifest_->signature.empty()) {
        std::vector<uint8_t> root_hash_vec(manifest_->root_hash.begin(), manifest_->root_hash.end());
        if (Signature::verify(root_hash_vec, manifest_->signature, manifest_->signer_pubkey)) {
            std::cout << "Manifest Signature Verified! Trusted source." << std::endl;
        } else {
            std::cerr << "WARNING: Manifest Signature Verification FAILED!" << std::endl;
            // Policy: fail download? Or just warn? For safety, let's warn but proceed for now (or fail).
            // state_ = ManagerState::FAILED;
            // return;
        }
    } else {
        std::cout << "Manifest is unsigned." << std::endl;
    }

    std::cout << "Received manifest for: " << manifest_->file_name << std::endl;
    final_file_path_ = manifest_->file_name;

    std::ofstream(temp_file_path_, std::ios::binary).close();
    fs::resize_file(temp_file_path_, manifest_->file_size);

    piece_states_.assign(manifest_->pieces_count, PieceState::Needed);
    piece_availability_.assign(manifest_->pieces_count, 0); // Initialize piece rarity counts
    state_ = ManagerState::DOWNLOADING;
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

    // Update global piece availability
    for (uint32_t i = 0; i < manifest_->pieces_count; ++i) {
        if (bf.has_piece(i)) {
            piece_availability_[i]++;
        }
    }

    schedule_work();
}

void DownloadManager::handle_have_response(const Message& msg, std::shared_ptr<Connection> peer_conn) {
    if (!manifest_) return;

    HavePayload payload;
    if (msg.payload.size() != sizeof(HavePayload)) return;
    std::memcpy(&payload, msg.payload.data(), sizeof(HavePayload));

    if (payload.root_hash != root_hash_) return;

    // Update the peer's bitfield
    auto peer_bitfield_opt = peer_conn->get_peer_bitfield(root_hash_);
    if (peer_bitfield_opt) {
        Bitfield peer_bitfield = *peer_bitfield_opt;
        if (!peer_bitfield.has_piece(payload.piece_index)) {
            peer_bitfield.set_piece(payload.piece_index);
            peer_conn->set_peer_bitfield(root_hash_, peer_bitfield);

            // Update global piece availability
            if (payload.piece_index < piece_availability_.size()) {
                piece_availability_[payload.piece_index]++;
                std::cout << "Peer " << peer_conn->socket().remote_endpoint() 
                          << " now has piece " << payload.piece_index << ". Rarity is now " 
                          << piece_availability_[payload.piece_index] << std::endl;
            }
        }
    }

    // We might be able to request this piece now
    schedule_work();
}

void DownloadManager::schedule_work() {
    if (state_ != ManagerState::DOWNLOADING) return;

    // Check if download is complete
    bool all_done = true;
    for(PieceState ps : piece_states_) {
        if (ps != PieceState::Have) {
            all_done = false;
            break;
        }
    }
    if (all_done) {
        finalize_download();
        return;
    }

    // Collect needed pieces and sort by rarity
    std::vector<std::pair<uint32_t, uint32_t>> rarest_pieces; // {piece_index, rarity_count}
    for (uint32_t i = 0; i < manifest_->pieces_count; ++i) {
        if (piece_states_[i] == PieceState::Needed) {
            rarest_pieces.push_back({i, piece_availability_[i]});
        }
    }

    // Sort by rarity (ascending)
    std::sort(rarest_pieces.begin(), rarest_pieces.end(), 
              [](const auto& a, const auto& b) { return a.second < b.second; });

    // Try to fill request windows for all peers
    for (const auto& peer : peers_) {
        // Check if peer is still connected and has a bitfield
        auto peer_bitfield_opt = peer->get_peer_bitfield(root_hash_);
        if (!peer_bitfield_opt) continue; // Peer not ready or no bitfield yet

        Bitfield peer_bitfield = *peer_bitfield_opt;

        // Fill peer's request window
        while (in_flight_requests_[peer].size() < REQUEST_WINDOW_SIZE) {
            bool requested_a_piece = false;
            for (const auto& piece_info : rarest_pieces) {
                uint32_t piece_index = piece_info.first;

                if (piece_states_[piece_index] == PieceState::Needed && peer_bitfield.has_piece(piece_index)) {
                    request_piece_from_peer(piece_index, peer);
                    requested_a_piece = true;
                    break; // Move to next peer or next slot in window
                }
            }
            if (!requested_a_piece) break; // No more pieces to request from this peer
        }
    }
}

void DownloadManager::request_piece_from_peer(uint32_t piece_index, std::shared_ptr<Connection> peer_conn) {
    piece_states_[piece_index] = PieceState::Requested;
    in_flight_requests_[peer_conn].insert(piece_index);

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

    // Remove from in-flight requests
    in_flight_requests_[peer_conn].erase(piece_index);

    if (piece_states_[piece_index] != PieceState::Requested) {
        std::cout << "Received unexpected piece " << piece_index << " (not requested or already have)." << std::endl;
        return;
    }

    std::vector<uint8_t> piece_data(msg.payload.begin() + HASH_SIZE + sizeof(uint32_t), msg.payload.end());

    if (verify_and_write_piece(piece_index, piece_data)) {
        piece_states_[piece_index] = PieceState::Have;
        std::cout << "Piece " << piece_index << " downloaded and verified." << std::endl;
        save_download_state(); // Save state after successful piece download
        
        // Notify all peers that we now have this piece
        for (const auto& peer : peers_) {
            if (peer != peer_conn) { // Don't notify the peer we got it from
                peer->send_have(root_hash_, piece_index);
            }
        }

        schedule_work();
    } else {
        std::cerr << "Piece " << piece_index << " failed verification." << std::endl;
        piece_states_[piece_index] = PieceState::Needed; // Mark as needed again
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
    save_download_state(); // Save state after download completion
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
