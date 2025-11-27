#include "files/download_manager.hpp"
#include "crypto/hasher.hpp"
#include "crypto/signature.hpp"
#include "common/serializer.hpp"
#include "common/logger.hpp"
#include <fstream>
#include <iostream>
#include <vector>
#include <algorithm>
#include <map>
#include <sstream>
#include <iomanip>

// Helper for serializing/deserializing manifest
namespace Serializer {
    std::vector<uint8_t> serialize_manifest(const Manifest& m);
    Manifest deserialize_manifest(const std::vector<uint8_t>& buffer);
}

DownloadManager::DownloadManager(hash_t root_hash, StorageManager& storage_manager)
    : state_(ManagerState::IDLE), root_hash_(root_hash), storage_manager_(storage_manager) {
    
    std::string hex_hash_str = Hasher::hash_to_hex(root_hash_);
    temp_file_path_ = fs::temp_directory_path() / (hex_hash_str + ".tmp");
    final_file_path_ = fs::current_path() / hex_hash_str; 

    LOG_INFO("DownloadManager created for hash: ", hex_hash_str);
    load_download_state(); 
}

void DownloadManager::load_download_state() {
    auto dm_state = storage_manager_.get_download_state(root_hash_);
    if (!std::get<0>(dm_state).empty()) {
        final_file_path_ = std::get<0>(dm_state);
        LOG_INFO("Loaded download state for ", Hasher::hash_to_hex(root_hash_), " from storage.");
        manifest_ = storage_manager_.get_manifest(root_hash_);
        if (manifest_) {
            piece_states_.assign(manifest_->pieces_count, PieceState::Needed); 
            piece_availability_.assign(manifest_->pieces_count, 0);
            LOG_INFO("Manifest loaded from storage.");
            state_ = ManagerState::DOWNLOADING; 
        }
    }
}

void DownloadManager::save_download_state() {
    if (manifest_) {
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
    LOG_INFO("Peer ", peer_conn->socket().remote_endpoint(), " added to download.");
    
    if (manifest_ && state_ == ManagerState::DOWNLOADING) {
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
        LOG_WARN("Cannot start download, no peers available.");
        return;
    }
    if (state_ != ManagerState::IDLE && state_ != ManagerState::REQUESTING_MANIFEST) return;

    if (!manifest_) {
        LOG_INFO("Starting download by requesting manifest...");
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
    // Check if peer is banned (should be removed from set, but double check)
    if (peers_.find(peer_conn) == peers_.end()) return;

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
    if (manifest_ && state_ == ManagerState::DOWNLOADING) {
        return;
    }

    if (state_ != ManagerState::REQUESTING_MANIFEST) return;

    bool found = msg.payload[0];
    if (!found) {
        LOG_WARN("File not found on peer ", peer_conn->socket().remote_endpoint());
        state_ = ManagerState::FAILED;
        return;
    }

    std::vector<uint8_t> manifest_data(msg.payload.begin() + 1, msg.payload.end());
    manifest_ = Serializer::deserialize_manifest(manifest_data);
    
    // Verify Signature if present
    if (!manifest_->signer_pubkey.empty() && !manifest_->signature.empty()) {
        std::vector<uint8_t> root_hash_vec(manifest_->root_hash.begin(), manifest_->root_hash.end());
        if (Signature::verify(root_hash_vec, manifest_->signature, manifest_->signer_pubkey)) {
            LOG_INFO("Manifest Signature Verified! Trusted source.");
        } else {
            LOG_ERR("WARNING: Manifest Signature Verification FAILED!");
        }
    } else {
        LOG_INFO("Manifest is unsigned.");
    }

    LOG_INFO("Received manifest for: ", manifest_->file_name);
    final_file_path_ = manifest_->file_name;

    std::ofstream(temp_file_path_, std::ios::binary).close();
    fs::resize_file(temp_file_path_, manifest_->file_size);

    piece_states_.assign(manifest_->pieces_count, PieceState::Needed);
    piece_availability_.assign(manifest_->pieces_count, 0);
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

    LOG_INFO("Received bitfield from peer ", peer_conn->socket().remote_endpoint());

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

    auto peer_bitfield_opt = peer_conn->get_peer_bitfield(root_hash_);
    if (peer_bitfield_opt) {
        Bitfield peer_bitfield = *peer_bitfield_opt;
        if (!peer_bitfield.has_piece(payload.piece_index)) {
            peer_bitfield.set_piece(payload.piece_index);
            peer_conn->set_peer_bitfield(root_hash_, peer_bitfield);

            if (payload.piece_index < piece_availability_.size()) {
                piece_availability_[payload.piece_index]++;
                LOG_DEBUG("Peer ", peer_conn->socket().remote_endpoint(), 
                          " now has piece ", payload.piece_index, ". Rarity: ", 
                          piece_availability_[payload.piece_index]);
            }
        }
    }

    schedule_work();
}

void DownloadManager::schedule_work() {
    if (state_ != ManagerState::DOWNLOADING) return;

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

    std::vector<std::pair<uint32_t, uint32_t>> rarest_pieces;
    for (uint32_t i = 0; i < manifest_->pieces_count; ++i) {
        if (piece_states_[i] == PieceState::Needed) {
            rarest_pieces.push_back({i, piece_availability_[i]});
        }
    }

    std::sort(rarest_pieces.begin(), rarest_pieces.end(), 
              [](const auto& a, const auto& b) { return a.second < b.second; });

    // --- END GAME MODE LOGIC START ---
    // If remaining needed pieces is small (e.g., < 5) and we have multiple peers,
    // allow duplicate requests for the same piece.
    // Simple check: if rarest_pieces.size() is small.
    bool end_game = (rarest_pieces.size() > 0 && rarest_pieces.size() < 5 && peers_.size() > 1);
    // ---------------------------------

    for (const auto& peer : peers_) {
        if (peer->is_peer_choking()) continue; // Skip choked peers

        auto peer_bitfield_opt = peer->get_peer_bitfield(root_hash_);
        if (!peer_bitfield_opt) continue;

        Bitfield peer_bitfield = *peer_bitfield_opt;

        while (in_flight_requests_[peer].size() < REQUEST_WINDOW_SIZE) {
            bool requested_a_piece = false;
            for (const auto& piece_info : rarest_pieces) {
                uint32_t piece_index = piece_info.first;

                bool already_requested = (piece_states_[piece_index] == PieceState::Requested);
                
                // In normal mode, skip if already requested.
                // In end-game mode, skip only if THIS peer already requested it.
                bool request_allowed = !already_requested;
                
                if (end_game && already_requested) {
                    // Check if THIS peer already requested it
                    if (in_flight_requests_[peer].count(piece_index) == 0) {
                        request_allowed = true;
                    }
                }

                if (request_allowed && peer_bitfield.has_piece(piece_index)) {
                    request_piece_from_peer(piece_index, peer);
                    requested_a_piece = true;
                    break; 
                }
            }
            if (!requested_a_piece) break;
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

    LOG_DEBUG("Requesting piece ", piece_index, " from ", peer_conn->socket().remote_endpoint());
    peer_conn->send_message(msg);
}

void DownloadManager::handle_piece_response(const Message& msg, std::shared_ptr<Connection> peer_conn) {
    if (state_ != ManagerState::DOWNLOADING) return;

    uint32_t piece_index;
    std::memcpy(&piece_index, msg.payload.data() + HASH_SIZE, sizeof(uint32_t));

    in_flight_requests_[peer_conn].erase(piece_index);

    // In end-game mode, we might receive a piece we already have.
    if (piece_states_[piece_index] == PieceState::Have) {
        LOG_DEBUG("Received piece ", piece_index, " which we already have. Ignoring.");
        return;
    }

    std::vector<uint8_t> piece_data(msg.payload.begin() + HASH_SIZE + sizeof(uint32_t), msg.payload.end());

    if (verify_and_write_piece(piece_index, piece_data)) {
        piece_states_[piece_index] = PieceState::Have;
        LOG_INFO("Piece ", piece_index, " downloaded and verified.");
        save_download_state();
        
        for (const auto& peer : peers_) {
            if (peer != peer_conn) { 
                peer->send_have(root_hash_, piece_index);
            }
        }
        schedule_work();
    } else {
        LOG_ERR("Piece ", piece_index, " failed verification from peer ", peer_conn->socket().remote_endpoint());
        piece_states_[piece_index] = PieceState::Needed; 
        
        // --- STRIKE SYSTEM ---
        peer_strikes_[peer_conn]++;
        if (peer_strikes_[peer_conn] >= MAX_STRIKES) {
            ban_peer(peer_conn);
        } else {
            schedule_work();
        }
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
    save_download_state(); 
    LOG_INFO("Download complete! Assembling file.");
    
    std::error_code ec;
    fs::rename(temp_file_path_, final_file_path_, ec);

    if (ec) {
        LOG_ERR("Failed to rename file: ", ec.message(), ". Attempting copy and delete.");
        try {
            fs::copy(temp_file_path_, final_file_path_, fs::copy_options::overwrite_existing);
            fs::remove(temp_file_path_);
            LOG_INFO("File copied and temporary file deleted.");
        } catch (const fs::filesystem_error& e) {
            LOG_ERR("Error during copy/delete fallback: ", e.what());
            state_ = ManagerState::FAILED;
            return;
        }
    }
    LOG_INFO("File saved as: ", final_file_path_);
}

void DownloadManager::ban_peer(std::shared_ptr<Connection> peer_conn) {
    LOG_WARN("Banning peer ", peer_conn->socket().remote_endpoint(), " due to repeated bad pieces.");
    peers_.erase(peer_conn);
    in_flight_requests_.erase(peer_conn);
    peer_strikes_.erase(peer_conn);
    
    // Ideally we should disconnect, but Connection manages its own lifecycle mostly.
    // We can force close the socket.
    try {
        if(peer_conn->socket().is_open()) {
            peer_conn->socket().close();
        }
    } catch(...) {}
    
    schedule_work();
}
