#ifndef P2P_CONNECTION_HPP
#define P2P_CONNECTION_HPP

#include <asio.hpp>
#include <asio/ts/buffer.hpp>
#include <asio/ts/internet.hpp>
#include <asio/ssl.hpp> // Added for SSL
#include <deque>
#include <memory>
#include <iostream>
#include <functional>
#include <map>
#include <optional> // <--- Added this include

#include "protocol.hpp"
#include "../files/bitfield.hpp"
#include "../common/serializer.hpp" // Include serializer for send_have
#include "../common/rate_limiter.hpp" // Include rate_limiter.hpp

// Forward declaration for the Connection class
class Connection;

// Define a message structure for easier handling
struct Message {
    MessageType type;
    std::vector<uint8_t> payload;
};

class Connection : public std::enable_shared_from_this<Connection> {
public:
    using ssl_socket = asio::ssl::stream<asio::ip::tcp::socket>; // Changed from tcp_socket
    using message_handler = std::function<void(Message)>;

    Connection(asio::io_context& io_context, asio::ssl::context& ssl_context, 
               std::shared_ptr<RateLimiter> upload_limiter, 
               std::shared_ptr<RateLimiter> download_limiter)
        : io_context_(io_context), socket_(io_context, ssl_context),
          upload_rate_limiter_(upload_limiter), 
          download_rate_limiter_(download_limiter),
          am_choking_(true), // Default choked
          peer_choking_(true),
          download_speed_(0.0),
          last_speed_update_(std::chrono::steady_clock::now()) {} 

    void set_message_handler(message_handler handler) {
        message_handler_ = std::move(handler);
    }

    virtual ssl_socket::lowest_layer_type& socket() { 
        return socket_.lowest_layer();
    }
    virtual asio::ip::tcp::endpoint get_remote_endpoint() const {
        return socket_.lowest_layer().remote_endpoint();
    }

    asio::io_context& get_io_context() { // Public accessor for io_context_
        return io_context_;
    }

    void start(asio::ssl::stream_base::handshake_type type, std::function<void()> on_success = nullptr) { // Added handshake_type parameter and callback
        socket_.async_handshake(type,
            [self = shared_from_this(), on_success](const asio::error_code& error) {
                if (!error) {
                    std::cout << "SSL Handshake successful!" << std::endl;
                    if (on_success) {
                        on_success();
                    }
                    self->read_header(); // Start reading application data
                } else {
                    std::cerr << "SSL Handshake failed: " << error.message() << std::endl;
                    self->socket_.lowest_layer().close();
                }
            });
    }

    virtual void send_message(const Message& msg) {
        asio::post(io_context_,
                   [self = shared_from_this(), msg]() {
                       bool write_in_progress = !self->write_msgs_.empty();
                       self->write_msgs_.push_back(msg);
                       if (!write_in_progress) {
                           self->write_header();
                       }
                   });
    }

    // Bitfield management
    virtual void set_peer_bitfield(const hash_t& root_hash, const Bitfield& bitfield) {
        peer_bitfields_[root_hash] = bitfield;
    }

    virtual std::optional<Bitfield> get_peer_bitfield(const hash_t& root_hash) {
        auto it = peer_bitfields_.find(root_hash);
        if (it != peer_bitfields_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    virtual void send_have(const hash_t& root_hash, uint32_t piece_index) {
        Message have_msg;
        have_msg.type = MessageType::HAVE;
        have_msg.payload = Serializer::serialize_have_payload(root_hash, piece_index);
        send_message(have_msg);
    }

    // Choking / Unchoking
    virtual bool is_am_choking() const { return am_choking_; }
    virtual bool is_peer_choking() const { return peer_choking_; }

    virtual void choke_peer() {
        if (am_choking_) return;
        am_choking_ = true;
        Message msg;
        msg.type = MessageType::CHOKE;
        send_message(msg);
    }

    virtual void unchoke_peer() {
        if (!am_choking_) return;
        am_choking_ = false;
        Message msg;
        msg.type = MessageType::UNCHOKE;
        send_message(msg);
    }
    
    virtual void set_peer_choking(bool choking) {
        peer_choking_ = choking;
    }

    // Speed Measurement
    virtual double get_download_speed() const { return download_speed_; }
    
    void update_download_speed(size_t bytes, double seconds) {
        // Simple moving average or just immediate rate
        if (seconds > 0) {
            double current_rate = bytes / seconds;
            // Use an exponential moving average for smoothness
            download_speed_ = (download_speed_ * 0.7) + (current_rate * 0.3);
        }
    }

private:
    void read_header() {
        asio::async_read(socket_, asio::buffer(read_header_buffer_, HEADER_SIZE), // Use ssl_socket
            [self = shared_from_this()](const asio::error_code& error, size_t bytes_transferred) {
                if (!error) {
                    uint32_t payload_len;
                    std::memcpy(&payload_len, self->read_header_buffer_.data(), sizeof(uint32_t));
                    payload_len = asio::detail::socket_ops::network_to_host_long(payload_len);

                    MessageType msg_type = static_cast<MessageType>(self->read_header_buffer_[sizeof(uint32_t)]);

                    self->read_body(payload_len, msg_type);
                } else {
                    self->socket_.lowest_layer().close(); // Close lowest_layer
                }
            });
    }

    void read_body(uint32_t payload_len, MessageType msg_type) {
        read_msg_.type = msg_type;
        read_msg_.payload.resize(payload_len);

        asio::async_read(socket_, asio::buffer(read_msg_.payload), // Use ssl_socket
            [self = shared_from_this()](const asio::error_code& error, size_t bytes_transferred) {
                if (!error) {
                    self->download_rate_limiter_->try_consume(bytes_transferred); // Track downloaded bytes
                    
                    // Update speed stats
                    self->bytes_since_last_update_ += bytes_transferred;
                    auto now = std::chrono::steady_clock::now();
                    std::chrono::duration<double> elapsed = now - self->last_speed_update_;
                    if (elapsed.count() >= 1.0) { // Update every second
                        self->update_download_speed(self->bytes_since_last_update_, elapsed.count());
                        self->bytes_since_last_update_ = 0;
                        self->last_speed_update_ = now;
                    }

                    if (self->message_handler_) {
                        self->message_handler_(self->read_msg_);
                    }
                    self->read_header();
                } else {
                    std::cerr << "Error reading body: " << error.message() << std::endl;
                    self->socket_.lowest_layer().close(); // Close lowest_layer
                }
            });
    }

    void write_header() {
        if (!write_msgs_.empty()) {
            const Message& msg = write_msgs_.front();
            uint32_t payload_len = static_cast<uint32_t>(msg.payload.size());
            payload_len = asio::detail::socket_ops::host_to_network_long(payload_len);

            std::memcpy(write_header_buffer_.data(), &payload_len, sizeof(uint32_t));
            write_header_buffer_[sizeof(uint32_t)] = static_cast<uint8_t>(msg.type);

            // Check if we can immediately send this message
            if (upload_rate_limiter_->try_consume(HEADER_SIZE + msg.payload.size())) {
                do_write_header();
            } else {
                // If not, schedule a retry
                std::cout << "Upload rate limit exceeded. Deferring send..." << std::endl;
                schedule_write_retry();
            }
        }
    }

    void do_write_header() {
        if (!write_msgs_.empty()) {
            asio::async_write(socket_, asio::buffer(write_header_buffer_, HEADER_SIZE), // Use ssl_socket
                [self = shared_from_this()](const asio::error_code& error, size_t bytes_transferred) {
                    if (!error) {
                        self->do_write_body();
                    } else {
                        std::cerr << "Error writing header: " << error.message() << std::endl;
                        self->socket_.lowest_layer().close(); // Close lowest_layer
                    }
                });
        }
    }

    void do_write_body() {
        if (!write_msgs_.empty()) {
            const Message& msg = write_msgs_.front();
            asio::async_write(socket_, asio::buffer(msg.payload), // Use ssl_socket
                [self = shared_from_this()](const asio::error_code& error, size_t bytes_transferred) {
                    if (!error) {
                        self->write_msgs_.pop_front();
                        if (!self->write_msgs_.empty()) {
                            // Check if next message can be sent immediately
                            if (self->upload_rate_limiter_->try_consume(HEADER_SIZE + self->write_msgs_.front().payload.size())) {
                                self->do_write_header();
                            } else {
                                self->schedule_write_retry();
                            }
                        }
                    } else {
                        std::cerr << "Error writing body: " << error.message() << std::endl;
                        self->socket_.lowest_layer().close(); // Close lowest_layer
                    }
                });
        }
    }

    void schedule_write_retry() {
        // Schedule a timer to try sending again after a short delay
        // The duration should be calculated based on how many tokens are missing
        // For simplicity, let's just wait 100ms
        auto timer = std::make_shared<asio::steady_timer>(io_context_);
        timer->expires_at(std::chrono::steady_clock::now() + std::chrono::milliseconds(100));
        timer->async_wait([self = shared_from_this(), timer](const asio::error_code& error) {
            if (!error) {
                self->write_header(); // Retry sending the header
            }
        });
    }

private:
    asio::io_context& io_context_;
    ssl_socket socket_; // Changed from tcp_socket
    message_handler message_handler_;
    std::array<uint8_t, HEADER_SIZE> read_header_buffer_;
    std::array<uint8_t, HEADER_SIZE> write_header_buffer_;
    Message read_msg_;
    std::deque<Message> write_msgs_;

    // State for the remote peer
    std::map<hash_t, Bitfield> peer_bitfields_;

    std::shared_ptr<RateLimiter> upload_rate_limiter_;
    std::shared_ptr<RateLimiter> download_rate_limiter_;
    
    bool am_choking_;
    bool peer_choking_;
    double download_speed_; // Bytes per second
    std::chrono::steady_clock::time_point last_speed_update_;
    size_t bytes_since_last_update_ = 0;

public: // Public methods for rate limiting
    void set_upload_rate_limit(size_t bytes_per_sec) { upload_rate_limiter_->set_max_rate(bytes_per_sec); }
    size_t get_upload_rate_limit() const { return upload_rate_limiter_->get_max_rate(); }
    void set_download_rate_limit(size_t bytes_per_sec) { download_rate_limiter_->set_max_rate(bytes_per_sec); }
    size_t get_download_rate_limit() const { return download_rate_limiter_->get_max_rate(); }
};

#endif //P2P_CONNECTION_HPP
