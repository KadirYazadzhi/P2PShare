#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <future> // For std::promise and std::future
#include <filesystem> // Added for std::filesystem

#include "network/connection.hpp"
#include "network/protocol.hpp"
#include "common/serializer.hpp" // For Message serialization
#include "crypto/hasher.hpp" // For SHA256 verification (optional, but good practice)

using namespace std::chrono_literals;
using asio::ip::tcp;
namespace fs = std::filesystem; // Added namespace alias

const uint16_t THROTTLING_TEST_PORT = 8095;
const size_t FILE_SIZE = 100 * 1024; // 100 KB file for testing

// Helper to create a dummy file
void create_dummy_file(const std::string& filename, size_t size) {
    std::ofstream ofs(filename, std::ios::binary);
    std::vector<char> buffer(1024);
    for (size_t i = 0; i < size / 1024; ++i) {
        ofs.write(buffer.data(), buffer.size());
    }
    ofs.write(buffer.data(), size % 1024);
}

// SHA256 hash for verification
std::array<uint8_t, 32> calculate_file_hash(const std::string& filename) {
    std::ifstream ifs(filename, std::ios::binary);
    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    return Hasher::sha256(buffer);
}

void run_server(std::promise<void> server_ready_promise, std::shared_ptr<std::promise<std::chrono::steady_clock::duration>> transfer_time_promise_ptr) {
    asio::io_context io_context;
    asio::ssl::context ssl_context(asio::ssl::context::tlsv12_server);
    ssl_context.use_certificate_chain_file("../../server.crt");
    ssl_context.use_private_key_file("../../server.key", asio::ssl::context::pem);

    tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), THROTTLING_TEST_PORT));
    std::cout << "[Server] Waiting for connection on port " << THROTTLING_TEST_PORT << std::endl;
    server_ready_promise.set_value();

    auto conn = std::make_shared<Connection>(io_context, ssl_context);
    conn->set_upload_rate_limit(1024 * 10); // 10 KB/s upload limit
    std::cout << "[Server] Upload rate limit set to " << conn->get_upload_rate_limit() << " B/s" << std::endl;

    acceptor.async_accept(conn->socket().lowest_layer(),
        [&, conn, transfer_time_promise_ptr](const asio::error_code& ec) {
            if (!ec) {
                std::cout << "[Server] Accepted connection." << std::endl;
                conn->start(asio::ssl::stream_base::server, [&, conn, transfer_time_promise_ptr]() {
                    // Send a large dummy file
                    std::string dummy_file_name = "server_dummy_file.bin";
                    create_dummy_file(dummy_file_name, FILE_SIZE);
                    std::ifstream ifs(dummy_file_name, std::ios::binary);
                    std::vector<uint8_t> file_data((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

                    auto start_time = std::chrono::steady_clock::now();
                    auto file_data_ptr = std::make_shared<std::vector<uint8_t>>(file_data); // Share file_data
                    auto sent_bytes_ptr = std::make_shared<size_t>(0); // Shared counter

                    auto send_next_chunk = std::make_shared<std::function<void()>>();
                    *send_next_chunk = [&, conn, start_time, file_data_ptr, sent_bytes_ptr, transfer_time_promise_ptr, send_next_chunk]() {
                        if (*sent_bytes_ptr < FILE_SIZE) {
                            size_t bytes_to_send = std::min(FILE_SIZE - *sent_bytes_ptr, (size_t)1024);
                            std::vector<uint8_t> chunk(file_data_ptr->begin() + *sent_bytes_ptr, file_data_ptr->begin() + *sent_bytes_ptr + bytes_to_send);

                            Message msg;
                            msg.type = MessageType::PIECE;
                            msg.payload = Serializer::serialize_piece_payload(Hasher::sha256("dummy"), (uint32_t)(*sent_bytes_ptr / 1024), chunk);

                            conn->send_message(msg);
                            *sent_bytes_ptr += bytes_to_send;

                            asio::post(conn->get_io_context(), *send_next_chunk);

                        } else {
                            auto end_time = std::chrono::steady_clock::now();
                            transfer_time_promise_ptr->set_value(end_time - start_time);
                            std::cout << "[Server] Finished sending dummy file." << std::endl;
                            conn->socket().lowest_layer().close(); // Re-introducing close
                        }
                    };
                    asio::post(conn->get_io_context(), *send_next_chunk); // Start the sending process
                });
            } else {
                std::cerr << "[Server] Accept failed: " << ec.message() << std::endl;
            }
        });

    io_context.run();
    std::cout << "[Server] Shutting down." << std::endl;
}

void run_client(std::shared_ptr<std::promise<void>> client_finished_promise_ptr) {
    asio::io_context io_context;
    asio::ssl::context ssl_context(asio::ssl::context::tlsv12_client);
    ssl_context.load_verify_file("../../server.crt");
    ssl_context.set_verify_mode(asio::ssl::verify_peer);

    auto conn = std::make_shared<Connection>(io_context, ssl_context);
    conn->set_download_rate_limit(1024 * 10); // 10 KB/s download limit
    std::cout << "[Client] Download rate limit set to " << conn->get_download_rate_limit() << " B/s" << std::endl;

    tcp::resolver resolver(io_context);
    auto endpoints = resolver.resolve("127.0.0.1", std::to_string(THROTTLING_TEST_PORT));

    size_t received_bytes = 0;
    std::string received_file_name = "client_received_file.bin";
    std::ofstream ofs(received_file_name, std::ios::binary);

    conn->set_message_handler([&, client_finished_promise_ptr](Message msg) {
        if (msg.type == MessageType::PIECE) {
            auto [root_hash, piece_index, data] = Serializer::deserialize_piece_payload(msg.payload);
            ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
            received_bytes += data.size();
            std::cout << "[Client] Received " << received_bytes << "/" << FILE_SIZE << " bytes." << std::endl;

            if (received_bytes >= FILE_SIZE) {
                std::cout << "[Client] Download complete. Closing file." << std::endl;
                ofs.close();
                conn->socket().lowest_layer().close(); // Re-introducing close
                client_finished_promise_ptr->set_value();
            }
        }
    });

    asio::async_connect(conn->socket().lowest_layer(), endpoints,
        [&, conn, client_finished_promise_ptr](const asio::error_code& ec, const tcp::endpoint& ep) {
            if (!ec) {
                std::cout << "[Client] Connected to " << ep << std::endl;
                conn->start(asio::ssl::stream_base::client, [&, conn, client_finished_promise_ptr]() {
                    std::cout << "[Client] SSL handshake complete. Waiting for data..." << std::endl;
                    // Client just waits for the server to send data
                });
            } else {
                std::cerr << "[Client] Connect failed: " << ec.message() << std::endl;
                client_finished_promise_ptr->set_value(); // Signal failure
            }
        });
    
    io_context.run();
    std::cout << "[Client] Shutting down." << std::endl;
    // Clean up
    fs::remove(received_file_name);
    fs::remove("server_dummy_file.bin"); // Server's dummy file
}

int main(int argc, char* argv[]) {
    fs::path executable_dir = ".";
    if (argc > 0) {
        executable_dir = fs::path(argv[0]).parent_path();
        fs::current_path(executable_dir);
    }

    std::cout << "--- Starting Throttling Test ---" << std::endl;

    std::promise<void> server_ready_promise;
    std::future<void> server_ready_future = server_ready_promise.get_future();
    
    auto transfer_time_promise_ptr = std::make_shared<std::promise<std::chrono::steady_clock::duration>>();
    std::future<std::chrono::steady_clock::duration> transfer_time_future = transfer_time_promise_ptr->get_future();
    
    auto client_finished_promise_ptr = std::make_shared<std::promise<void>>();
    std::future<void> client_finished_future = client_finished_promise_ptr->get_future();


    std::thread server_thread(run_server, std::move(server_ready_promise), transfer_time_promise_ptr);
    server_ready_future.wait(); // Wait for server to be ready
    std::this_thread::sleep_for(100ms); // Small delay

    std::thread client_thread(run_client, client_finished_promise_ptr);

    client_finished_future.wait(); // Wait for client to finish
    auto actual_transfer_time = transfer_time_future.get();
    
    server_thread.join();
    client_thread.join();
    
    // Calculate expected time: FILE_SIZE / RATE
    // 100 KB / 10 KB/s = 10 seconds
    double expected_min_time_sec = static_cast<double>(FILE_SIZE) / (1024 * 10);
    double actual_transfer_time_sec = std::chrono::duration<double>(actual_transfer_time).count();

    std::cout << "Expected min transfer time: " << expected_min_time_sec << " seconds" << std::endl;
    std::cout << "Actual transfer time:     " << actual_transfer_time_sec << " seconds" << std::endl;

    // Allow some margin for overhead
    assert(actual_transfer_time_sec >= expected_min_time_sec - 1.0); // Allow 1 second less for overhead
    assert(actual_transfer_time_sec <= expected_min_time_sec + 5.0); // Allow 5 seconds more for overhead
    std::cout << "Throttling test PASSED. Transfer time is within expected limits." << std::endl;

    std::cout << "--- Throttling Test Finished Successfully ---" << std::endl;

    return 0;
}