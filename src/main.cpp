#include <iostream>
#include <string>
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <memory>
#include <thread>
#include <chrono>

#include "network/server.hpp"
#include "network/client.hpp"
#include "network/protocol.hpp"

// A simple message handler for the client to print received messages.
void client_message_handler(const Message& msg, std::shared_ptr<Connection> conn) {
    std::cout << "Client received message of type: " << static_cast<int>(msg.type) << std::endl;
    if (msg.type == MessageType::HANDSHAKE) {
        std::cout << "--> Received HANDSHAKE back from server." << std::endl;
    }
}

void print_usage() {
    std::cout << "Usage: p2pshare <mode> [options]\n"
              << "Modes:\n"
              << "  server <port>          - Run as a server.\n"
              << "  client <host> <port>   - Run as a client and connect to a server.\n"
              << "  handshake_test <port>  - Run an automated server/client handshake test.\n";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage();
        return 1;
    }

    std::string mode = argv[1];
    asio::io_context io_context;

    try {
        if (mode == "server" && argc == 3) {
            uint16_t port = std::stoi(argv[2]);
            Server s(io_context, port);
            io_context.run();
        } else if (mode == "client" && argc == 4) {
            std::string host = argv[2];
            uint16_t port = std::stoi(argv[3]);

            asio::ssl::context ssl_context(asio::ssl::context::tlsv12_client);
            ssl_context.load_verify_file("server.crt");
            ssl_context.set_verify_mode(asio::ssl::verify_peer);

            Client c(io_context, client_message_handler, ssl_context);

            c.connect(host, port, [](std::shared_ptr<Connection> conn){
                if (conn) {
                    std::cout << "Client connection successful. Handshake sent." << std::endl;
                } else {
                    std::cerr << "Client connection failed." << std::endl;
                }
            });

            io_context.run();
        } else if (mode == "handshake_test" && argc == 3) {
            uint16_t port = std::stoi(argv[2]);

            // Start server in a separate thread
            asio::io_context server_io_context;
            Server s(server_io_context, port);
            std::thread server_thread([&server_io_context]() {
                try {
                    server_io_context.run();
                } catch (const std::exception& e) {
                    std::cerr << "Server thread exception: " << e.what() << std::endl;
                }
            });

            // Give server a moment to start
            std::cout << "Waiting for server to start..." << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(500));

            // Client connects to the server
            std::cout << "Starting client..." << std::endl;
            asio::io_context client_io_context;
            asio::ssl::context client_ssl_context(asio::ssl::context::tlsv12_client);
            client_ssl_context.load_verify_file("server.crt");
            client_ssl_context.set_verify_mode(asio::ssl::verify_peer);

            Client c(client_io_context, client_message_handler, client_ssl_context);

            c.connect("127.0.0.1", port, [&client_io_context](std::shared_ptr<Connection> conn){
                if(conn) {
                    std::cout << "Client connected and sent handshake to server." << std::endl;
                } else {
                     std::cerr << "Client connection in test failed." << std::endl;
                     client_io_context.stop();
                }
            });

            client_io_context.run();
            
            std::cout << "Client finished. Stopping server." << std::endl;
            server_io_context.stop();
            if(server_thread.joinable()) {
                server_thread.join();
            }
             std::cout << "Test finished." << std::endl;

        }else {
            print_usage();
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}