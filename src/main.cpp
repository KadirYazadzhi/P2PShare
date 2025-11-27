#include <iostream>
#include <string>
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <memory>
#include <thread>
#include <chrono>
#include <filesystem>

#include "network/server.hpp"
#include "network/client.hpp" // Keeping for test mode
#include "network/protocol.hpp"
#include "storage/storage_manager.hpp"
#include "files/file_sharer.hpp"
#include "cli/cli.hpp"
#include "common/logger.hpp" // Added

void print_usage() {
    std::cout << "Usage: p2pshare <mode> [options]\n"
              << "Modes:\n"
              << "  interactive [port]     - Run full P2P node with CLI (default port 8080)\n"
              << "  server <port>          - Run as a headless server.\n"
              << "  handshake_test <port>  - Run automated handshake test.\n";
}

// Keep test handler for handshake_test
void client_message_handler(const Message& msg, std::shared_ptr<Connection> conn) {
     LOG_INFO("Test Client received msg type: ", static_cast<int>(msg.type));
}

int main(int argc, char* argv[]) {
    // Initialize Logger
    Logger::instance().init("p2p_node.log");
    LOG_INFO("Starting P2PShare Node...");

    std::string mode = "interactive";
    if (argc > 1) {
        mode = argv[1];
    }

    try {
        if (mode == "interactive" || mode == "server") {
            uint16_t port = 8080;
            if (argc > 2) {
                port = std::stoi(argv[2]);
            }
            
            std::string db_path = "p2p_data.db";
            asio::io_context io_context;

            // 1. Setup Storage
            StorageManager storage_manager(db_path);

            // 2. Setup FileSharer
            FileSharer::instance().set_storage_manager(&storage_manager);

            // 3. Setup Server
            Server server(io_context, port, storage_manager);

            // 4. Run IO in background thread
            std::thread io_thread([&io_context]() {
                // Use a work guard to keep run() from returning if no work
                auto work_guard = asio::make_work_guard(io_context);
                try {
                    io_context.run();
                } catch (const std::exception& e) {
                    std::cerr << "IO Thread Error: " << e.what() << std::endl;
                }
            });

            std::cout << "P2P Node started on port " << port << " (" << mode << " mode)" << std::endl;

            if (mode == "interactive") {
                CLI cli(storage_manager, server);
                cli.run();
                
                // Cleanup after CLI exit
                io_context.stop();
                if (io_thread.joinable()) io_thread.join();
            } else {
                if (io_thread.joinable()) io_thread.join();
            }

        } else if (mode == "handshake_test" && argc == 3) {
            // Keep original test logic for verification
            uint16_t port = std::stoi(argv[2]);
            
            asio::io_context server_io;
            StorageManager sm("test_db.sqlite");
            Server s(server_io, port, sm);
            
            std::thread server_thread([&server_io](){
                server_io.run();
            });
            
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            
            asio::io_context client_io;
            asio::ssl::context ssl_ctx(asio::ssl::context::tlsv12_client);
            ssl_ctx.load_verify_file("server.crt");
            ssl_ctx.set_verify_mode(asio::ssl::verify_peer);
            
            Client c(client_io, client_message_handler, ssl_ctx);
            c.connect("127.0.0.1", port, [](std::shared_ptr<Connection> conn){
                if(conn) std::cout << "Test Client Connected!\n";
            });
            
            client_io.run_for(std::chrono::seconds(2));
            server_io.stop();
            if(server_thread.joinable()) server_thread.join();
            
        } else {
            print_usage();
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Fatal Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
