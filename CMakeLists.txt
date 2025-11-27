cmake_minimum_required(VERSION 3.10)
project(P2PShare CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenSSL for hashing
find_package(OpenSSL REQUIRED)

# Find SQLite3
find_package(SQLite3 REQUIRED)

# Include directories
include_directories(include)
include_directories(third_party/asio/include)
include_directories(third_party/json/include)
# Gather all source files
set(SOURCES
    src/common/serializer.cpp
    src/common/rate_limiter.cpp
    src/crypto/hasher.cpp
    src/files/chunker.cpp
    src/files/download_manager.cpp
    src/files/file_sharer.cpp
    src/cli/cli.cpp
    src/main.cpp
    src/network/client.cpp
    src/network/server.cpp
    src/network/nat_traversal.cpp # Added nat_traversal.cpp
    src/storage/share_state.cpp
    src/dht/kademlia.cpp
    src/dht/dht_node.cpp
    src/storage/storage_manager.cpp # Added storage_manager.cpp
)

# Add miniupnpc as a subdirectory
add_subdirectory(third_party/miniupnpc/miniupnpc)

# Add the executable
add_executable(p2pshare ${SOURCES})

# Link libraries
target_link_libraries(p2pshare PRIVATE OpenSSL::SSL OpenSSL::Crypto miniupnpc::miniupnpc sqlite3)

# Add include directory for the executable
target_include_directories(p2pshare PRIVATE include third_party/miniupnpc/miniupnpc/include)
