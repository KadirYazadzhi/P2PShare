cmake_minimum_required(VERSION 3.10)
project(TestEnv CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add the main project's include directory
include_directories(../include)
include_directories(../third_party/miniupnpc/miniupnpc/include)


# The main project includes ASIO via add_subdirectory or find_package.
# For this simple test, we can just point to the include directory.
# We assume the main CMakeLists.txt has already made third_party libs available.
include_directories(../third_party/asio/include)

# Add miniupnpc as a subdirectory to make its targets available
add_subdirectory(../third_party/miniupnpc/miniupnpc miniupnpc_build)


add_executable(test_runner
    main.cpp
    ../src/files/chunker.cpp
    ../src/files/file_sharer.cpp
    ../src/crypto/hasher.cpp
    ../src/storage/storage_manager.cpp
    ../src/common/serializer.cpp
    ../src/dht/kademlia.cpp
    ../src/dht/dht_node.cpp
    ../src/network/nat_traversal.cpp
)

# Link against OpenSSL, which is required by the hasher
find_package(OpenSSL REQUIRED)
target_link_libraries(test_runner PRIVATE OpenSSL::SSL OpenSSL::Crypto miniupnpc::miniupnpc sqlite3)

# Link against SQLite3, which is required by the StorageManager
find_package(SQLite3 REQUIRED)
target_link_libraries(test_runner PRIVATE sqlite3)

# Add the throttling_test executable
add_executable(throttling_test
    throttling_test.cpp
    ../src/files/chunker.cpp
    ../src/files/file_sharer.cpp
    ../src/crypto/hasher.cpp
    ../src/storage/storage_manager.cpp
    ../src/common/serializer.cpp
    ../../src/common/rate_limiter.cpp
    ../src/network/nat_traversal.cpp
    ../src/dht/kademlia.cpp
    ../src/dht/dht_node.cpp
)

target_link_libraries(throttling_test PRIVATE OpenSSL::SSL OpenSSL::Crypto sqlite3 miniupnpc::miniupnpc)