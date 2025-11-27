#include "gtest/gtest.h"
#include "gmock/gmock.h" // Added for MOCK_METHOD
#include "crypto/hasher.hpp"
#include "crypto/signature.hpp"
#include "common/serializer.hpp"
#include "common/rate_limiter.hpp"
#include "files/manifest.hpp"
#include "network/protocol.hpp"
#include "dht/dht_node.hpp"
#include "dht/kademlia.hpp" // For KADEMLIA_ALPHA
#include "files/download_manager.hpp" // For DownloadManager
#include "network/connection.hpp" // For Connection mock
#include "storage/storage_manager.hpp" // For StorageManager
#include "files/chunker.hpp" // For Chunker
#include <fstream> // Moved here

#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <filesystem> // Required for fs::remove

namespace fs = std::filesystem;

// --- Unit Tests (as before) ---

// Test Hasher::sha256(const std::vector<uint8_t>&)
TEST(HasherTest, Sha256Vector) {
    std::vector<uint8_t> data = {'a', 'b', 'c'};
    hash_t expected_hash = Hasher::hex_to_hash("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    ASSERT_EQ(Hasher::sha256(data), expected_hash);
}

// Test Hasher::sha256(const std::string&)
TEST(HasherTest, Sha256String) {
    std::string data = "Hello, World!";
    hash_t expected_hash = Hasher::hex_to_hash("d04b98f48e8f8bcc15ae5b7ac0d655f4874f2a6cefe4e664df0d8cb3b8fd91d1");
    ASSERT_EQ(Hasher::sha256(data), expected_hash);
}

// Test Hasher::hex_to_hash and Hasher::hash_to_hex
TEST(HasherTest, HexConversion) {
    std::string hex_str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    hash_t hash = Hasher::hex_to_hash(hex_str);
    ASSERT_EQ(Hasher::hash_to_hex(hash), hex_str);
}

// Test Signature::generate_keypair, sign, and verify
TEST(SignatureTest, KeygenSignVerify) {
    auto keypair = Signature::generate_keypair();
    ASSERT_FALSE(keypair.first.empty()); // Private key PEM
    ASSERT_FALSE(keypair.second.empty()); // Public key DER

    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o', ',', ' ', 'S', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e', '!'};
    
    std::vector<uint8_t> signature = Signature::sign(message, keypair.first);
    ASSERT_FALSE(signature.empty());

    // Valid verification
    ASSERT_TRUE(Signature::verify(message, signature, keypair.second));

    // Invalid message
    message[0] = 'X';
    ASSERT_FALSE(Signature::verify(message, signature, keypair.second));

    // Invalid signature
    signature[0] ^= 0x01; // Flip a bit
    ASSERT_FALSE(Signature::verify(message, signature, keypair.second));
}

// Test RateLimiter
TEST(RateLimiterTest, BasicConsumption) {
    RateLimiter limiter(100); // 100 bytes/sec
    ASSERT_TRUE(limiter.try_consume(50)); // Should allow
    ASSERT_FALSE(limiter.try_consume(60)); // Should not allow (100-50=50 left)

    std::this_thread::sleep_for(std::chrono::milliseconds(1000)); // Wait 1 sec
    ASSERT_TRUE(limiter.try_consume(60)); // Should allow (50 + 100 = 150 available)
}

TEST(RateLimiterTest, SetRate) {
    RateLimiter limiter(100);
    limiter.set_max_rate(50); // New rate 50 bytes/sec
    ASSERT_TRUE(limiter.try_consume(40));
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    ASSERT_TRUE(limiter.try_consume(40)); // Was 10+50 = 60, consumed 40.
}

// Test Serializer for Manifest
TEST(SerializerTest, ManifestSerialization) {
    Manifest m_orig;
    m_orig.file_name = "test_file.txt";
    m_orig.file_size = 123456;
    m_orig.piece_size = 16384;
    m_orig.piece_hashes.push_back(Hasher::hex_to_hash("1111111111111111111111111111111111111111111111111111111111111111"));
    m_orig.piece_hashes.push_back(Hasher::hex_to_hash("2222222222222222222222222222222222222222222222222222222222222222"));
    m_orig.pieces_count = m_orig.piece_hashes.size(); // Corrected
    m_orig.root_hash = Hasher::hex_to_hash("0000000000000000000000000000000000000000000000000000000000000001");
    
    auto keypair = Signature::generate_keypair();
    std::vector<uint8_t> data_to_sign(m_orig.root_hash.begin(), m_orig.root_hash.end());
    m_orig.signature = Signature::sign(data_to_sign, keypair.first);
    m_orig.signer_pubkey = keypair.second;

    std::vector<uint8_t> buffer = Serializer::serialize_manifest(m_orig);
    Manifest m_deserialized = Serializer::deserialize_manifest(buffer);

    ASSERT_EQ(m_orig.file_name, m_deserialized.file_name);
    ASSERT_EQ(m_orig.file_size, m_deserialized.file_size);
    ASSERT_EQ(m_orig.piece_size, m_deserialized.piece_size);
    ASSERT_EQ(m_orig.pieces_count, m_deserialized.pieces_count);
    ASSERT_EQ(m_orig.root_hash, m_deserialized.root_hash);
    ASSERT_EQ(m_orig.piece_hashes, m_deserialized.piece_hashes);
    ASSERT_EQ(m_orig.signer_pubkey, m_deserialized.signer_pubkey);
    ASSERT_EQ(m_orig.signature, m_deserialized.signature);
}

// Test Serializer for HandshakePayload
TEST(SerializerTest, HandshakeSerialization) {
    HandshakePayload hs_orig;
    hs_orig.protocol_version = 1;
    hs_orig.listen_port = 12345;
    hs_orig.features = 0xFFFFFFFF;
    hs_orig.pubkey = Hasher::hex_to_hash("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    hs_orig.peer_id = dht::generate_random_id();

    std::vector<uint8_t> buffer = Serializer::serialize_handshake_payload(hs_orig);
    HandshakePayload hs_deserialized = Serializer::deserialize_handshake_payload(buffer);

    ASSERT_EQ(hs_orig.protocol_version, hs_deserialized.protocol_version);
    ASSERT_EQ(hs_orig.listen_port, hs_deserialized.listen_port);
    ASSERT_EQ(hs_orig.features, hs_deserialized.features);
    ASSERT_EQ(hs_orig.pubkey, hs_deserialized.pubkey);
    ASSERT_EQ(hs_orig.peer_id, hs_deserialized.peer_id);
}

// Test Serializer for RelayRegisterResponsePayload
TEST(SerializerTest, RelayRegisterResponseSerialization) {
    uint32_t session_id_orig = 123456789;
    std::vector<uint8_t> buffer = Serializer::serialize_relay_register_response(session_id_orig);
    uint32_t session_id_deserialized = Serializer::deserialize_relay_register_response(buffer);
    ASSERT_EQ(session_id_orig, session_id_deserialized);
}

// Test Serializer for RelayConnectPayload
TEST(SerializerTest, RelayConnectSerialization) {
    uint32_t session_id_orig = 987654321;
    std::vector<uint8_t> buffer = Serializer::serialize_relay_connect(session_id_orig);
    uint32_t session_id_deserialized = Serializer::deserialize_relay_connect(buffer);
    ASSERT_EQ(session_id_orig, session_id_deserialized);
}


// --- Integration Tests ---

// Fixture for DHT Node tests
class DhtNodeIntegrationTest : public ::testing::Test {
protected:
    asio::io_context io_context_1;
    asio::io_context io_context_2;
    asio::io_context io_context_3;

    StorageManager sm_1{"dht_test_1.db"};
    StorageManager sm_2{"dht_test_2.db"};
    StorageManager sm_3{"dht_test_3.db"};

    std::unique_ptr<dht::DhtNode> node1;
    std::unique_ptr<dht::DhtNode> node2;
    std::unique_ptr<dht::DhtNode> node3;

    std::thread thread1;
    std::thread thread2;
    std::thread thread3;

    void SetUp() override {
        fs::remove("dht_test_1.db");
        fs::remove("dht_test_2.db");
        fs::remove("dht_test_3.db");
        
        node1 = std::make_unique<dht::DhtNode>(io_context_1, 50001, sm_1);
        node2 = std::make_unique<dht::DhtNode>(io_context_2, 50002, sm_2);
        node3 = std::make_unique<dht::DhtNode>(io_context_3, 50003, sm_3);

        node1->start();
        node2->start();
        node3->start();

        thread1 = std::thread([this](){ io_context_1.run(); });
        thread2 = std::thread([this](){ io_context_2.run(); });
        thread3 = std::thread([this](){ io_context_3.run(); });

        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    void TearDown() override {
        io_context_1.stop();
        io_context_2.stop();
        io_context_3.stop();

        if (thread1.joinable()) thread1.join();
        if (thread2.joinable()) thread2.join();
        if (thread3.joinable()) thread3.join();
    }
};

TEST_F(DhtNodeIntegrationTest, BootstrapAndFindNode) {
    node2->bootstrap(asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 50001));
    std::this_thread::sleep_for(std::chrono::seconds(2));

    node3->bootstrap(asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 50002));
    std::this_thread::sleep_for(std::chrono::seconds(2));

    std::vector<dht::NodeInfo> found_nodes;
    bool lookup_complete = false;

    node3->start_find_node_lookup(node1->get_self_id(), 
        [&](const std::vector<dht::NodeInfo>& nodes) {
            found_nodes = nodes;
            lookup_complete = true;
        });

    for(int i = 0; i < 10 && !lookup_complete; ++i) { 
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    ASSERT_TRUE(lookup_complete);
    ASSERT_FALSE(found_nodes.empty());
    
    bool node1_found = false;
    for (const auto& node_info : found_nodes) {
        if (node_info.id == node1->get_self_id()) {
            node1_found = true;
            break;
        }
    }
    ASSERT_TRUE(node1_found);
}

TEST_F(DhtNodeIntegrationTest, StoreAndFindValue) {
    node2->bootstrap(asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 50001));
    std::this_thread::sleep_for(std::chrono::seconds(2));
    node3->bootstrap(asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 50002));
    std::this_thread::sleep_for(std::chrono::seconds(2));

    dht::NodeID test_key = dht::generate_random_id();
    std::vector<uint8_t> test_value = {'H', 'e', 'l', 'l', 'o', ' ', 'D', 'H', 'T', '!'};

    node1->start_find_node_lookup(test_key, 
        [&](const std::vector<dht::NodeInfo>& closest_nodes) {
            for(const auto& node_info : closest_nodes) {
                node1->send_store(node_info.endpoint, test_key, test_value);
            }
        });
    std::this_thread::sleep_for(std::chrono::seconds(2));

    std::optional<std::vector<uint8_t>> found_value;
    bool lookup_complete = false;

    node3->start_find_value_lookup(test_key, 
        [&](const std::optional<std::vector<uint8_t>>& value, const std::vector<dht::NodeInfo>&) {
            found_value = value;
            lookup_complete = true;
        });
    
    for(int i = 0; i < 10 && !lookup_complete; ++i) { 
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    ASSERT_TRUE(lookup_complete);
    ASSERT_TRUE(found_value.has_value());
    ASSERT_EQ(found_value.value(), test_value);
}

// Fixture for DownloadManager tests
class DownloadManagerTest : public ::testing::Test {
protected:
    asio::io_context io_context_;
    StorageManager sm_ {"download_test.db"};
    Manifest test_manifest;
    hash_t test_root_hash;
    std::vector<uint8_t> piece_data_1 = {'P', 'I', 'E', 'C', 'E', '1'};
    std::vector<uint8_t> piece_data_2 = {'P', 'I', 'E', 'C', 'E', '2'};

    void SetUp() override {
        fs::remove("download_test.db");
        // We cannot remove final_file_path_ here as it's not yet determined by DM.
        // DownloadManager creates temp_file_path_ and renames it.
        // We'll remove it in TearDown.

        test_root_hash = Hasher::sha256("test_content");
        test_manifest.file_name = "test_file.txt";
        test_manifest.file_size = piece_data_1.size() + piece_data_2.size();
        test_manifest.piece_size = piece_data_1.size();
        test_manifest.pieces_count = 2;
        test_manifest.root_hash = test_root_hash;
        test_manifest.piece_hashes.push_back(Hasher::sha256(piece_data_1));
        test_manifest.piece_hashes.push_back(Hasher::sha256(piece_data_2));

        sm_.save_manifest(test_manifest);
    }

    void TearDown() override {
        fs::remove("download_test.db");
        // The DownloadManagerTest will create its own DM instance, we need to
        // get the final path from it.
        // This is tricky if DM instance is not accessible here.
        // For simplicity, let's remove by a predictable name for now.
        fs::remove(Hasher::hash_to_hex(Hasher::sha256("test_content"))); // Predictable final file name
        fs::remove(Hasher::hash_to_hex(Hasher::sha256("test_content")) + ".tmp"); // Temp file
    }
};

// Mock Connection class for DownloadManager testing
class MockConnection : public Connection {
public:
    MockConnection(asio::io_context& io_context, asio::ssl::context& ssl_context,
                   std::shared_ptr<RateLimiter> upload_limiter,
                   std::shared_ptr<RateLimiter> download_limiter)
        : Connection(io_context, ssl_context, upload_limiter, download_limiter) {}

    MOCK_METHOD(void, send_message, (const Message& msg), (override));
    MOCK_METHOD(void, set_peer_bitfield, (const hash_t& root_hash, const Bitfield& bitfield), (override));
    MOCK_METHOD(std::optional<Bitfield>, get_peer_bitfield, (const hash_t& root_hash), (override));
    MOCK_METHOD(void, send_have, (const hash_t& root_hash, uint32_t piece_index), (override));
    MOCK_METHOD(bool, is_am_choking, (), (const, override));
    MOCK_METHOD(bool, is_peer_choking, (), (const, override));
    MOCK_METHOD(void, choke_peer, (), (override));
    MOCK_METHOD(void, unchoke_peer, (), (override));
    MOCK_METHOD(void, set_peer_choking, (bool choking), (override));
    MOCK_METHOD(double, get_download_speed, (), (const, override));
};


TEST_F(DownloadManagerTest, FullDownload) {
    // Requires a mock server logic. This is hard without mocking the server itself.
    // DownloadManager expects to be called by the Server with messages.

    // This test will only verify that DownloadManager can request pieces and write them.
    // Mock a Connection to control sent messages.
    asio::ssl::context ssl_context(asio::ssl::context::tlsv12_client); // Dummy
    std::shared_ptr<RateLimiter> up_limiter = std::make_shared<RateLimiter>(0);
    std::shared_ptr<RateLimiter> down_limiter = std::make_shared<RateLimiter>(0);

    // MockConnection peer(io_context_, ssl_context, up_limiter, down_limiter);
    // There is no constructor with 5 arguments.
    // Connection::Connection(asio::io_context& io_context, asio::ssl::context& ssl_context, std::shared_ptr<RateLimiter> upload_limiter, std::shared_ptr<RateLimiter> download_limiter)

    // Manual mock for now.
    class MockConnectionManual : public Connection {
    public:
        MockConnectionManual(asio::io_context& io_context, asio::ssl::context& ssl_context,
                   std::shared_ptr<RateLimiter> upload_limiter,
                   std::shared_ptr<RateLimiter> download_limiter)
            : Connection(io_context, ssl_context, upload_limiter, download_limiter),
              ep_(asio::ip::make_address("127.0.0.1"), 12345) {}

        std::vector<Message> sent_messages;
        std::optional<Bitfield> peer_bitfield;

        void send_message(const Message& msg) override {
            sent_messages.push_back(msg);
        }

        void set_peer_bitfield(const hash_t& root_hash, const Bitfield& bf) override {
            peer_bitfield = bf;
        }

        std::optional<Bitfield> get_peer_bitfield(const hash_t& root_hash) override {
            return peer_bitfield;
        }

        bool is_am_choking() const override { return false; }
        bool is_peer_choking() const override { return false; }
        void choke_peer() override {}
        void unchoke_peer() override {}
        void set_peer_choking(bool choking) override {}
        double get_download_speed() const override { return 0.0; }
        asio::ip::tcp::endpoint remote_endpoint() const { return ep_; } // Mock endpoint

    private:
        asio::ip::tcp::endpoint ep_;
    };
    
    // Test that the manifest is loaded from StorageManager.
    DownloadManager dm(test_root_hash, sm_);
    
    // Simulate peer connection and manifest/bitfield exchange
    auto peer = std::make_shared<MockConnectionManual>(io_context_, ssl_context, up_limiter, down_limiter);
    dm.add_peer(peer);

    // DM sends QUERY_SEARCH for manifest. This happens in start().
    dm.start();

    // Simulate SEARCH_RESPONSE (manifest)
    Message search_resp_msg;
    search_resp_msg.type = MessageType::SEARCH_RESPONSE;
    search_resp_msg.payload.push_back(1); // Found = true
    search_resp_msg.payload.insert(search_resp_msg.payload.end(),
                                   Serializer::serialize_manifest(test_manifest).begin(),
                                   Serializer::serialize_manifest(test_manifest).end());
    dm.handle_message(search_resp_msg, peer);

    // Simulate BITFIELD
    Message bitfield_msg;
    bitfield_msg.type = MessageType::BITFIELD;
    Bitfield full_bitfield(test_manifest.pieces_count);
    full_bitfield.set_all();
    
    bitfield_msg.payload = Serializer::serialize_bitfield_payload(test_root_hash, full_bitfield);

    dm.handle_message(bitfield_msg, peer);

    // DM should now request pieces.
    // Check if REQUEST_PIECE messages were sent
    ASSERT_FALSE(peer->sent_messages.empty());
    
    // Need to verify the content of the first message. It should be REQUEST_PIECE for piece 0.
    // DownloadManager could send multiple requests depending on REQUEST_WINDOW_SIZE.
    bool piece_0_requested = false;
    bool piece_1_requested = false;

    for(const auto& msg_sent : peer->sent_messages) {
        if(msg_sent.type == MessageType::REQUEST_PIECE) {
            RequestPiecePayload req_payload;
            std::memcpy(&req_payload, msg_sent.payload.data(), sizeof(req_payload));
            if(req_payload.piece_index == 0) piece_0_requested = true;
            if(req_payload.piece_index == 1) piece_1_requested = true;
        }
    }
    ASSERT_TRUE(piece_0_requested);
    ASSERT_TRUE(piece_1_requested);


    // Simulate receiving piece 0
    Message piece_msg_0;
    piece_msg_0.type = MessageType::PIECE;
    piece_msg_0.payload = Serializer::serialize_piece_payload(test_root_hash, 0, piece_data_1);
    dm.handle_message(piece_msg_0, peer);

    // Simulate receiving piece 1
    Message piece_msg_1;
    piece_msg_1.type = MessageType::PIECE;
    piece_msg_1.payload = Serializer::serialize_piece_payload(test_root_hash, 1, piece_data_2);
    dm.handle_message(piece_msg_1, peer);

    // Check if the file is assembled and verified
    std::string expected_content(piece_data_1.begin(), piece_data_1.end());
    expected_content.append(piece_data_2.begin(), piece_data_2.end());
    
    std::ifstream final_file(dm.get_final_file_path().string(), std::ios::binary);
    std::string actual_content((std::istreambuf_iterator<char>(final_file)), std::istreambuf_iterator<char>());
    
    ASSERT_EQ(actual_content, expected_content);
}