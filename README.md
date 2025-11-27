# P2PShare: A Modern C++ Peer-to-Peer File Sharing System

**P2PShare** is a high-performance, decentralized file sharing system built from scratch in modern C++20. It implements a BitTorrent-like protocol, featuring a Kademlia DHT for peer discovery, advanced NAT traversal (TCP Hole Punching, UPnP, Relay), end-to-end encryption via TLS, and cryptographic data verification.

The project is designed to demonstrate advanced systems programming concepts, including asynchronous networking, distributed systems algorithms, low-level binary serialization, and robust concurrency control.

## 🌟 Key Features

### 🔗 Networking & Connectivity
*   **Decentralized Architecture:** No central server required. Peers discover each other via a distributed hash table (DHT).
*   **Asynchronous I/O:** Built on `Boost.Asio` (standalone) for high-concurrency, non-blocking network operations.
*   **NAT Traversal:** Supports UPnP and STUN for automatic port mapping.
*   **TCP Hole Punching:** Allows direct connection between peers behind restrictive NATs using UDP signaling via DHT.
*   **Relay Server (TURN-like):** Fallback mechanism for communication when direct connection is impossible (e.g., symmetric NATs).
*   **TLS Encryption:** All peer-to-peer communication is secured using OpenSSL/TLS.

### 📦 Data Transfer & Storage
*   **Chunked Transfer:** Files are split into pieces (256KB default) and verified individually using SHA-256.
*   **Manifests:** Files are described by a cryptographic manifest containing piece hashes, file size, and digital signatures.
*   **Persistence:** Uses SQLite to persist shared files, active downloads, known peers, and DHT routing tables across restarts.
*   **Resume Capability:** Automatically resumes interrupted downloads from the last verified piece.

### 🛡️ Security & Integrity
*   **Digital Signatures:** Manifests are signed with ECDSA (secp256r1) keys to ensure authenticity.
*   **Identity Management:** Auto-generates persistent cryptographic identities (public/private keys).
*   **Traffic Encryption:** Secure Handshake and data transport.

### ⚡ Optimization & Economics
*   **Tit-for-Tat (Optimistic Unchoking):** Implements BitTorrent's reciprocity algorithm to reward uploading peers and prevent free-riding.
*   **End-Game Mode:** Aggressively requests remaining pieces from all available peers to finish downloads quickly.
*   **Rate Limiting:** Global upload/download bandwidth limits with token bucket algorithm.

---

## 📂 Project Structure

```
P2PShare/
├── src/
│   ├── cli/
│   │   └── cli.cpp            # Command-Line Interface logic (commands parsing)
│   ├── common/
│   │   ├── logger.cpp         # Thread-safe logging system with levels/colors
│   │   ├── rate_limiter.cpp   # Token bucket rate limiting implementation
│   │   └── serializer.cpp     # Binary serialization for wire protocol
│   ├── crypto/
│   │   ├── hasher.cpp         # SHA-256 hashing utilities (OpenSSL wrapper)
│   │   └── signature.cpp      # ECDSA keygen, signing, and verification
│   ├── dht/
│   │   ├── dht_node.cpp       # High-level Kademlia node logic (RPCs, Lookup)
│   │   └── kademlia.cpp       # Routing Table logic (k-buckets, distance metric)
│   ├── files/
│   │   ├── chunker.cpp        # File splitting and manifest generation
│   │   ├── download_manager.cpp # Orchestrates downloading, piece verification, and writing
│   │   └── file_sharer.cpp    # Manages local shared files and reading pieces
│   ├── network/
│   │   ├── client.cpp         # Simple client connector wrapper
│   │   ├── connection.cpp     # Wraps TCP/SSL socket, handles message framing & state
│   │   ├── nat_traversal.cpp  # UPnP and STUN implementation
│   │   └── server.cpp         # Central node controller: accepts connections, manages peers & relay
│   ├── storage/
│   │   └── storage_manager.cpp # SQLite database interface (persistence layer)
│   └── main.cpp               # Entry point, initialization of components
├── include/                   # Header files mirroring the src structure
│   ├── cli/
│   ├── common/
│   ├── crypto/
│   ├── dht/
│   ├── files/
│   ├── network/
│   └── storage/
├── tests/                     # Unit and Integration tests using GoogleTest
└── third_party/               # Submodules: Asio, JSON, MiniUPnPc, GoogleTest
```

---

## 🧠 Design Philosophy

1.  **Modern C++ (C++20):** Leverages modern features like `std::filesystem`, smart pointers (`std::shared_ptr`, `std::unique_ptr`), lambdas, and threading primitives for safe and expressive code.
2.  **Asynchronous Model:** Uses the Proactor pattern via `io_context`. This allows a single thread (or a small pool) to handle thousands of concurrent connections without the overhead of thread-per-connection.
3.  **Dependency Injection:** Components like `StorageManager` and `RateLimiter` are injected into `Server` and `DownloadManager`, making the system modular and testable.
4.  **Binary Protocol:** Custom binary framing `[Length][Type][Payload]` minimizes overhead compared to text-based protocols (like HTTP/JSON) for core data transfer.
5.  **Robustness:** Defensive programming with comprehensive error handling, logging, and automatic recovery mechanisms (e.g., re-requesting failed pieces, banning bad peers).

---

## 🛠️ Core Components Explained

### 1. The Server (`src/network/server.cpp`)
The `Server` class is the heart of the application. It:
*   Listens on a TCP port for incoming file transfer connections.
*   Runs a UDP listener for the DHT node.
*   Manages the lifecycle of all active `Connection` objects.
*   Orchestrates the **Relay** logic (acting as a bridge between NATed peers).
*   Runs the **Tit-for-Tat** timer loop to recalculate choke/unchoke states.

### 2. The DHT Node (`src/dht/dht_node.cpp`)
Implements the Kademlia distributed hash table.
*   **Routing:** Maintains k-buckets of known peers closest to specific IDs.
*   **RPCs:** Sends and handles `PING`, `FIND_NODE`, `STORE`, and `FIND_VALUE` messages over UDP.
*   **Discovery:** Used to publish (announce) that "I have file X" and to query "Who has file X?".
*   **Signaling:** Used as a side-channel to initiate TCP Hole Punching requests.

### 3. Download Manager (`src/files/download_manager.cpp`)
Responsible for downloading a single file.
*   **State Machine:** Tracks the state of every piece (Needed, Requested, Have).
*   **Swarm Management:** Tracks which connected peers have which pieces (via Bitfields).
*   **Strategy:** Implements "Rarest-First" selection and "End-Game" mode.
*   **Integrity:** Verifies the SHA-256 hash of every received piece against the trusted Manifest.

### 4. Connection (`src/network/connection.cpp`)
Represents a persistent TCP/TLS link to a peer.
*   **Framing:** Handles the low-level reading/writing of length-prefixed messages.
*   **Rate Limiting:** Enforces global upload/download speed limits.
*   **Security:** Wraps the raw socket in an SSL stream.

---

## 🚀 Build & Run

### Prerequisites
*   CMake (3.10+)
*   C++ Compiler (GCC/Clang with C++20 support)
*   OpenSSL
*   SQLite3

### Compilation
```bash
mkdir build
cd build
cmake ..
make
```

### Running Tests
The project includes a comprehensive test suite covering hashing, serialization, rate limiting, and DHT integration.
```bash
cd build
ctest --output-on-failure
# or manually: ./unit_tests
```

### Running the Application
**Interactive Mode (CLI):**
```bash
./p2pshare interactive [port]
# Default port is 8080
```

**Example Workflow:**
1.  **Start Node A:** `./p2pshare interactive 8080`
2.  **Start Node B:** `./p2pshare interactive 8081`
3.  **Bootstrap:** In Node B: `dht_bootstrap 127.0.0.1 8080`
4.  **Share:** In Node A: `share my_file.txt` (Copy the Root Hash)
5.  **Download:** In Node B: `download <ROOT_HASH>`

---

## 🎓 Knowledge Showcase

This project demonstrates proficiency in:
*   **Systems Programming:** Socket programming, memory management, file I/O.
*   **Network Protocols:** Designing and implementing custom binary protocols, handling packet fragmentation/reassembly.
*   **Distributed Systems:** DHT implementation, eventual consistency, peer discovery, NAT traversal techniques.
*   **Concurrency:** Thread synchronization, race condition avoidance, async programming patterns.
*   **Cryptography:** Applied cryptography using OpenSSL (hashing, signing, verification).
*   **Software Engineering:** Unit testing (GoogleTest), dependency management (CMake), modular design.

## 🔮 Future Improvements
*   **Full WebRTC Support:** For browser-based clients.
*   **Merkle Trees:** For verifying large files with smaller proof overhead.
*   **Graphical User Interface (GUI):** Using Qt or Dear ImGui.
*   **Metrics Exporter:** Prometheus endpoint for monitoring network health.
