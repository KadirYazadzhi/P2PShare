#ifndef P2P_SIGNATURE_HPP
#define P2P_SIGNATURE_HPP

#include <vector>
#include <string>
#include <optional>

class Signature {
public:
    // Generate a new EC keypair and return (private_key_pem, public_key_der)
    static std::pair<std::string, std::vector<uint8_t>> generate_keypair();

    // Sign data using private key (PEM string)
    static std::vector<uint8_t> sign(const std::vector<uint8_t>& data, const std::string& private_key_pem);

    // Verify signature using public key (DER bytes)
    static bool verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature, const std::vector<uint8_t>& public_key_der);
};

#endif // P2P_SIGNATURE_HPP
