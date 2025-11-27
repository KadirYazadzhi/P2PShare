#include "crypto/signature.hpp"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <iostream>
#include <memory>

// Helper deleters for unique_ptr
struct BIO_Deleter { void operator()(BIO* b) { BIO_free_all(b); } };
struct EVP_PKEY_Deleter { void operator()(EVP_PKEY* p) { EVP_PKEY_free(p); } };
struct EVP_MD_CTX_Deleter { void operator()(EVP_MD_CTX* c) { EVP_MD_CTX_free(c); } };

std::pair<std::string, std::vector<uint8_t>> Signature::generate_keypair() {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL), EVP_PKEY_CTX_free);
    
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1) <= 0) {
        std::cerr << "Error initializing keygen." << std::endl;
        return {};
    }

    EVP_PKEY* pkey_raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &pkey_raw) <= 0) {
        std::cerr << "Error generating key." << std::endl;
        return {};
    }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> pkey(pkey_raw);

    // Export Private Key to PEM
    std::unique_ptr<BIO, BIO_Deleter> bio_priv(BIO_new(BIO_s_mem()));
    PEM_write_bio_PrivateKey(bio_priv.get(), pkey.get(), NULL, NULL, 0, NULL, NULL);
    
    char* priv_data;
    long priv_len = BIO_get_mem_data(bio_priv.get(), &priv_data);
    std::string private_key_pem(priv_data, priv_len);

    // Export Public Key to DER
    std::unique_ptr<BIO, BIO_Deleter> bio_pub(BIO_new(BIO_s_mem()));
    i2d_PUBKEY_bio(bio_pub.get(), pkey.get());
    
    char* pub_data;
    long pub_len = BIO_get_mem_data(bio_pub.get(), &pub_data);
    std::vector<uint8_t> public_key_der(pub_data, pub_data + pub_len);

    return {private_key_pem, public_key_der};
}

std::vector<uint8_t> Signature::sign(const std::vector<uint8_t>& data, const std::string& private_key_pem) {
    std::unique_ptr<BIO, BIO_Deleter> bio(BIO_new_mem_buf(private_key_pem.data(), private_key_pem.size()));
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> pkey(PEM_read_bio_PrivateKey(bio.get(), NULL, NULL, NULL));

    if (!pkey) {
        std::cerr << "Error loading private key." << std::endl;
        return {};
    }

    std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> ctx(EVP_MD_CTX_new());
    if (EVP_DigestSignInit(ctx.get(), NULL, EVP_sha256(), NULL, pkey.get()) <= 0) {
        return {};
    }

    size_t sig_len = 0;
    if (EVP_DigestSign(ctx.get(), NULL, &sig_len, data.data(), data.size()) <= 0) {
        return {};
    }

    std::vector<uint8_t> signature(sig_len);
    if (EVP_DigestSign(ctx.get(), signature.data(), &sig_len, data.data(), data.size()) <= 0) {
        return {};
    }
    signature.resize(sig_len);
    return signature;
}

bool Signature::verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature, const std::vector<uint8_t>& public_key_der) {
    const unsigned char* p = public_key_der.data();
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> pkey(d2i_PUBKEY(NULL, &p, public_key_der.size()));

    if (!pkey) {
        return false;
    }

    std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> ctx(EVP_MD_CTX_new());
    if (EVP_DigestVerifyInit(ctx.get(), NULL, EVP_sha256(), NULL, pkey.get()) <= 0) {
        return false;
    }

    if (EVP_DigestVerify(ctx.get(), signature.data(), signature.size(), data.data(), data.size()) == 1) {
        return true;
    }
    return false;
}
