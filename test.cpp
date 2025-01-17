#include <iostream>
#include <vector>
#include <string>
#include <oqs/oqs.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <chrono>

class Server {
public:
    OQS_KEM *kem;
    unsigned char *public_key;
    unsigned char *private_key;
    unsigned char *key;
    unsigned char *hashed_key;

    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = EVP_aes_256_ecb();
    std::vector<unsigned char> encrypted;
    unsigned char *iv;

    Server() {
        kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
        if (!kem) {
            std::cerr << "Error initialize KEM" << std::endl;
            exit(1);
        }
    
        public_key = new unsigned char[kem->length_public_key];
        private_key = new unsigned char[kem->length_secret_key];

        if (OQS_KEM_keypair(kem, public_key, private_key) != OQS_SUCCESS) {
            std::cerr << "Error generate key pair" << std::endl;
            exit(1);
        }

        std::cout << "Server public key: ";
        for (size_t i = 0; i < kem->length_public_key; i++) {
            printf("%02x", public_key[i]);
        }
        std::cout << std::endl << std::endl;

        std::cout << "Server private key: ";
        for (size_t i = 0; i < kem->length_secret_key; i++) {
            printf("%02x", private_key[i]);
        }
        std::cout << std::endl << std::endl;
    }

    void decapsulateKey(const unsigned char *ciphertext) {
        key = new unsigned char[kem->length_shared_secret];

        if (OQS_KEM_decaps(kem, key, ciphertext, private_key) != OQS_SUCCESS) {
            std::cerr << "Error decapsulate key" << std::endl;
            exit(1);
        }

        std::cout << "Server decapsulated key: ";
        for (size_t i = 0; i < kem->length_shared_secret; i++) {
            printf("%02x", key[i]);
        }
        std::cout << std::endl << std::endl;
    }

    void SHA256Key() {
        SHA256_CTX sha256_ctx;
        hashed_key = new unsigned char[SHA256_DIGEST_LENGTH];

        if (SHA256_Init(&sha256_ctx) != 1) {
            std::cerr << "Error initialize SHA256" << std::endl;
            exit(1);
        }

        if (SHA256_Update(&sha256_ctx, key, kem->length_shared_secret) != 1) {
            std::cerr << "Error update SHA256" << std::endl;
            exit(1);
        }

        if (SHA256_Final(hashed_key, &sha256_ctx) != 1) {
            std::cerr << "Error final SHA256" << std::endl;
            exit(1);
        }

        std::cout << "Server hashed key: ";
        for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            printf("%02x", hashed_key[i]);
        }
        std::cout << std::endl << std::endl;
    }

    void encrypt(const std::string message) {
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            std::cerr << "Error initialize CTX" << std::endl;
            exit(1);
        }

        std::cout << "Original message: " << message << std::endl << std::endl;

        std::vector<unsigned char> messageInBytes;
        for (char ch : message) {
            messageInBytes.push_back(static_cast<unsigned char>(ch));
        }

        iv = new unsigned char[EVP_CIPHER_iv_length(cipher)];
        int length = 0, encrypted_length = 0;
        encrypted.resize(messageInBytes.size() + EVP_CIPHER_block_size(cipher));

        if (!RAND_bytes(iv, EVP_CIPHER_iv_length(cipher))) {
            std::cerr << "Error generate iv" << std::endl;
            exit(1);
        }

        if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key, iv) != 1) {
            std::cerr << "Error initialize encryption" << std::endl;
            exit(1);
        }

        if (EVP_EncryptUpdate(ctx, encrypted.data(), &length, messageInBytes.data(), messageInBytes.size()) != 1) {
            std::cerr << "Error update encryption" << std::endl;
            exit(1);
        }

        encrypted_length = length;

        if (EVP_EncryptFinal_ex(ctx, encrypted.data() + length, &length) != 1) {
            std::cerr << "Error final encryption" << std::endl;
            exit(1);
        }

        encrypted_length += length;
        encrypted.resize(encrypted_length);

        std::cout << "Encrypted message: ";
        for (size_t i = 0; i < encrypted_length; i++) {
            printf("%02x", encrypted[i]);
        }
        std::cout << std::endl << std::endl;
    }

    ~Server() {
        delete[] public_key;
        delete[] private_key;
        delete[] key;
        delete[] hashed_key;
        delete[] iv;
        OQS_KEM_free(kem);
        EVP_CIPHER_CTX_free(ctx);
    } 
};

class Client {
public:
    OQS_KEM *kem;
    unsigned char *key;
    unsigned char *ciphertext;
    unsigned char *hashed_key;

    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = EVP_aes_256_ecb();
    std::vector<unsigned char> decrypted;

    Client() {
        kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
        if (!kem) {
            std::cerr << "Error initialize KEM" << std:: endl;
            exit(1);
        }

        key = new unsigned char[kem->length_shared_secret];

        if (!RAND_bytes(key, kem->length_shared_secret)) {
            std::cerr << "Error generate key" << std::endl;
            exit(1);
        }

        std::cout << "Client key: ";
        for (size_t i = 0; i < kem->length_shared_secret; i++) {
            printf("%02x", key[i]);
        }
        std::cout << std::endl << std::endl;
    }

    void encapsulateKey(const unsigned char *public_key) {
        ciphertext = new unsigned char[kem->length_ciphertext];

        if (OQS_KEM_encaps(kem, ciphertext, key, public_key) != OQS_SUCCESS) {
            std::cerr << "Error encapsulate key" << std::endl;
            exit(1);
        }

        std::cout << "Client encapsulated key: ";
        for (size_t i = 0; i < kem->length_ciphertext; i++) {
            printf("%02x", ciphertext[i]);
        } 
        std::cout << std::endl << std::endl;
    }

    void SHA256Key() {
        SHA256_CTX sha256_ctx;
        hashed_key = new unsigned char[SHA256_DIGEST_LENGTH];

        if (SHA256_Init(&sha256_ctx) != 1) {
            std::cerr << "Error initialize SHA256" << std::endl;
            exit(1);
        }

        if (SHA256_Update(&sha256_ctx, key, kem->length_shared_secret) != 1) {
            std::cerr << "Error update SHA256" << std::endl;
            exit(1);
        }

        if (SHA256_Final(hashed_key, &sha256_ctx) != 1) {
            std::cerr << "Error final SHA256" << std::endl;
            exit(1);
        }

        std::cout << "Client hashed key: ";
        for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            printf("%02x", hashed_key[i]);
        }
        std::cout << std::endl << std::endl;
    }

    void decrypt(const std::vector<unsigned char> encrypted, unsigned char *iv) {
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            std::cerr << "Error initialize CTX" << std::endl;
            exit(1);
        }

        int length = 0, decrypted_length = 0;
        decrypted.resize(encrypted.size());

        if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key, iv) != 1) {
            std::cerr << "Error initialize decryption" << std::endl;
            exit(1);
        }

        if (EVP_DecryptUpdate(ctx, decrypted.data(), &length, encrypted.data(), encrypted.size()) != 1) {
            std::cerr << "Error during decryption.\n";
            exit(1);
        }

        decrypted_length = length;

        if (EVP_DecryptFinal_ex(ctx, decrypted.data() + length, &length) != 1) {
            std::cerr << "Error finalizing decryption.\n";
            exit(1);
        }

        decrypted_length += length;
        decrypted.resize(decrypted_length);

        std::string decryptedInAscii;
        for (unsigned char byte : decrypted) {
            decryptedInAscii.push_back(static_cast<char>(byte));
        }

        std::cout << "Decrypted message: " << decryptedInAscii << std::endl << std::endl;
    }

    ~Client() {
        delete[] key;
        delete[] ciphertext;
        delete[] hashed_key;
        OQS_KEM_free(kem);
        EVP_CIPHER_CTX_free(ctx);
    } 
};

int main() {
    auto start_time = std::chrono::high_resolution_clock::now();

    Server server;
    Client client;

    client.encapsulateKey(server.public_key);
    server.decapsulateKey(client.ciphertext);

    server.SHA256Key();
    client.SHA256Key();

    server.encrypt("Teacher Tu is the most handsome among all the students.");
    client.decrypt(server.encrypted, server.iv);

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> total_duration = end_time - start_time;
    std::cout << "Total execution time: " << total_duration.count() << " seconds.";

    return 0;
}