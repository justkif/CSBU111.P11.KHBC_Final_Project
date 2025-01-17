#include <openssl/rsa.h>         // For RSA functions
#include <openssl/pem.h>         // For PEM file I/O
#include <openssl/bio.h>         // For BIO operations
#include <openssl/err.h>         // For error handling
#include <iostream>              // For standard I/O
#include <vector>                // For handling byte data
#include <string>                // For string operations
#include <chrono>

// Print OpenSSL errors for debugging purposes
void print_openssl_errors() {
    ERR_print_errors_fp(stderr);
}

// Generate RSA keys and save them to files using BIO
void generate_rsa_keys(int bits, const std::string& public_key_file, const std::string& private_key_file) {
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);  // Common public exponent 65537

    // Generate the RSA key pair
    if (RSA_generate_key_ex(rsa, bits, bn, nullptr) != 1) {
        std::cerr << "Error generating RSA key pair.\n";
        print_openssl_errors();
        exit(1);
    }

    // Save the public key
    BIO* bio_pub = BIO_new_file(public_key_file.c_str(), "wb");
    PEM_write_bio_RSA_PUBKEY(bio_pub, rsa);
    BIO_free(bio_pub);

    // Save the private key
    BIO* bio_priv = BIO_new_file(private_key_file.c_str(), "wb");
    PEM_write_bio_RSAPrivateKey(bio_priv, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    BIO_free(bio_priv);

    RSA_free(rsa);
    BN_free(bn);
    std::cout << "RSA keys generated successfully.\n";
}

// Load a public key from a file using BIO
RSA* load_public_key(const std::string& public_key_file) {
    BIO* bio = BIO_new_file(public_key_file.c_str(), "rb");
    if (!bio) {
        std::cerr << "Error opening public key file.\n";
        print_openssl_errors();
        exit(1);
    }
    RSA* rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return rsa;
}

// Load a private key from a file using BIO
RSA* load_private_key(const std::string& private_key_file) {
    BIO* bio = BIO_new_file(private_key_file.c_str(), "rb");
    if (!bio) {
        std::cerr << "Error opening private key file.\n";
        print_openssl_errors();
        exit(1);
    }
    RSA* rsa = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return rsa;
}

// Encrypt data using RSA public key
std::vector<unsigned char> rsa_encrypt(RSA* rsa, const std::vector<unsigned char>& plaintext) {
    std::vector<unsigned char> ciphertext(RSA_size(rsa));
    int len = RSA_public_encrypt(plaintext.size(), plaintext.data(), ciphertext.data(), rsa, RSA_PKCS1_OAEP_PADDING);
    if (len == -1) {
        std::cerr << "Error during encryption.\n";
        print_openssl_errors();
        exit(1);
    }
    ciphertext.resize(len);
    return ciphertext;
}

// Decrypt data using RSA private key
std::vector<unsigned char> rsa_decrypt(RSA* rsa, const std::vector<unsigned char>& ciphertext) {
    std::vector<unsigned char> plaintext(RSA_size(rsa));
    int len = RSA_private_decrypt(ciphertext.size(), ciphertext.data(), plaintext.data(), rsa, RSA_PKCS1_OAEP_PADDING);
    if (len == -1) {
        std::cerr << "Error during decryption.\n";
        print_openssl_errors();
        exit(1);
    }
    plaintext.resize(len);
    return plaintext;
}

// Read a file using BIO
std::vector<unsigned char> bio_read(const std::string& filename) {
    BIO* bio = BIO_new_file(filename.c_str(), "rb");
    if (!bio) {
        std::cerr << "Error opening input file: " << filename << "\n";
        print_openssl_errors();
        exit(1);
    }

    std::vector<unsigned char> data;
    unsigned char buffer[1024];
    int bytesRead;
    while ((bytesRead = BIO_read(bio, buffer, sizeof(buffer))) > 0) {
        data.insert(data.end(), buffer, buffer + bytesRead);
    }
    BIO_free(bio);
    return data;
}

// Write a file using BIO
void bio_write(const std::string& filename, const std::vector<unsigned char>& data) {
    BIO* bio = BIO_new_file(filename.c_str(), "wb");
    if (!bio) {
        std::cerr << "Error opening output file: " << filename << "\n";
        print_openssl_errors();
        exit(1);
    }
    BIO_write(bio, data.data(), data.size());
    BIO_free(bio);
}

// Main function to handle command-line arguments
int main() {
    // Record the start time of the entire execution
    auto start_time = std::chrono::high_resolution_clock::now();

    // Step 1: Generate RSA key pair
    const std::string public_key_file = "public_key.pem";
    const std::string private_key_file = "private_key.pem";
    auto genkey_start = std::chrono::high_resolution_clock::now();
    generate_rsa_keys(2048, public_key_file, private_key_file);
    auto genkey_end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> genkey_duration = genkey_end - genkey_start;
    std::cout << "Key generation took: " << genkey_duration.count() << " seconds.\n";

    // Step 2: Load the public key
    RSA* public_key = load_public_key(public_key_file);

    // Step 3: Sample plaintext (you can modify this with your own content)
    std::string plaintext_str = "This is a secret message that will be encrypted!";
    std::vector<unsigned char> plaintext(plaintext_str.begin(), plaintext_str.end());

    // Step 4: Encrypt the data
    auto encrypt_start = std::chrono::high_resolution_clock::now();
    std::vector<unsigned char> encrypted_data = rsa_encrypt(public_key, plaintext);
    bio_write("encrypted_data.dat", encrypted_data);
    RSA_free(public_key);  // Clean up public key after use
    auto encrypt_end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> encrypt_duration = encrypt_end - encrypt_start;
    std::cout << "Encryption took: " << encrypt_duration.count() << " seconds.\n";

    std::cout << "Encryption completed. Encrypted data saved to 'encrypted_data.dat'.\n";

    // Step 5: Load the private key
    RSA* private_key = load_private_key(private_key_file);

    // Step 6: Decrypt the data
    auto decrypt_start = std::chrono::high_resolution_clock::now();
    std::vector<unsigned char> decrypted_data = rsa_decrypt(private_key, encrypted_data);
    bio_write("decrypted_data.txt", decrypted_data);
    RSA_free(private_key);  // Clean up private key after use
    auto decrypt_end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> decrypt_duration = decrypt_end - decrypt_start;
    std::cout << "Decryption took: " << decrypt_duration.count() << " seconds.\n";

    std::cout << "Decryption completed. Decrypted data saved to 'decrypted_data.txt'.\n";

    // Record the end time of the entire execution
    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> total_duration = end_time - start_time;
    std::cout << "Total execution time: " << total_duration.count() << " seconds.\n";

    return 0;
}
