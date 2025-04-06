#ifndef ENCRYPTION_WRAPPER_H
#define ENCRYPTION_WRAPPER_H

#include <cstdint>
#include <string>
#include "secure_memory.h"

namespace otp {

/**
 * @brief Class providing encryption/decryption services for pad files.
 * 
 * This encryption wrapper provides a simple interface for AES-256 encryption
 * to protect pad files when stored on disk.
 */
class EncryptionWrapper {
public:
    /**
     * @brief Default constructor.
     */
    EncryptionWrapper();
    
    /**
     * @brief Encrypt data using a password-derived key.
     * 
     * @param data Data to encrypt
     * @param password Password for encryption
     * @param salt Salt for key derivation (optional, generated if null)
     * @param saltLength Length of salt (ignored if salt is null)
     * @param iv Initialization vector (optional, generated if null)
     * @param ivLength Length of IV (ignored if IV is null)
     * @return SecureBuffer containing encrypted data with salt and IV prepended
     */
    SecureBuffer encrypt(
        const SecureBuffer& data,
        const std::string& password,
        const uint8_t* salt = nullptr,
        size_t saltLength = 0,
        const uint8_t* iv = nullptr,
        size_t ivLength = 0);
    
    /**
     * @brief Decrypt data using a password-derived key.
     * 
     * @param encryptedData Encrypted data (with salt and IV prepended)
     * @param password Password for decryption
     * @return SecureBuffer containing decrypted data
     */
    SecureBuffer decrypt(
        const SecureBuffer& encryptedData,
        const std::string& password);
    
    /**
     * @brief Generate a key from a password.
     * 
     * @param password Password to derive key from
     * @param salt Salt for key derivation
     * @param saltLength Length of salt
     * @param keyLength Length of key to generate
     * @return SecureBuffer containing derived key
     */
    SecureBuffer deriveKeyFromPassword(
        const std::string& password,
        const uint8_t* salt,
        size_t saltLength,
        size_t keyLength = 32);
    
    /**
     * @brief Generate random data.
     * 
     * @param length Length of data to generate
     * @return SecureBuffer containing random data
     */
    SecureBuffer generateRandomData(size_t length);

private:
    // Constants
    static constexpr size_t DEFAULT_SALT_LENGTH = 16;
    static constexpr size_t DEFAULT_IV_LENGTH = 16;
    static constexpr size_t KEY_LENGTH = 32; // AES-256
    
    // Structure of encrypted data:
    // [ Salt Length (4 bytes) | Salt | IV Length (4 bytes) | IV | Encrypted Data ]
    
    // Helper methods
    SecureBuffer aesEncrypt(
        const SecureBuffer& data,
        const SecureBuffer& key,
        const uint8_t* iv,
        size_t ivLength);
    
    SecureBuffer aesDecrypt(
        const SecureBuffer& encryptedData,
        const SecureBuffer& key,
        const uint8_t* iv,
        size_t ivLength);
};

} // namespace otp

#endif // ENCRYPTION_WRAPPER_H
