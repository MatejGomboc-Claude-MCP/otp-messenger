#include "encryption_wrapper.h"
#include <stdexcept>
#include <cstring>
#include <Windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

namespace otp {

EncryptionWrapper::EncryptionWrapper() {
    // Nothing to initialize
}

SecureBuffer EncryptionWrapper::encrypt(
    const SecureBuffer& data,
    const std::string& password,
    const uint8_t* salt,
    size_t saltLength,
    const uint8_t* iv,
    size_t ivLength) {
    
    // Generate salt if not provided
    SecureBuffer saltBuffer;
    if (salt == nullptr) {
        saltLength = DEFAULT_SALT_LENGTH;
        saltBuffer = generateRandomData(saltLength);
        salt = saltBuffer.data();
    }
    
    // Generate IV if not provided
    SecureBuffer ivBuffer;
    if (iv == nullptr) {
        ivLength = DEFAULT_IV_LENGTH;
        ivBuffer = generateRandomData(ivLength);
        iv = ivBuffer.data();
    }
    
    // Derive key from password
    SecureBuffer key = deriveKeyFromPassword(password, salt, saltLength, KEY_LENGTH);
    
    // Encrypt the data
    SecureBuffer encryptedData = aesEncrypt(data, key, iv, ivLength);
    
    // Construct the result: [Salt Length | Salt | IV Length | IV | Encrypted Data]
    SecureBuffer result(4 + saltLength + 4 + ivLength + encryptedData.size());
    
    // Write salt length
    uint32_t saltLen32 = static_cast<uint32_t>(saltLength);
    std::memcpy(result.data(), &saltLen32, 4);
    
    // Write salt
    std::memcpy(result.data() + 4, salt, saltLength);
    
    // Write IV length
    uint32_t ivLen32 = static_cast<uint32_t>(ivLength);
    std::memcpy(result.data() + 4 + saltLength, &ivLen32, 4);
    
    // Write IV
    std::memcpy(result.data() + 4 + saltLength + 4, iv, ivLength);
    
    // Write encrypted data
    std::memcpy(result.data() + 4 + saltLength + 4 + ivLength, 
               encryptedData.data(), 
               encryptedData.size());
    
    return result;
}

SecureBuffer EncryptionWrapper::decrypt(
    const SecureBuffer& encryptedData,
    const std::string& password) {
    
    // Ensure we have at least enough data for the headers
    if (encryptedData.size() < 8) {
        throw std::runtime_error("Invalid encrypted data format");
    }
    
    // Read salt length
    uint32_t saltLength = 0;
    std::memcpy(&saltLength, encryptedData.data(), 4);
    
    // Ensure we have enough data for the salt
    if (encryptedData.size() < 4 + saltLength + 4) {
        throw std::runtime_error("Invalid encrypted data format - salt size mismatch");
    }
    
    // Read salt
    const uint8_t* salt = encryptedData.data() + 4;
    
    // Read IV length
    uint32_t ivLength = 0;
    std::memcpy(&ivLength, encryptedData.data() + 4 + saltLength, 4);
    
    // Ensure we have enough data for the IV
    if (encryptedData.size() < 4 + saltLength + 4 + ivLength) {
        throw std::runtime_error("Invalid encrypted data format - IV size mismatch");
    }
    
    // Read IV
    const uint8_t* iv = encryptedData.data() + 4 + saltLength + 4;
    
    // Calculate offset to encrypted data
    size_t dataOffset = 4 + saltLength + 4 + ivLength;
    
    // Ensure we have some encrypted data
    if (encryptedData.size() <= dataOffset) {
        throw std::runtime_error("Invalid encrypted data format - no encrypted data");
    }
    
    // Extract encrypted data
    size_t encDataSize = encryptedData.size() - dataOffset;
    SecureBuffer encDataBuffer(encDataSize);
    std::memcpy(encDataBuffer.data(), encryptedData.data() + dataOffset, encDataSize);
    
    // Derive key from password
    SecureBuffer key = deriveKeyFromPassword(password, salt, saltLength, KEY_LENGTH);
    
    // Decrypt the data
    return aesDecrypt(encDataBuffer, key, iv, ivLength);
}

SecureBuffer EncryptionWrapper::deriveKeyFromPassword(
    const std::string& password,
    const uint8_t* salt,
    size_t saltLength,
    size_t keyLength) {
    
    // Create buffer for derived key
    SecureBuffer derivedKey(keyLength);
    
    // Initialize BCrypt
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        0);
    
    if (!NT_SUCCESS(status)) {
        throw std::runtime_error("Failed to open algorithm provider");
    }
    
    // Create hash object
    BCRYPT_HASH_HANDLE hHash = NULL;
    status = BCryptCreateHash(
        hAlg,
        &hHash,
        NULL,
        0,
        NULL,
        0,
        0);
    
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to create hash object");
    }
    
    // Hash the password
    status = BCryptHashData(
        hHash,
        reinterpret_cast<PUCHAR>(const_cast<char*>(password.c_str())),
        static_cast<ULONG>(password.size()),
        0);
    
    if (!NT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to hash password");
    }
    
    // Hash the salt
    status = BCryptHashData(
        hHash,
        const_cast<PUCHAR>(salt),
        static_cast<ULONG>(saltLength),
        0);
    
    if (!NT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to hash salt");
    }
    
    // Create temporary hash output (SHA-256 is 32 bytes)
    uint8_t hashOutput[32];
    
    // Finalize the hash
    status = BCryptFinishHash(
        hHash,
        hashOutput,
        sizeof(hashOutput),
        0);
    
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    
    if (!NT_SUCCESS(status)) {
        throw std::runtime_error("Failed to finalize hash");
    }
    
    // For keys longer than 32 bytes, we need to do multiple iterations
    // (this is a simplified PBKDF2-like approach)
    std::memcpy(derivedKey.data(), hashOutput, std::min(keyLength, static_cast<size_t>(32)));
    
    if (keyLength > 32) {
        // For demonstration, we'll just repeat the hash for the remaining bytes
        // In a real implementation, you would use a proper key derivation function like PBKDF2
        for (size_t i = 32; i < keyLength; i++) {
            derivedKey[i] = hashOutput[i % 32];
        }
    }
    
    return derivedKey;
}

SecureBuffer EncryptionWrapper::generateRandomData(size_t length) {
    // Create buffer for random data
    SecureBuffer buffer(length);
    
    // Use BCrypt for cryptographically secure random data
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_RNG_ALGORITHM,
        NULL,
        0);
    
    if (!NT_SUCCESS(status)) {
        throw std::runtime_error("Failed to open RNG algorithm provider");
    }
    
    // Generate random data
    status = BCryptGenRandom(
        hAlg,
        buffer.data(),
        static_cast<ULONG>(length),
        0);
    
    BCryptCloseAlgorithmProvider(hAlg, 0);
    
    if (!NT_SUCCESS(status)) {
        throw std::runtime_error("Failed to generate random data");
    }
    
    return buffer;
}

SecureBuffer EncryptionWrapper::aesEncrypt(
    const SecureBuffer& data,
    const SecureBuffer& key,
    const uint8_t* iv,
    size_t ivLength) {
    
    // Initialize BCrypt
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0);
    
    if (!NT_SUCCESS(status)) {
        throw std::runtime_error("Failed to open AES algorithm provider");
    }
    
    // Set chaining mode to CBC
    status = BCryptSetProperty(
        hAlg,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC),
        0);
    
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to set chaining mode");
    }
    
    // Get key object size
    DWORD keyObjectSize = 0;
    DWORD bytesReturned = 0;
    status = BCryptGetProperty(
        hAlg,
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&keyObjectSize),
        sizeof(keyObjectSize),
        &bytesReturned,
        0);
    
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to get key object size");
    }
    
    // Get block size
    DWORD blockSize = 0;
    status = BCryptGetProperty(
        hAlg,
        BCRYPT_BLOCK_LENGTH,
        reinterpret_cast<PUCHAR>(&blockSize),
        sizeof(blockSize),
        &bytesReturned,
        0);
    
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to get block size");
    }
    
    // Validate IV length
    if (ivLength != blockSize) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Invalid IV length");
    }
    
    // Create key object
    SecureBuffer keyObject(keyObjectSize);
    BCRYPT_KEY_HANDLE hKey = NULL;
    
    status = BCryptGenerateSymmetricKey(
        hAlg,
        &hKey,
        keyObject.data(),
        keyObjectSize,
        const_cast<PUCHAR>(key.data()),
        static_cast<ULONG>(key.size()),
        0);
    
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to generate symmetric key");
    }
    
    // Calculate output buffer size
    DWORD encryptBufferSize = 0;
    status = BCryptEncrypt(
        hKey,
        const_cast<PUCHAR>(data.data()),
        static_cast<ULONG>(data.size()),
        NULL,
        const_cast<PUCHAR>(iv),
        static_cast<ULONG>(ivLength),
        NULL,
        0,
        &encryptBufferSize,
        BCRYPT_BLOCK_PADDING);
    
    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to calculate encryption buffer size");
    }
    
    // Create output buffer
    SecureBuffer encryptedData(encryptBufferSize);
    
    // Perform encryption
    DWORD encryptedDataSize = 0;
    status = BCryptEncrypt(
        hKey,
        const_cast<PUCHAR>(data.data()),
        static_cast<ULONG>(data.size()),
        NULL,
        const_cast<PUCHAR>(iv),
        static_cast<ULONG>(ivLength),
        encryptedData.data(),
        static_cast<ULONG>(encryptedData.size()),
        &encryptedDataSize,
        BCRYPT_BLOCK_PADDING);
    
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    
    if (!NT_SUCCESS(status)) {
        throw std::runtime_error("Failed to encrypt data");
    }
    
    // Resize buffer to actual encrypted size
    if (encryptedDataSize < encryptedData.size()) {
        encryptedData.resize(encryptedDataSize);
    }
    
    return encryptedData;
}

SecureBuffer EncryptionWrapper::aesDecrypt(
    const SecureBuffer& encryptedData,
    const SecureBuffer& key,
    const uint8_t* iv,
    size_t ivLength) {
    
    // Initialize BCrypt
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0);
    
    if (!NT_SUCCESS(status)) {
        throw std::runtime_error("Failed to open AES algorithm provider");
    }
    
    // Set chaining mode to CBC
    status = BCryptSetProperty(
        hAlg,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC),
        0);
    
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to set chaining mode");
    }
    
    // Get key object size
    DWORD keyObjectSize = 0;
    DWORD bytesReturned = 0;
    status = BCryptGetProperty(
        hAlg,
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&keyObjectSize),
        sizeof(keyObjectSize),
        &bytesReturned,
        0);
    
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to get key object size");
    }
    
    // Get block size
    DWORD blockSize = 0;
    status = BCryptGetProperty(
        hAlg,
        BCRYPT_BLOCK_LENGTH,
        reinterpret_cast<PUCHAR>(&blockSize),
        sizeof(blockSize),
        &bytesReturned,
        0);
    
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to get block size");
    }
    
    // Validate IV length
    if (ivLength != blockSize) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Invalid IV length");
    }
    
    // Create key object
    SecureBuffer keyObject(keyObjectSize);
    BCRYPT_KEY_HANDLE hKey = NULL;
    
    status = BCryptGenerateSymmetricKey(
        hAlg,
        &hKey,
        keyObject.data(),
        keyObjectSize,
        const_cast<PUCHAR>(key.data()),
        static_cast<ULONG>(key.size()),
        0);
    
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to generate symmetric key");
    }
    
    // Calculate output buffer size
    DWORD decryptBufferSize = 0;
    status = BCryptDecrypt(
        hKey,
        const_cast<PUCHAR>(encryptedData.data()),
        static_cast<ULONG>(encryptedData.size()),
        NULL,
        const_cast<PUCHAR>(iv),
        static_cast<ULONG>(ivLength),
        NULL,
        0,
        &decryptBufferSize,
        BCRYPT_BLOCK_PADDING);
    
    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("Failed to calculate decryption buffer size");
    }
    
    // Create output buffer
    SecureBuffer decryptedData(decryptBufferSize);
    
    // Perform decryption
    DWORD decryptedDataSize = 0;
    status = BCryptDecrypt(
        hKey,
        const_cast<PUCHAR>(encryptedData.data()),
        static_cast<ULONG>(encryptedData.size()),
        NULL,
        const_cast<PUCHAR>(iv),
        static_cast<ULONG>(ivLength),
        decryptedData.data(),
        static_cast<ULONG>(decryptedData.size()),
        &decryptedDataSize,
        BCRYPT_BLOCK_PADDING);
    
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    
    if (!NT_SUCCESS(status)) {
        throw std::runtime_error("Failed to decrypt data");
    }
    
    // Resize buffer to actual decrypted size
    if (decryptedDataSize < decryptedData.size()) {
        decryptedData.resize(decryptedDataSize);
    }
    
    return decryptedData;
}

} // namespace otp
