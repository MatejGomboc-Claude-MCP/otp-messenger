#include "message_protocol.h"
#include <chrono>
#include <random>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <Windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

namespace otp {

MessageProtocol::MessageProtocol() : currentSequence(0) {
    // Initialize with a random starting sequence
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dist(1, 1000000);
    currentSequence = dist(gen);
}

SecureBuffer MessageProtocol::createMessage(
    MessageType type,
    const SecureBuffer& payload,
    PadVaultManager& padVault) {
    
    // Calculate required key material
    // We need payload length + MAC_LENGTH bytes for MAC
    size_t requiredKeyLength = payload.size() + MAC_LENGTH;
    
    // Find available pad
    auto availablePads = padVault.findAvailablePads(requiredKeyLength);
    if (availablePads.empty()) {
        throw std::runtime_error("No pads available with sufficient key material");
    }
    
    // Select the first available pad (in a real app, you might want a selection strategy)
    uint64_t padId = availablePads[0];
    
    // Get key material
    SecureBuffer keyMaterial = padVault.getKeyMaterialFromPad(padId, requiredKeyLength);
    
    // Split key material into encryption key and MAC key
    SecureBuffer encryptionKey(payload.size());
    SecureBuffer macKey(MAC_LENGTH);
    
    std::memcpy(encryptionKey.data(), keyMaterial.data(), payload.size());
    std::memcpy(macKey.data(), keyMaterial.data() + payload.size(), MAC_LENGTH);
    
    // Encrypt the payload
    SecureBuffer encryptedPayload = otpEncrypt(payload, encryptionKey);
    
    // Prepare message header
    MessageHeader header;
    std::memcpy(header.magic, "OTP1", 4);
    header.version = 1;
    header.messageType = static_cast<uint8_t>(type);
    header.padId = padId;
    header.keyOffset = 0; // Will be filled by pad manager later
    header.messageLength = static_cast<uint32_t>(encryptedPayload.size());
    
    // Set timestamp
    auto now = std::chrono::system_clock::now();
    header.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    
    // Set sequence number
    header.sequenceNum = ++currentSequence;
    
    // Clear reserved bytes
    std::memset(header.reserved, 0, sizeof(header.reserved));
    
    // Generate MAC
    SecureBuffer mac = generateMAC(header, encryptedPayload, macKey);
    
    // Mark key material as used
    padVault.markPadAsUsed(padId, header.keyOffset, requiredKeyLength);
    
    // Construct final message (header + encryptedPayload + MAC)
    SecureBuffer finalMessage(sizeof(MessageHeader) + encryptedPayload.size() + mac.size());
    
    size_t offset = 0;
    std::memcpy(finalMessage.data() + offset, &header, sizeof(MessageHeader));
    offset += sizeof(MessageHeader);
    
    std::memcpy(finalMessage.data() + offset, encryptedPayload.data(), encryptedPayload.size());
    offset += encryptedPayload.size();
    
    std::memcpy(finalMessage.data() + offset, mac.data(), mac.size());
    
    return finalMessage;
}

SecureBuffer MessageProtocol::createTextMessage(const std::string& text, PadVaultManager& padVault) {
    // Convert text to SecureBuffer
    SecureBuffer payload(reinterpret_cast<const uint8_t*>(text.c_str()), text.size());
    
    // Create message
    return createMessage(MessageType::Text, payload, padVault);
}

SecureBuffer MessageProtocol::createChallengeMessage(const std::string& challenge, PadVaultManager& padVault) {
    // Convert challenge to SecureBuffer
    SecureBuffer payload(reinterpret_cast<const uint8_t*>(challenge.c_str()), challenge.size());
    
    // Create message
    return createMessage(MessageType::Challenge, payload, padVault);
}

SecureBuffer MessageProtocol::createChallengeResponse(
    const SecureBuffer& challengeMessage,
    const std::string& response,
    PadVaultManager& padVault) {
    
    // Parse the challenge message to get its details
    MessageType type;
    SecureBuffer challengePayload;
    
    if (!parseMessage(challengeMessage, padVault, type, challengePayload)) {
        throw std::runtime_error("Invalid challenge message");
    }
    
    if (type != MessageType::Challenge) {
        throw std::runtime_error("Not a challenge message");
    }
    
    // Convert response to SecureBuffer
    SecureBuffer payload(reinterpret_cast<const uint8_t*>(response.c_str()), response.size());
    
    // Create message
    return createMessage(MessageType::Response, payload, padVault);
}

SecureBuffer MessageProtocol::createDuressMessage(const std::string& text, PadVaultManager& padVault) {
    // Convert text to SecureBuffer
    SecureBuffer textBuffer(reinterpret_cast<const uint8_t*>(text.c_str()), text.size());
    
    // Add duress markers
    SecureBuffer payload = addDuressMarkers(textBuffer);
    
    // Create message
    return createMessage(MessageType::Duress, payload, padVault);
}

bool MessageProtocol::parseMessage(
    const SecureBuffer& encryptedMessage,
    PadVaultManager& padVault,
    MessageType& outType,
    SecureBuffer& outPayload) {
    
    // Check minimum size
    if (encryptedMessage.size() < sizeof(MessageHeader) + MAC_LENGTH) {
        return false;
    }
    
    // Extract header
    MessageHeader header;
    std::memcpy(&header, encryptedMessage.data(), sizeof(MessageHeader));
    
    // Validate header
    if (!validateMessageHeader(header)) {
        return false;
    }
    
    // Extract encrypted payload and MAC
    size_t encryptedPayloadSize = header.messageLength;
    size_t encryptedPayloadOffset = sizeof(MessageHeader);
    size_t macOffset = encryptedPayloadOffset + encryptedPayloadSize;
    
    if (encryptedMessage.size() < macOffset + MAC_LENGTH) {
        return false;
    }
    
    SecureBuffer encryptedPayload(encryptedPayloadSize);
    std::memcpy(encryptedPayload.data(), 
               encryptedMessage.data() + encryptedPayloadOffset, 
               encryptedPayloadSize);
    
    SecureBuffer receivedMAC(MAC_LENGTH);
    std::memcpy(receivedMAC.data(), 
               encryptedMessage.data() + macOffset, 
               MAC_LENGTH);
    
    // Get key material
    size_t requiredKeyLength = encryptedPayloadSize + MAC_LENGTH;
    SecureBuffer keyMaterial;
    
    try {
        keyMaterial = padVault.getKeyMaterialFromPad(header.padId, requiredKeyLength, header.keyOffset);
    }
    catch (const std::exception&) {
        return false;
    }
    
    // Split key material into encryption key and MAC key
    SecureBuffer encryptionKey(encryptedPayloadSize);
    SecureBuffer macKey(MAC_LENGTH);
    
    std::memcpy(encryptionKey.data(), keyMaterial.data(), encryptedPayloadSize);
    std::memcpy(macKey.data(), keyMaterial.data() + encryptedPayloadSize, MAC_LENGTH);
    
    // Verify MAC
    if (!verifyMAC(header, encryptedPayload, receivedMAC, macKey)) {
        return false;
    }
    
    // Decrypt payload
    outPayload = otpDecrypt(encryptedPayload, encryptionKey);
    
    // Set output type
    outType = static_cast<MessageType>(header.messageType);
    
    return true;
}

std::string MessageProtocol::extractText(const SecureBuffer& payload) {
    // Convert payload to string
    return std::string(reinterpret_cast<const char*>(payload.data()), payload.size());
}

bool MessageProtocol::isDuressMessage(const SecureBuffer& message) {
    // Extract header
    if (message.size() < sizeof(MessageHeader)) {
        return false;
    }
    
    MessageHeader header;
    std::memcpy(&header, message.data(), sizeof(MessageHeader));
    
    // Check if it's explicitly a duress message
    if (header.messageType == static_cast<uint8_t>(MessageType::Duress)) {
        return true;
    }
    
    // For other message types, we would need to decrypt and check for duress markers
    return false;
}

uint64_t MessageProtocol::getMessagePadId(const SecureBuffer& message) {
    // Extract header
    if (message.size() < sizeof(MessageHeader)) {
        return 0;
    }
    
    MessageHeader header;
    std::memcpy(&header, message.data(), sizeof(MessageHeader));
    
    // Validate magic number
    if (std::memcmp(header.magic, "OTP1", 4) != 0) {
        return 0;
    }
    
    return header.padId;
}

uint32_t MessageProtocol::getMessageSequence(const SecureBuffer& message) {
    // Extract header
    if (message.size() < sizeof(MessageHeader)) {
        return 0;
    }
    
    MessageHeader header;
    std::memcpy(&header, message.data(), sizeof(MessageHeader));
    
    // Validate magic number
    if (std::memcmp(header.magic, "OTP1", 4) != 0) {
        return 0;
    }
    
    return header.sequenceNum;
}

SecureBuffer MessageProtocol::generateMAC(
    const MessageHeader& header,
    const SecureBuffer& encryptedPayload,
    const SecureBuffer& macKey) {
    
    // Create a buffer containing header + encrypted payload
    SecureBuffer dataToAuthenticate(sizeof(MessageHeader) + encryptedPayload.size());
    
    std::memcpy(dataToAuthenticate.data(), &header, sizeof(MessageHeader));
    std::memcpy(dataToAuthenticate.data() + sizeof(MessageHeader), 
               encryptedPayload.data(), encryptedPayload.size());
    
    // Create a buffer for the MAC
    SecureBuffer mac(MAC_LENGTH);
    
    // Use BCrypt to compute HMAC-SHA256
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        BCRYPT_ALG_HANDLE_HMAC_FLAG);
    
    if (NT_SUCCESS(status)) {
        // Create hash object
        BCRYPT_HASH_HANDLE hHash = NULL;
        status = BCryptCreateHash(
            hAlg,
            &hHash,
            NULL,
            0,
            macKey.data(),
            static_cast<ULONG>(macKey.size()),
            0);
        
        if (NT_SUCCESS(status)) {
            // Hash data
            status = BCryptHashData(
                hHash,
                dataToAuthenticate.data(),
                static_cast<ULONG>(dataToAuthenticate.size()),
                0);
            
            if (NT_SUCCESS(status)) {
                // Finalize hash
                status = BCryptFinishHash(
                    hHash,
                    mac.data(),
                    static_cast<ULONG>(mac.size()),
                    0);
            }
            
            // Clean up hash
            BCryptDestroyHash(hHash);
        }
        
        // Clean up algorithm
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    
    return mac;
}

bool MessageProtocol::verifyMAC(
    const MessageHeader& header,
    const SecureBuffer& encryptedPayload,
    const SecureBuffer& receivedMAC,
    const SecureBuffer& macKey) {
    
    // Generate MAC for comparison
    SecureBuffer computedMAC = generateMAC(header, encryptedPayload, macKey);
    
    // Compare in constant time to prevent timing attacks
    if (computedMAC.size() != receivedMAC.size()) {
        return false;
    }
    
    // Constant-time comparison
    unsigned char result = 0;
    for (size_t i = 0; i < computedMAC.size(); i++) {
        result |= computedMAC[i] ^ receivedMAC[i];
    }
    
    return (result == 0);
}

SecureBuffer MessageProtocol::otpEncrypt(
    const SecureBuffer& plaintext,
    const SecureBuffer& keyMaterial) {
    
    // Check if key material is enough
    if (keyMaterial.size() < plaintext.size()) {
        throw std::runtime_error("Insufficient key material for encryption");
    }
    
    // Create buffer for ciphertext
    SecureBuffer ciphertext(plaintext.size());
    
    // XOR plaintext with key material (the core of OTP)
    for (size_t i = 0; i < plaintext.size(); i++) {
        ciphertext[i] = plaintext[i] ^ keyMaterial[i];
    }
    
    return ciphertext;
}

SecureBuffer MessageProtocol::otpDecrypt(
    const SecureBuffer& ciphertext,
    const SecureBuffer& keyMaterial) {
    
    // OTP decryption is identical to encryption (XOR is symmetric)
    return otpEncrypt(ciphertext, keyMaterial);
}

bool MessageProtocol::validateMessageHeader(const MessageHeader& header) {
    // Check magic number
    if (std::memcmp(header.magic, "OTP1", 4) != 0) {
        return false;
    }
    
    // Check version
    if (header.version != 1) {
        return false;
    }
    
    // Ensure message type is valid
    auto type = static_cast<MessageType>(header.messageType);
    if (type != MessageType::Text && 
        type != MessageType::File && 
        type != MessageType::KeySync && 
        type != MessageType::Challenge && 
        type != MessageType::Response && 
        type != MessageType::Duress && 
        type != MessageType::CodePhrase) {
        return false;
    }
    
    // Ensure message length is reasonable (e.g., not too large)
    if (header.messageLength == 0 || header.messageLength > 1024 * 1024) {
        return false;
    }
    
    return true;
}

SecureBuffer MessageProtocol::addDuressMarkers(const SecureBuffer& data) {
    // In a real implementation, you would add subtle patterns to indicate duress
    // For simplicity, we'll just duplicate the data and set a special byte pattern
    
    SecureBuffer result(data.size() + 4);
    
    // Copy the original data
    std::memcpy(result.data(), data.data(), data.size());
    
    // Add duress marker at the end
    // This is a simplistic approach - a real implementation would be more subtle
    result[data.size()] = 0xD;
    result[data.size() + 1] = 0xE;
    result[data.size() + 2] = 0xA;
    result[data.size() + 3] = 0xD;
    
    return result;
}

bool MessageProtocol::containsDuressMarkers(const SecureBuffer& data) {
    // Check if data has duress markers
    // This is a simplistic approach - a real implementation would be more sophisticated
    
    if (data.size() < 4) {
        return false;
    }
    
    return (data[data.size() - 4] == 0xD &&
            data[data.size() - 3] == 0xE &&
            data[data.size() - 2] == 0xA &&
            data[data.size() - 1] == 0xD);
}

} // namespace otp
