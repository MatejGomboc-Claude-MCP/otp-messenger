#ifndef MESSAGE_PROTOCOL_H
#define MESSAGE_PROTOCOL_H

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include "secure_memory.h"
#include "pad_file_manager.h"

namespace otp {

/**
 * @brief Message structure with MAC support.
 */
struct MessageHeader {
    char magic[4];           // "OTP1"
    uint8_t version;         // Message format version (1)
    uint8_t messageType;     // Type of message
    uint64_t padId;          // ID of pad used
    uint64_t keyOffset;      // Offset in pad 
    uint32_t messageLength;  // Length of encrypted message
    uint64_t timestamp;      // Message timestamp
    uint32_t sequenceNum;    // Sequence number for replay protection
    uint8_t reserved[16];    // Reserved for future use
    // Following this header is the encrypted payload, then the MAC
};

/**
 * @brief Class for handling message encryption, decryption, and verification.
 */
class MessageProtocol {
public:
    /**
     * @brief Message types.
     */
    enum class MessageType : uint8_t {
        Text = 1,
        File = 2,
        KeySync = 3,
        Challenge = 4,
        Response = 5,
        Duress = 6,
        CodePhrase = 7
    };
    
    /**
     * @brief Create a new message protocol instance.
     */
    MessageProtocol();
    
    /**
     * @brief Encrypt and format a message.
     * 
     * @param type Type of message
     * @param payload Plain message data
     * @param padVault Pad vault manager
     * @return SecureBuffer containing the complete message
     */
    SecureBuffer createMessage(
        MessageType type,
        const SecureBuffer& payload,
        PadVaultManager& padVault);
    
    /**
     * @brief Encrypt a text message.
     * 
     * @param text Text message
     * @param padVault Pad vault manager
     * @return SecureBuffer containing the complete message
     */
    SecureBuffer createTextMessage(
        const std::string& text,
        PadVaultManager& padVault);
    
    /**
     * @brief Create a challenge message for verification.
     * 
     * @param challenge Challenge text
     * @param padVault Pad vault manager
     * @return SecureBuffer containing the complete message
     */
    SecureBuffer createChallengeMessage(
        const std::string& challenge,
        PadVaultManager& padVault);
    
    /**
     * @brief Create a response to a challenge.
     * 
     * @param challengeMessage Original challenge message
     * @param response Response text
     * @param padVault Pad vault manager
     * @return SecureBuffer containing the complete message
     */
    SecureBuffer createChallengeResponse(
        const SecureBuffer& challengeMessage,
        const std::string& response,
        PadVaultManager& padVault);
    
    /**
     * @brief Create a duress message.
     * 
     * @param text Text that appears normal but indicates duress
     * @param padVault Pad vault manager
     * @return SecureBuffer containing the complete message
     */
    SecureBuffer createDuressMessage(
        const std::string& text,
        PadVaultManager& padVault);
    
    /**
     * @brief Parse and verify a received message.
     * 
     * @param encryptedMessage Encrypted message data
     * @param padVault Pad vault manager
     * @param outType Receives the message type
     * @param outPayload Receives the decrypted payload
     * @return true if message was valid and decrypted successfully
     */
    bool parseMessage(
        const SecureBuffer& encryptedMessage,
        PadVaultManager& padVault,
        MessageType& outType,
        SecureBuffer& outPayload);
    
    /**
     * @brief Extract text from a decrypted message payload.
     * 
     * @param payload Decrypted payload
     * @return Text string
     */
    std::string extractText(const SecureBuffer& payload);
    
    /**
     * @brief Check if a message appears to be a duress message.
     * 
     * @param message Message to check
     * @return true if duress is indicated
     */
    bool isDuressMessage(const SecureBuffer& message);
    
    /**
     * @brief Get the pad ID used in a message.
     * 
     * @param message Encrypted message
     * @return Pad ID or 0 if invalid
     */
    uint64_t getMessagePadId(const SecureBuffer& message);
    
    /**
     * @brief Get the sequence number from a message.
     * 
     * @param message Encrypted message
     * @return Sequence number or 0 if invalid
     */
    uint32_t getMessageSequence(const SecureBuffer& message);

private:
    // Current sequence number for outgoing messages
    uint32_t currentSequence;
    
    // MAC length in bytes
    static constexpr size_t MAC_LENGTH = 32;
    
    // Helper methods
    SecureBuffer generateMAC(
        const MessageHeader& header,
        const SecureBuffer& encryptedPayload,
        const SecureBuffer& macKey);
    
    bool verifyMAC(
        const MessageHeader& header,
        const SecureBuffer& encryptedPayload,
        const SecureBuffer& receivedMAC,
        const SecureBuffer& macKey);
    
    SecureBuffer otpEncrypt(
        const SecureBuffer& plaintext,
        const SecureBuffer& keyMaterial);
    
    SecureBuffer otpDecrypt(
        const SecureBuffer& ciphertext,
        const SecureBuffer& keyMaterial);
    
    bool validateMessageHeader(const MessageHeader& header);
    
    // Helpers for duress indicators
    SecureBuffer addDuressMarkers(const SecureBuffer& data);
    bool containsDuressMarkers(const SecureBuffer& data);
};

} // namespace otp

#endif // MESSAGE_PROTOCOL_H
