#include <iostream>
#include <string>
#include <filesystem>
#include "secure_memory.h"
#include "pad_file_manager.h"
#include "message_protocol.h"
#include "secure_wiper.h"

using namespace otp;

// Demo application to showcase the pad-based architecture
int main(int argc, char* argv[]) {
    std::cout << "OTP Messenger Pad Demo" << std::endl;
    std::cout << "======================" << std::endl << std::endl;
    
    try {
        // Create a temporary directory for our test vault
        std::filesystem::path tempDir = std::filesystem::temp_directory_path() / "otp_demo";
        std::filesystem::create_directories(tempDir);
        std::cout << "Created temp directory: " << tempDir.string() << std::endl;
        
        // Initialize pad vault
        PadVaultManager padVault;
        std::string masterPassword = "demo-password-123";
        
        std::cout << "Initializing pad vault..." << std::endl;
        if (!padVault.initialize(tempDir, masterPassword)) {
            throw std::runtime_error("Failed to initialize pad vault");
        }
        
        // Create some pads
        const size_t padSize = 1024 * 1024; // 1MB pads
        const int padCount = 3;
        
        std::cout << "Creating " << padCount << " pads of " << (padSize / 1024) << "KB each..." << std::endl;
        if (!padVault.createPads(padSize, padCount, masterPassword)) {
            throw std::runtime_error("Failed to create pads");
        }
        
        // Show available pads
        std::cout << "Available pads: " << padVault.getAvailablePadCount() << std::endl;
        std::cout << "Total available key material: " << padVault.getTotalAvailableKeyMaterial() << " bytes" << std::endl;
        
        // Create a message protocol
        MessageProtocol msgProtocol;
        
        // Create a test message
        std::string message = "This is a test message using the pad-based OTP architecture with MAC authentication!";
        std::cout << "\nOriginal message: " << message << std::endl;
        
        // Encrypt the message
        SecureBuffer encryptedMsg = msgProtocol.createTextMessage(message, padVault);
        std::cout << "Encrypted message size: " << encryptedMsg.size() << " bytes" << std::endl;
        
        // Show which pad was used
        uint64_t padId = msgProtocol.getMessagePadId(encryptedMsg);
        std::cout << "Used pad ID: 0x" << std::hex << padId << std::dec << std::endl;
        
        // Decrypt the message
        MessageProtocol::MessageType type;
        SecureBuffer decryptedPayload;
        
        std::cout << "\nDecrypting message..." << std::endl;
        if (msgProtocol.parseMessage(encryptedMsg, padVault, type, decryptedPayload)) {
            std::string decryptedText = msgProtocol.extractText(decryptedPayload);
            std::cout << "Decrypted message: " << decryptedText << std::endl;
            std::cout << "Message type: " << static_cast<int>(type) << std::endl;
        } else {
            std::cout << "Failed to decrypt message!" << std::endl;
        }
        
        // Create and verify a challenge-response exchange
        std::cout << "\nDemonstrating challenge-response mechanism..." << std::endl;
        std::string challenge = "What is the password?";
        SecureBuffer challengeMsg = msgProtocol.createChallengeMessage(challenge, padVault);
        
        std::cout << "Challenge sent: " << challenge << std::endl;
        
        // Verify challenge message
        MessageProtocol::MessageType challengeType;
        SecureBuffer challengePayload;
        
        if (msgProtocol.parseMessage(challengeMsg, padVault, challengeType, challengePayload)) {
            std::string receivedChallenge = msgProtocol.extractText(challengePayload);
            std::cout << "Challenge received: " << receivedChallenge << std::endl;
            
            // Create response
            std::string response = "The password is secret!";
            SecureBuffer responseMsg = msgProtocol.createChallengeResponse(challengeMsg, response, padVault);
            
            // Verify response
            MessageProtocol::MessageType responseType;
            SecureBuffer responsePayload;
            
            if (msgProtocol.parseMessage(responseMsg, padVault, responseType, responsePayload)) {
                std::string receivedResponse = msgProtocol.extractText(responsePayload);
                std::cout << "Response received: " << receivedResponse << std::endl;
            }
        }
        
        // Check remaining key material
        std::cout << "\nRemaining key material after operations: " << padVault.getTotalAvailableKeyMaterial() 
                 << " bytes (" << (padVault.getTotalAvailableKeyMaterial() * 100.0 / (padSize * padCount)) << "%)" << std::endl;
        
        // Clean up
        std::cout << "\nCleaning up..." << std::endl;
        padVault.closeAllPads();
        
        // Securely delete the test directory
        std::filesystem::remove_all(tempDir);
        
        std::cout << "Demo completed successfully!" << std::endl;
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
