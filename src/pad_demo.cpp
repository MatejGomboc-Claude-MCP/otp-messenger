#include <iostream>
#include <string>
#include <filesystem>
#include <memory>
#include "secure_memory.h"
#include "pad_file_manager.h"
#include "message_protocol.h"
#include "secure_wiper.h"

using namespace otp;

// Simple demonstration of the pad-based architecture
int main() {
    try {
        // Create a temporary directory for the demo
        std::filesystem::path tempDir = std::filesystem::temp_directory_path() / "otp_demo";
        std::filesystem::create_directories(tempDir);
        
        std::cout << "OTP Messenger Pad-Based Architecture Demo" << std::endl;
        std::cout << "==========================================" << std::endl;
        std::cout << "Using temporary directory: " << tempDir.string() << std::endl << std::endl;
        
        // Create a PadVaultManager for Alice
        PadVaultManager aliceVault;
        
        // Initialize Alice's vault
        std::cout << "Initializing Alice's pad vault..." << std::endl;
        if (!aliceVault.initialize(tempDir / "alice_vault", "alice_password")) {
            throw std::runtime_error("Failed to initialize Alice's pad vault");
        }
        
        // Create some pads for Alice
        std::cout << "Creating pads for Alice..." << std::endl;
        if (!aliceVault.createPads(1024 * 1024, 3, "alice_password")) { // 1MB pads
            throw std::runtime_error("Failed to create pads for Alice");
        }
        
        // Create a PadVaultManager for Bob
        PadVaultManager bobVault;
        
        // Initialize Bob's vault
        std::cout << "Initializing Bob's pad vault..." << std::endl;
        if (!bobVault.initialize(tempDir / "bob_vault", "bob_password")) {
            throw std::runtime_error("Failed to initialize Bob's pad vault");
        }
        
        // In a real application, Alice and Bob would exchange pad files securely
        // For this demo, we'll create identical pads for both
        
        // Create some pads for Bob (identical to Alice's)
        std::cout << "Creating pads for Bob..." << std::endl;
        if (!bobVault.createPads(1024 * 1024, 3, "bob_password")) { // 1MB pads
            throw std::runtime_error("Failed to create pads for Bob");
        }
        
        // Create message protocols
        MessageProtocol aliceProtocol;
        MessageProtocol bobProtocol;
        
        // Alice creates a message for Bob
        std::string aliceMessage = "Hello Bob, this is a secret message from Alice!";
        std::cout << "\nAlice writes message: \"" << aliceMessage << "\"" << std::endl;
        
        SecureBuffer encryptedMessage = aliceProtocol.createTextMessage(aliceMessage, aliceVault);
        
        std::cout << "Message encrypted using pad ID: " 
                  << aliceProtocol.getMessagePadId(encryptedMessage) << std::endl;
        
        std::cout << "Message size: " << encryptedMessage.size() << " bytes" << std::endl;
        
        // Bob receives and decrypts the message
        std::cout << "\nBob receives the encrypted message..." << std::endl;
        
        MessageProtocol::MessageType messageType;
        SecureBuffer decryptedPayload;
        
        if (bobProtocol.parseMessage(encryptedMessage, bobVault, messageType, decryptedPayload)) {
            std::string decryptedText = bobProtocol.extractText(decryptedPayload);
            
            std::cout << "Message type: ";
            switch (messageType) {
                case MessageProtocol::MessageType::Text:
                    std::cout << "Text Message";
                    break;
                case MessageProtocol::MessageType::Challenge:
                    std::cout << "Challenge";
                    break;
                case MessageProtocol::MessageType::Response:
                    std::cout << "Response";
                    break;
                case MessageProtocol::MessageType::Duress:
                    std::cout << "Duress";
                    break;
                default:
                    std::cout << "Other";
                    break;
            }
            std::cout << std::endl;
            
            std::cout << "Decrypted message: \"" << decryptedText << "\"" << std::endl;
        } else {
            std::cout << "Failed to decrypt message!" << std::endl;
        }
        
        // Demonstrate challenge-response mechanism
        std::cout << "\nDemonstrating challenge-response mechanism..." << std::endl;
        
        // Alice creates a challenge for Bob
        std::string challenge = "What is the name of our project?";
        std::cout << "Alice creates challenge: \"" << challenge << "\"" << std::endl;
        
        SecureBuffer challengeMessage = aliceProtocol.createChallengeMessage(challenge, aliceVault);
        
        // Bob receives and decrypts the challenge
        if (bobProtocol.parseMessage(challengeMessage, bobVault, messageType, decryptedPayload)) {
            std::string challengeText = bobProtocol.extractText(decryptedPayload);
            std::cout << "Bob receives challenge: \"" << challengeText << "\"" << std::endl;
            
            // Bob creates a response
            std::string response = "OTP Messenger";
            std::cout << "Bob responds with: \"" << response << "\"" << std::endl;
            
            SecureBuffer responseMessage = bobProtocol.createChallengeResponse(challengeMessage, response, bobVault);
            
            // Alice receives and verifies the response
            if (aliceProtocol.parseMessage(responseMessage, aliceVault, messageType, decryptedPayload)) {
                std::string responseText = aliceProtocol.extractText(decryptedPayload);
                std::cout << "Alice receives response: \"" << responseText << "\"" << std::endl;
                
                if (responseText == "OTP Messenger") {
                    std::cout << "Challenge-response verification successful!" << std::endl;
                } else {
                    std::cout << "Challenge-response verification failed!" << std::endl;
                }
            }
        }
        
        // Demonstrate duress message
        std::cout << "\nDemonstrating duress message..." << std::endl;
        
        // Bob is under duress and sends a covert signal to Alice
        std::string duressMessage = "Everything is fine, let's meet tomorrow as planned.";
        std::cout << "Bob is under duress but sends innocent-looking message: \"" 
                  << duressMessage << "\"" << std::endl;
        
        SecureBuffer encryptedDuressMessage = bobProtocol.createDuressMessage(duressMessage, bobVault);
        
        // Alice receives and detects duress
        if (aliceProtocol.parseMessage(encryptedDuressMessage, aliceVault, messageType, decryptedPayload)) {
            std::string receivedText = aliceProtocol.extractText(decryptedPayload);
            std::cout << "Alice receives message: \"" << receivedText << "\"" << std::endl;
            
            if (messageType == MessageProtocol::MessageType::Duress) {
                std::cout << "Alice detects that Bob is under duress!" << std::endl;
            } else {
                std::cout << "Alice does not detect duress signal." << std::endl;
            }
        }
        
        // Demonstrate pad usage and depletion
        std::cout << "\nDemonstrating pad usage tracking..." << std::endl;
        
        // Get initial available key material
        uint64_t initialKeyMaterial = aliceVault.getTotalAvailableKeyMaterial();
        std::cout << "Initial available key material: " << initialKeyMaterial << " bytes" << std::endl;
        
        // Create a large message that uses significant key material
        std::string largeMessage(10000, 'X'); // 10KB message
        SecureBuffer encryptedLargeMessage = aliceProtocol.createTextMessage(largeMessage, aliceVault);
        
        // Check remaining key material
        uint64_t remainingKeyMaterial = aliceVault.getTotalAvailableKeyMaterial();
        std::cout << "Remaining available key material: " << remainingKeyMaterial << " bytes" << std::endl;
        std::cout << "Used " << (initialKeyMaterial - remainingKeyMaterial) << " bytes of key material" << std::endl;
        
        // Clean up
        std::cout << "\nCleaning up..." << std::endl;
        aliceVault.closeAllPads();
        bobVault.closeAllPads();
        
        // Remove the temporary directory and files
        std::filesystem::remove_all(tempDir);
        
        std::cout << "\nDemo completed successfully!" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
