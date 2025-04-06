#ifndef PAD_FILE_MANAGER_H
#define PAD_FILE_MANAGER_H

#include <cstdint>
#include <string>
#include <vector>
#include <filesystem>
#include <memory>
#include <unordered_map>
#include <mutex>
#include "secure_memory.h"

namespace otp {

/**
 * @brief Format of pad file header (stored encrypted on disk).
 */
struct PadFileHeader {
    char magic[8];           // "OTPPAD01"
    uint32_t version;        // Format version
    uint64_t padId;          // Unique pad identifier
    uint64_t totalSize;      // Total key material size
    uint64_t usedOffset;     // Current usage position
    uint8_t ivBytes[16];     // Initialization Vector for encryption
    uint8_t authTag[32];     // Authentication tag for header integrity
    uint8_t reserved[32];    // Reserved for future use
};

/**
 * @brief Class that manages a single pad file with encryption and access control.
 */
class PadFileManager {
public:
    /**
     * @brief Constructor.
     */
    PadFileManager();
    
    /**
     * @brief Destructor that ensures secure cleanup.
     */
    ~PadFileManager();
    
    /**
     * @brief Create a new pad with random key material.
     * 
     * @param filePath Path where to save the pad
     * @param size Size of the pad in bytes
     * @param password Password for encrypting the pad
     * @return true if successful, false otherwise
     */
    bool createPad(const std::filesystem::path& filePath, 
                  size_t size, 
                  const std::string& password);
    
    /**
     * @brief Open an existing pad file.
     * 
     * @param filePath Path to the pad file
     * @param password Password for decrypting the pad
     * @return true if successful, false otherwise
     */
    bool openPad(const std::filesystem::path& filePath,
                const std::string& password);
    
    /**
     * @brief Get key material from the pad.
     * 
     * @param length Size of key material to get
     * @param offset Specific offset (or 0 for current position)
     * @return SecureBuffer containing key material
     */
    SecureBuffer getKeyMaterial(size_t length, uint64_t offset = 0);
    
    /**
     * @brief Mark key material as used.
     * 
     * @param offset Offset in the pad
     * @param length Length of key material
     * @return true if successful, false otherwise
     */
    bool markAsUsed(uint64_t offset, size_t length);
    
    /**
     * @brief Get the unique ID of this pad.
     * 
     * @return Pad ID
     */
    uint64_t getPadId() const;
    
    /**
     * @brief Get amount of unused key material.
     * 
     * @return Bytes of unused key material
     */
    uint64_t getUnusedSize() const;
    
    /**
     * @brief Get total size of key material.
     * 
     * @return Total bytes in pad
     */
    uint64_t getTotalSize() const;
    
    /**
     * @brief Save changes to disk.
     * 
     * @return true if successful, false otherwise
     */
    bool save();
    
    /**
     * @brief Close the pad file.
     */
    void close();
    
    /**
     * @brief Securely destroy the pad (emergency).
     * 
     * @return true if successful, false otherwise
     */
    bool emergencyDestroy();

private:
    // The pad file path
    std::filesystem::path padFilePath;
    
    // Pad header and data
    PadFileHeader header;
    SecureBuffer keyMaterial;
    
    // Encryption key derived from password
    SecureBuffer encryptionKey;
    
    // State tracking
    bool isOpen;
    bool isModified;
    std::mutex accessMutex;
    
    // Helper methods
    bool encryptAndSavePad();
    bool decryptPad(const std::string& password);
    SecureBuffer deriveKeyFromPassword(const std::string& password, const uint8_t* salt, size_t saltLength);
    bool verifyPadIntegrity();
    bool securelyWipePadFile();
    
    // Generate random data
    static SecureBuffer generateRandomData(size_t size);
    
    // Generate a unique pad ID
    static uint64_t generatePadId();
};

/**
 * @brief Class that manages a collection of pads as a vault.
 */
class PadVaultManager {
public:
    /**
     * @brief Constructor.
     */
    PadVaultManager();
    
    /**
     * @brief Destructor.
     */
    ~PadVaultManager();
    
    /**
     * @brief Initialize the pad vault.
     * 
     * @param vaultPath Directory path for the vault
     * @param masterPassword Master password for encryption
     * @return true if successful, false otherwise
     */
    bool initialize(const std::filesystem::path& vaultPath, 
                   const std::string& masterPassword);
    
    /**
     * @brief Create a set of new pads.
     * 
     * @param padSize Size of each pad in bytes
     * @param count Number of pads to create
     * @param masterPassword Password for encryption
     * @return true if successful, false otherwise
     */
    bool createPads(size_t padSize, int count, 
                   const std::string& masterPassword);
    
    /**
     * @brief Find available pads for a message of specific size.
     * 
     * @param messageSize Size of message to accommodate
     * @return Vector of pad IDs that have sufficient space
     */
    std::vector<uint64_t> findAvailablePads(size_t messageSize);
    
    /**
     * @brief Get count of available pads.
     * 
     * @param minAvailableSize Minimum available size to consider a pad
     * @return Count of available pads
     */
    size_t getAvailablePadCount(size_t minAvailableSize = 0) const;
    
    /**
     * @brief Get total available key material.
     * 
     * @return Total available bytes
     */
    uint64_t getTotalAvailableKeyMaterial() const;
    
    /**
     * @brief Get key material from a specific pad.
     * 
     * @param padId ID of the pad
     * @param length Length of key material needed
     * @param offset Specific offset (0 for current position)
     * @return SecureBuffer with key material
     */
    SecureBuffer getKeyMaterialFromPad(uint64_t padId, size_t length, uint64_t offset = 0);
    
    /**
     * @brief Mark pad key material as used.
     * 
     * @param padId ID of the pad
     * @param offset Offset in the pad
     * @param length Length of key material
     * @return true if successful, false otherwise
     */
    bool markPadAsUsed(uint64_t padId, uint64_t offset, size_t length);
    
    /**
     * @brief Close all open pads.
     */
    void closeAllPads();
    
    /**
     * @brief Refresh pad metadata from disk.
     * 
     * @return true if successful, false otherwise
     */
    bool refreshMetadata();

private:
    // Vault location and metadata
    std::filesystem::path vaultPath;
    std::string vaultPassword;
    
    // Structure to track pad metadata
    struct PadMetadata {
        uint64_t padId;
        std::filesystem::path filePath;
        uint64_t totalSize;
        uint64_t usedOffset;
        bool isOpen;
    };
    
    // Map of pad ID to metadata
    std::unordered_map<uint64_t, PadMetadata> padRegistry;
    
    // Currently open pads
    std::unordered_map<uint64_t, std::unique_ptr<PadFileManager>> openPads;
    
    // Synchronization
    mutable std::mutex registryMutex;
    
    // Helper methods
    bool loadMetadata();
    bool saveMetadata();
    bool openPad(uint64_t padId);
    std::filesystem::path getPadFilePath(uint64_t padId) const;
    static std::string generatePadFilename(uint64_t padId);
};

} // namespace otp

#endif // PAD_FILE_MANAGER_H
