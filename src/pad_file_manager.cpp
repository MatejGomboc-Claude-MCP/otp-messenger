#include "pad_file_manager.h"
#include <random>
#include <fstream>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <Windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

namespace otp {

// PadFileManager implementation

PadFileManager::PadFileManager() : isOpen(false), isModified(false) {
    // Initialize header with zeros
    memset(&header, 0, sizeof(PadFileHeader));
}

PadFileManager::~PadFileManager() {
    // Make sure to save any changes before destruction
    if (isOpen && isModified) {
        save();
    }
    
    // Secure cleanup
    if (keyMaterial.size() > 0) {
        keyMaterial.clear();
    }
    
    if (encryptionKey.size() > 0) {
        encryptionKey.clear();
    }
    
    // Clear header
    SecureMemory::secureZero(&header, sizeof(PadFileHeader));
}

bool PadFileManager::createPad(const std::filesystem::path& filePath, 
                            size_t size, 
                            const std::string& password) {
    std::lock_guard<std::mutex> lock(accessMutex);
    
    // Check if already open
    if (isOpen) {
        close();
    }
    
    try {
        // Generate random key material
        keyMaterial = generateRandomData(size);
        
        // Set up header
        std::memcpy(header.magic, "OTPPAD01", 8);
        header.version = 1;
        header.padId = generatePadId();
        header.totalSize = size;
        header.usedOffset = 0;
        
        // Generate random IV for encryption
        SecureBuffer iv = generateRandomData(16);
        std::memcpy(header.ivBytes, iv.data(), 16);
        
        // Store the file path
        padFilePath = filePath;
        
        // Create directory if it doesn't exist
        std::filesystem::create_directories(padFilePath.parent_path());
        
        // Generate encryption key from password
        encryptionKey = deriveKeyFromPassword(password, header.ivBytes, 16);
        
        // Save the pad to disk
        isOpen = true;
        isModified = true;
        if (!save()) {
            return false;
        }
        
        return true;
    }
    catch (const std::exception&) {
        return false;
    }
}

bool PadFileManager::openPad(const std::filesystem::path& filePath, const std::string& password) {
    std::lock_guard<std::mutex> lock(accessMutex);
    
    // Check if already open
    if (isOpen) {
        close();
    }
    
    try {
        // Store file path
        padFilePath = filePath;
        
        // Check if file exists
        if (!std::filesystem::exists(padFilePath)) {
            return false;
        }
        
        // Open file and read header
        std::ifstream file(padFilePath, std::ios::binary);
        if (!file) {
            return false;
        }
        
        // Read the header
        file.read(reinterpret_cast<char*>(&header), sizeof(PadFileHeader));
        if (!file) {
            return false;
        }
        
        // Verify magic number
        if (std::memcmp(header.magic, "OTPPAD01", 8) != 0) {
            return false;
        }
        
        // Derive encryption key from password and IV
        encryptionKey = deriveKeyFromPassword(password, header.ivBytes, 16);
        
        // Read and decrypt the pad content
        if (!decryptPad(password)) {
            return false;
        }
        
        isOpen = true;
        isModified = false;
        
        return true;
    }
    catch (const std::exception&) {
        return false;
    }
}

SecureBuffer PadFileManager::getKeyMaterial(size_t length, uint64_t offset) {
    std::lock_guard<std::mutex> lock(accessMutex);
    
    if (!isOpen || keyMaterial.size() == 0) {
        throw std::runtime_error("Pad not open or empty");
    }
    
    // If offset is 0, use the current offset
    if (offset == 0) {
        offset = header.usedOffset;
    }
    
    // Check if we have enough unused key material
    if (offset + length > header.totalSize) {
        throw std::runtime_error("Not enough key material available");
    }
    
    // Extract the requested portion of key material
    SecureBuffer result(length);
    std::memcpy(result.data(), keyMaterial.data() + offset, length);
    
    return result;
}

bool PadFileManager::markAsUsed(uint64_t offset, size_t length) {
    std::lock_guard<std::mutex> lock(accessMutex);
    
    if (!isOpen) {
        return false;
    }
    
    // If offset is 0, use the current position
    if (offset == 0) {
        offset = header.usedOffset;
    }
    
    // Validate parameters
    if (offset + length > header.totalSize) {
        return false;
    }
    
    // Update the used offset if we're marking from the current position
    if (offset == header.usedOffset) {
        header.usedOffset += length;
        isModified = true;
        
        // Optionally wipe the used key material
        SecureMemory::secureZero(keyMaterial.data() + offset, length);
        
        // Auto-save changes
        return save();
    }
    else if (offset + length > header.usedOffset) {
        // If we're marking beyond the current offset, update it
        header.usedOffset = offset + length;
        isModified = true;
        
        // Wipe the used key material
        SecureMemory::secureZero(keyMaterial.data() + offset, length);
        
        // Auto-save changes
        return save();
    }
    
    // If we're marking something that's already marked as used, just return true
    return true;
}

uint64_t PadFileManager::getPadId() const {
    return header.padId;
}

uint64_t PadFileManager::getUnusedSize() const {
    if (!isOpen) {
        return 0;
    }
    
    return header.totalSize - header.usedOffset;
}

uint64_t PadFileManager::getTotalSize() const {
    if (!isOpen) {
        return 0;
    }
    
    return header.totalSize;
}

bool PadFileManager::save() {
    if (!isOpen || !isModified) {
        return true; // Nothing to save
    }
    
    return encryptAndSavePad();
}

void PadFileManager::close() {
    // Save changes if needed
    if (isOpen && isModified) {
        save();
    }
    
    // Clear sensitive data
    keyMaterial.clear();
    encryptionKey.clear();
    
    // Reset header
    SecureMemory::secureZero(&header, sizeof(PadFileHeader));
    
    isOpen = false;
    isModified = false;
}

bool PadFileManager::emergencyDestroy() {
    std::lock_guard<std::mutex> lock(accessMutex);
    
    // Close the file if open
    if (isOpen) {
        close();
    }
    
    return securelyWipePadFile();
}

bool PadFileManager::encryptAndSavePad() {
    try {
        // Create or open the file for writing
        std::ofstream file(padFilePath, std::ios::binary | std::ios::trunc);
        if (!file) {
            return false;
        }
        
        // Write header
        file.write(reinterpret_cast<char*>(&header), sizeof(PadFileHeader));
        
        // Encrypt the key material
        // In a real implementation, this would use a proper encryption algorithm
        // Here's a simplified example using XOR (not secure for production!)
        SecureBuffer encryptedData(keyMaterial.size());
        
        // Simple XOR encryption (this should be replaced with proper AES encryption)
        for (size_t i = 0; i < keyMaterial.size(); i++) {
            encryptedData[i] = keyMaterial[i] ^ encryptionKey[i % encryptionKey.size()];
        }
        
        // Write encrypted data
        file.write(reinterpret_cast<char*>(encryptedData.data()), encryptedData.size());
        
        // Ensure all data is written
        file.flush();
        file.close();
        
        isModified = false;
        return true;
    }
    catch (const std::exception&) {
        return false;
    }
}

bool PadFileManager::decryptPad(const std::string& password) {
    try {
        // Open the file
        std::ifstream file(padFilePath, std::ios::binary | std::ios::ate);
        if (!file) {
            return false;
        }
        
        // Get file size
        std::streamsize fileSize = file.tellg();
        file.seekg(sizeof(PadFileHeader), std::ios::beg);
        
        // Calculate data size
        std::streamsize dataSize = fileSize - sizeof(PadFileHeader);
        if (dataSize <= 0) {
            return false;
        }
        
        // Read encrypted data
        SecureBuffer encryptedData(static_cast<size_t>(dataSize));
        file.read(reinterpret_cast<char*>(encryptedData.data()), dataSize);
        file.close();
        
        // Allocate buffer for decrypted data
        keyMaterial.resize(static_cast<size_t>(dataSize));
        
        // Simple XOR decryption (this should be replaced with proper AES decryption)
        for (size_t i = 0; i < dataSize; i++) {
            keyMaterial[i] = encryptedData[i] ^ encryptionKey[i % encryptionKey.size()];
        }
        
        return true;
    }
    catch (const std::exception&) {
        return false;
    }
}

SecureBuffer PadFileManager::deriveKeyFromPassword(
    const std::string& password, 
    const uint8_t* salt, 
    size_t saltLength) {
    
    // In a real implementation, this would use PBKDF2 or Argon2
    // For simplicity, we'll use a basic key derivation approach here
    
    // Create a 32-byte key (256 bits)
    SecureBuffer derivedKey(32);
    
    // Initialize BCrypt
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        0);
    
    if (NT_SUCCESS(status)) {
        // Create a hash
        BCRYPT_HASH_HANDLE hHash = NULL;
        status = BCryptCreateHash(
            hAlg,
            &hHash,
            NULL,
            0,
            NULL,
            0,
            0);
        
        if (NT_SUCCESS(status)) {
            // Hash the password
            status = BCryptHashData(
                hHash,
                (PUCHAR)password.c_str(),
                (ULONG)password.size(),
                0);
            
            // Hash the salt
            if (NT_SUCCESS(status)) {
                status = BCryptHashData(
                    hHash,
                    (PUCHAR)salt,
                    (ULONG)saltLength,
                    0);
            }
            
            // Finalize the hash
            if (NT_SUCCESS(status)) {
                status = BCryptFinishHash(
                    hHash,
                    derivedKey.data(),
                    (ULONG)derivedKey.size(),
                    0);
            }
            
            // Clean up
            BCryptDestroyHash(hHash);
        }
        
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    
    return derivedKey;
}

bool PadFileManager::verifyPadIntegrity() {
    // In a real implementation, we'd verify the integrity of the pad data
    // using the authTag in the header
    return true; // Simplified for this example
}

bool PadFileManager::securelyWipePadFile() {
    // Check if file exists
    if (!std::filesystem::exists(padFilePath)) {
        return true; // File already gone
    }
    
    try {
        // Get file size
        auto fileSize = std::filesystem::file_size(padFilePath);
        
        // Open file for writing
        std::fstream file(padFilePath, std::ios::binary | std::ios::in | std::ios::out);
        if (!file) {
            return false;
        }
        
        const size_t bufferSize = 1024 * 1024; // 1MB buffer
        SecureBuffer buffer(bufferSize);
        
        // Multiple overwrite passes
        for (int pass = 0; pass < 3; pass++) {
            file.seekp(0, std::ios::beg);
            
            // Pattern to write (0x00, 0xFF, random)
            uint8_t pattern = (pass == 0) ? 0x00 : (pass == 1) ? 0xFF : 0;
            
            // Fill buffer with pattern
            if (pass < 2) {
                // Fixed pattern
                std::memset(buffer.data(), pattern, buffer.size());
            } else {
                // Random pattern
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<> dis(0, 255);
                
                for (size_t i = 0; i < buffer.size(); i++) {
                    buffer[i] = static_cast<uint8_t>(dis(gen));
                }
            }
            
            // Write pattern in chunks
            size_t remaining = fileSize;
            while (remaining > 0) {
                size_t bytesToWrite = (remaining > bufferSize) ? bufferSize : remaining;
                
                file.write(reinterpret_cast<char*>(buffer.data()), bytesToWrite);
                if (!file) {
                    file.close();
                    return false;
                }
                
                // Flush to ensure data is written to disk
                file.flush();
                
                remaining -= bytesToWrite;
            }
        }
        
        // Close the file
        file.close();
        
        // Delete the file
        std::filesystem::remove(padFilePath);
        
        return true;
    }
    catch (const std::exception&) {
        return false;
    }
}

SecureBuffer PadFileManager::generateRandomData(size_t size) {
    // Create buffer for random data
    SecureBuffer buffer(size);
    
    // Use BCrypt for cryptographically secure random data
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_RNG_ALGORITHM,
        NULL,
        0);
    
    if (NT_SUCCESS(status)) {
        // Generate random data
        status = BCryptGenRandom(
            hAlg,
            buffer.data(),
            (ULONG)buffer.size(),
            0);
        
        // Clean up
        BCryptCloseAlgorithmProvider(hAlg, 0);
        
        if (NT_SUCCESS(status)) {
            return buffer;
        }
    }
    
    throw std::runtime_error("Failed to generate random data");
}

uint64_t PadFileManager::generatePadId() {
    // Generate a random 64-bit ID
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    
    // Generate ID, ensuring it's not zero (reserved)
    uint64_t id = 0;
    while (id == 0) {
        id = dis(gen);
    }
    
    return id;
}

// PadVaultManager implementation

PadVaultManager::PadVaultManager() {
    // Nothing to initialize here
}

PadVaultManager::~PadVaultManager() {
    // Close all open pads
    closeAllPads();
}

bool PadVaultManager::initialize(const std::filesystem::path& path, const std::string& password) {
    std::lock_guard<std::mutex> lock(registryMutex);
    
    // Store the vault path and password
    vaultPath = path;
    vaultPassword = password;
    
    // Create directory if it doesn't exist
    try {
        if (!std::filesystem::exists(vaultPath)) {
            std::filesystem::create_directories(vaultPath);
        }
        
        // Create metadata file if it doesn't exist
        auto metadataPath = vaultPath / "metadata.dat";
        if (!std::filesystem::exists(metadataPath)) {
            saveMetadata();
        }
        
        // Load metadata
        return loadMetadata();
    }
    catch (const std::exception&) {
        return false;
    }
}

bool PadVaultManager::createPads(size_t padSize, int count, const std::string& password) {
    std::lock_guard<std::mutex> lock(registryMutex);
    
    try {
        // Create the pads
        for (int i = 0; i < count; i++) {
            // Create pad manager
            auto padManager = std::make_unique<PadFileManager>();
            
            // Generate unique filename
            auto padId = generatePadId();
            auto filename = generatePadFilename(padId);
            auto filePath = vaultPath / filename;
            
            // Create the pad
            if (!padManager->createPad(filePath, padSize, password)) {
                return false;
            }
            
            // Add to registry
            PadMetadata metadata;
            metadata.padId = padId;
            metadata.filePath = filePath;
            metadata.totalSize = padSize;
            metadata.usedOffset = 0;
            metadata.isOpen = true;
            
            padRegistry[padId] = metadata;
            openPads[padId] = std::move(padManager);
        }
        
        // Save the updated registry
        return saveMetadata();
    }
    catch (const std::exception&) {
        return false;
    }
}

std::vector<uint64_t> PadVaultManager::findAvailablePads(size_t messageSize) {
    std::lock_guard<std::mutex> lock(registryMutex);
    
    // Refresh pad metadata first
    refreshMetadata();
    
    std::vector<uint64_t> availablePads;
    
    // Find pads with enough space
    for (const auto& pair : padRegistry) {
        const PadMetadata& metadata = pair.second;
        
        // Check if the pad has enough unused space
        if (metadata.totalSize - metadata.usedOffset >= messageSize) {
            availablePads.push_back(metadata.padId);
        }
    }
    
    return availablePads;
}

size_t PadVaultManager::getAvailablePadCount(size_t minAvailableSize) {
    std::lock_guard<std::mutex> lock(registryMutex);
    
    // Refresh metadata
    refreshMetadata();
    
    size_t count = 0;
    
    // Count pads with sufficient space
    for (const auto& pair : padRegistry) {
        const PadMetadata& metadata = pair.second;
        
        if (metadata.totalSize - metadata.usedOffset >= minAvailableSize) {
            count++;
        }
    }
    
    return count;
}

uint64_t PadVaultManager::getTotalAvailableKeyMaterial() const {
    std::lock_guard<std::mutex> lock(registryMutex);
    
    uint64_t total = 0;
    
    // Sum up all available space
    for (const auto& pair : padRegistry) {
        const PadMetadata& metadata = pair.second;
        total += (metadata.totalSize - metadata.usedOffset);
    }
    
    return total;
}

SecureBuffer PadVaultManager::getKeyMaterialFromPad(uint64_t padId, size_t length, uint64_t offset) {
    std::lock_guard<std::mutex> lock(registryMutex);
    
    // Check if the pad exists
    auto it = padRegistry.find(padId);
    if (it == padRegistry.end()) {
        throw std::runtime_error("Pad not found");
    }
    
    // Open the pad if not already open
    if (!it->second.isOpen) {
        if (!openPad(padId)) {
            throw std::runtime_error("Failed to open pad");
        }
    }
    
    // Get key material
    return openPads[padId]->getKeyMaterial(length, offset);
}

bool PadVaultManager::markPadAsUsed(uint64_t padId, uint64_t offset, size_t length) {
    std::lock_guard<std::mutex> lock(registryMutex);
    
    // Check if the pad exists
    auto it = padRegistry.find(padId);
    if (it == padRegistry.end()) {
        return false;
    }
    
    // Open the pad if not already open
    if (!it->second.isOpen) {
        if (!openPad(padId)) {
            return false;
        }
    }
    
    // Mark as used
    if (!openPads[padId]->markAsUsed(offset, length)) {
        return false;
    }
    
    // Update metadata
    it->second.usedOffset = openPads[padId]->getUnusedSize();
    
    // Save metadata
    return saveMetadata();
}

void PadVaultManager::closeAllPads() {
    std::lock_guard<std::mutex> lock(registryMutex);
    
    // Save metadata first
    saveMetadata();
    
    // Close all pads and clear the map
    for (auto& pair : openPads) {
        pair.second->close();
        
        // Update registry
        auto it = padRegistry.find(pair.first);
        if (it != padRegistry.end()) {
            it->second.isOpen = false;
        }
    }
    
    openPads.clear();
}

bool PadVaultManager::refreshMetadata() {
    // Update metadata for all open pads
    for (auto& pair : openPads) {
        uint64_t padId = pair.first;
        auto& pad = pair.second;
        
        auto it = padRegistry.find(padId);
        if (it != padRegistry.end()) {
            it->second.usedOffset = pad->getTotalSize() - pad->getUnusedSize();
        }
    }
    
    return saveMetadata();
}

bool PadVaultManager::loadMetadata() {
    auto metadataPath = vaultPath / "metadata.dat";
    
    // Check if file exists
    if (!std::filesystem::exists(metadataPath)) {
        // If not, create an empty registry
        padRegistry.clear();
        return true;
    }
    
    try {
        // Open file
        std::ifstream file(metadataPath, std::ios::binary);
        if (!file) {
            return false;
        }
        
        // Read number of entries
        uint32_t count = 0;
        file.read(reinterpret_cast<char*>(&count), sizeof(count));
        
        // Clear registry and read entries
        padRegistry.clear();
        
        for (uint32_t i = 0; i < count; i++) {
            PadMetadata metadata;
            
            // Read pad ID
            file.read(reinterpret_cast<char*>(&metadata.padId), sizeof(metadata.padId));
            
            // Read file path length and path
            uint32_t pathLength = 0;
            file.read(reinterpret_cast<char*>(&pathLength), sizeof(pathLength));
            
            std::string pathStr(pathLength, '\0');
            file.read(&pathStr[0], pathLength);
            metadata.filePath = pathStr;
            
            // Read pad info
            file.read(reinterpret_cast<char*>(&metadata.totalSize), sizeof(metadata.totalSize));
            file.read(reinterpret_cast<char*>(&metadata.usedOffset), sizeof(metadata.usedOffset));
            
            // Set as not open initially
            metadata.isOpen = false;
            
            // Add to registry
            padRegistry[metadata.padId] = metadata;
        }
        
        file.close();
        return true;
    }
    catch (const std::exception&) {
        return false;
    }
}

bool PadVaultManager::saveMetadata() {
    auto metadataPath = vaultPath / "metadata.dat";
    
    try {
        // Create directory if it doesn't exist
        std::filesystem::create_directories(metadataPath.parent_path());
        
        // Open file for writing
        std::ofstream file(metadataPath, std::ios::binary | std::ios::trunc);
        if (!file) {
            return false;
        }
        
        // Write number of entries
        uint32_t count = static_cast<uint32_t>(padRegistry.size());
        file.write(reinterpret_cast<char*>(&count), sizeof(count));
        
        // Write each entry
        for (const auto& pair : padRegistry) {
            const PadMetadata& metadata = pair.second;
            
            // Write pad ID
            file.write(reinterpret_cast<const char*>(&metadata.padId), sizeof(metadata.padId));
            
            // Write file path
            std::string pathStr = metadata.filePath.string();
            uint32_t pathLength = static_cast<uint32_t>(pathStr.size());
            file.write(reinterpret_cast<char*>(&pathLength), sizeof(pathLength));
            file.write(pathStr.c_str(), pathLength);
            
            // Write pad info
            file.write(reinterpret_cast<const char*>(&metadata.totalSize), sizeof(metadata.totalSize));
            file.write(reinterpret_cast<const char*>(&metadata.usedOffset), sizeof(metadata.usedOffset));
        }
        
        file.close();
        return true;
    }
    catch (const std::exception&) {
        return false;
    }
}

bool PadVaultManager::openPad(uint64_t padId) {
    // Check if the pad exists in registry
    auto it = padRegistry.find(padId);
    if (it == padRegistry.end()) {
        return false;
    }
    
    // Check if already open
    if (it->second.isOpen && openPads.find(padId) != openPads.end()) {
        return true;
    }
    
    // Create pad manager
    auto padManager = std::make_unique<PadFileManager>();
    
    // Open the pad
    if (!padManager->openPad(it->second.filePath, vaultPassword)) {
        return false;
    }
    
    // Update registry
    it->second.isOpen = true;
    
    // Add to open pads
    openPads[padId] = std::move(padManager);
    
    return true;
}

std::filesystem::path PadVaultManager::getPadFilePath(uint64_t padId) const {
    auto it = padRegistry.find(padId);
    if (it != padRegistry.end()) {
        return it->second.filePath;
    }
    
    // Return default path if not found
    return vaultPath / generatePadFilename(padId);
}

std::string PadVaultManager::generatePadFilename(uint64_t padId) {
    std::stringstream ss;
    ss << "pad_" << std::hex << std::setw(16) << std::setfill('0') << padId << ".bin";
    return ss.str();
}

} // namespace otp
