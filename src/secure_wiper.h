#ifndef SECURE_WIPER_H
#define SECURE_WIPER_H

#include <cstdint>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <Windows.h>

namespace otp {

/**
 * @brief Class for securely wiping files and data from storage.
 * 
 * Implements secure wiping techniques adapted from the permadelete project,
 * with different approaches for SSDs vs HDDs.
 */
class SecureWiper {
public:
    /**
     * @brief Securely wipe a range within a file.
     * 
     * @param filePath Path to the file
     * @param offset Offset within the file
     * @param length Length of data to wipe
     * @param passes Number of overwrite passes (default: 1)
     * @return true if successful, false otherwise
     */
    static bool securelyWipeRange(const std::filesystem::path& filePath, 
                               std::streamoff offset, 
                               std::streamsize length,
                               int passes = 1);
    
    /**
     * @brief Securely wipe an entire file.
     * 
     * @param filePath Path to the file
     * @param passes Number of overwrite passes (default: 1)
     * @param deleteAfter Whether to delete the file after wiping (default: true)
     * @return true if successful, false otherwise
     */
    static bool securelyWipeFile(const std::filesystem::path& filePath, 
                              int passes = 1,
                              bool deleteAfter = true);
    
    /**
     * @brief Detect if a storage device is an SSD.
     * 
     * @param path Path to check
     * @return true if SSD, false for HDD or unknown
     */
    static bool isStorageSSD(const std::filesystem::path& path);
    
    /**
     * @brief Destroy file metadata by renaming and resetting timestamps.
     * 
     * @param filePath Path to the file
     * @param renameRounds Number of times to rename (default: 5)
     * @return true if successful, false otherwise
     */
    static bool destroyFileMetadata(std::filesystem::path& filePath, int renameRounds = 5);

private:
    // Constants
    static constexpr size_t MAX_BUFFER_SIZE = 1024 * 1024; // 1MB buffer
    
    // Helper methods
    static bool overwriteWithPattern(std::fstream& file, 
                                  std::streamoff offset, 
                                  std::streamsize length,
                                  uint8_t pattern);
    
    static bool overwriteWithRandom(std::fstream& file, 
                                 std::streamoff offset, 
                                 std::streamsize length);
    
    // Windows-specific SSD detection
    static bool detectSSDWindows(const std::wstring& driveLetter);
    
    // Get the drive letter from a path
    static std::wstring getDriveLetter(const std::filesystem::path& path);
};

} // namespace otp

#endif // SECURE_WIPER_H
