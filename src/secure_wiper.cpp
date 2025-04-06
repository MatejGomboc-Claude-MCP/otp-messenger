#include "secure_wiper.h"
#include <random>
#include <algorithm>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <limits>
#include "secure_memory.h"

namespace otp {

bool SecureWiper::securelyWipeRange(const std::filesystem::path& filePath, 
                                 std::streamoff offset, 
                                 std::streamsize length,
                                 int passes) {
    // Don't attempt to wipe if the storage is SSD - rely on TRIM instead
    if (isStorageSSD(filePath)) {
        return true; // Success - no action needed for SSDs
    }
    
    try {
        // Open the file for both reading and writing
        std::fstream file(filePath, std::ios::binary | std::ios::in | std::ios::out);
        if (!file) {
            return false;
        }
        
        // Get file size to validate offset and length
        file.seekg(0, std::ios::end);
        std::streamsize fileSize = file.tellg();
        
        if (offset < 0 || offset >= fileSize) {
            return false;
        }
        
        if (length <= 0 || offset + length > fileSize) {
            return false;
        }
        
        // Perform multiple overwrite passes
        for (int pass = 0; pass < passes; pass++) {
            // Different pattern for each pass:
            // Pass 0: All zeros
            // Pass 1: All ones
            // Pass 2+: Random data
            
            if (pass == 0) {
                // Zeros pass
                if (!overwriteWithPattern(file, offset, length, 0x00)) {
                    return false;
                }
            }
            else if (pass == 1) {
                // Ones pass
                if (!overwriteWithPattern(file, offset, length, 0xFF)) {
                    return false;
                }
            }
            else {
                // Random pass
                if (!overwriteWithRandom(file, offset, length)) {
                    return false;
                }
            }
        }
        
        // Final zeros pass
        if (passes > 0 && !overwriteWithPattern(file, offset, length, 0x00)) {
            return false;
        }
        
        // Ensure all data is written to disk
        file.flush();
        file.close();
        
        return true;
    }
    catch (const std::exception&) {
        return false;
    }
}

bool SecureWiper::securelyWipeFile(const std::filesystem::path& filePath, 
                                int passes,
                                bool deleteAfter) {
    try {
        // Check if file exists
        if (!std::filesystem::exists(filePath)) {
            return false;
        }
        
        // Get file size
        auto fileSize = std::filesystem::file_size(filePath);
        
        // Nothing to wipe if file is empty
        if (fileSize == 0) {
            if (deleteAfter) {
                std::filesystem::remove(filePath);
            }
            return true;
        }
        
        // If the storage is SSD, don't bother with overwriting
        if (isStorageSSD(filePath)) {
            // Just destroy metadata if needed
            std::filesystem::path tempPath = filePath;
            
            if (deleteAfter) {
                destroyFileMetadata(tempPath);
                std::filesystem::remove(tempPath);
            }
            
            return true;
        }
        
        // For HDD, wipe the entire file
        if (!securelyWipeRange(filePath, 0, fileSize, passes)) {
            return false;
        }
        
        // Reset file to zero length (truncate it)
        {
            std::fstream file(filePath, std::ios::binary | std::ios::trunc | std::ios::out);
            file.close();
        }
        
        // Destroy metadata and optionally delete
        std::filesystem::path tempPath = filePath;
        
        if (!destroyFileMetadata(tempPath)) {
            return false;
        }
        
        if (deleteAfter) {
            std::filesystem::remove(tempPath);
        }
        
        return true;
    }
    catch (const std::exception&) {
        return false;
    }
}

bool SecureWiper::isStorageSSD(const std::filesystem::path& path) {
    // Get drive letter/root
    std::wstring driveLetter = getDriveLetter(path);
    
    // On Windows, use DeviceIoControl to detect SSD
    return detectSSDWindows(driveLetter);
}

bool SecureWiper::destroyFileMetadata(std::filesystem::path& filePath, int renameRounds) {
    std::error_code ec;
    auto parent = filePath.parent_path();
    
    // Create random name generator
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 15);
    
    // Rename the file multiple times
    for (int i = 0; i < renameRounds; i++) {
        // Generate a random filename
        std::stringstream ss;
        for (int j = 0; j < 8; j++) {
            ss << std::hex << dist(gen);
        }
        ss << ".tmp";
        
        // Create the new path
        auto newPath = parent / ss.str();
        
        // Skip if new path already exists
        if (std::filesystem::exists(newPath)) {
            continue;
        }
        
        // Rename the file
        std::filesystem::rename(filePath, newPath, ec);
        if (ec) {
            return false;
        }
        
        filePath = newPath;
    }
    
    // Set file times to a default date (January 1, 2000)
    auto defaultTime = std::filesystem::file_time_type::clock::from_time_t(946684800); // 2000-01-01
    
    std::filesystem::last_write_time(filePath, defaultTime, ec);
    std::filesystem::permissions(filePath, 
                               std::filesystem::perms::owner_read | 
                               std::filesystem::perms::owner_write,
                               ec);
    
    return true;
}

bool SecureWiper::overwriteWithPattern(std::fstream& file, 
                                    std::streamoff offset, 
                                    std::streamsize length,
                                    uint8_t pattern) {
    // Set file position
    file.seekp(offset, std::ios::beg);
    if (!file) {
        return false;
    }
    
    // Create a buffer of the pattern
    size_t bufferSize = std::min(static_cast<size_t>(length), MAX_BUFFER_SIZE);
    std::vector<uint8_t> buffer(bufferSize, pattern);
    
    // Write the pattern in chunks
    std::streamsize remaining = length;
    while (remaining > 0) {
        // Calculate bytes to write
        std::streamsize bytesToWrite = std::min(remaining, static_cast<std::streamsize>(bufferSize));
        
        // Write the data
        file.write(reinterpret_cast<char*>(buffer.data()), bytesToWrite);
        if (!file) {
            return false;
        }
        
        // Flush to ensure data is written to disk
        file.flush();
        
        remaining -= bytesToWrite;
    }
    
    return true;
}

bool SecureWiper::overwriteWithRandom(std::fstream& file, 
                                   std::streamoff offset, 
                                   std::streamsize length) {
    // Set file position
    file.seekp(offset, std::ios::beg);
    if (!file) {
        return false;
    }
    
    // Create a random number generator
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned short> dist(0, 255);
    
    // Create a buffer of random data
    size_t bufferSize = std::min(static_cast<size_t>(length), MAX_BUFFER_SIZE);
    std::vector<uint8_t> buffer(bufferSize);
    
    // Fill the buffer with random data
    for (auto& byte : buffer) {
        byte = static_cast<uint8_t>(dist(gen));
    }
    
    // Write the random data in chunks
    std::streamsize remaining = length;
    while (remaining > 0) {
        // Calculate bytes to write
        std::streamsize bytesToWrite = std::min(remaining, static_cast<std::streamsize>(bufferSize));
        
        // Write the data
        file.write(reinterpret_cast<char*>(buffer.data()), bytesToWrite);
        if (!file) {
            return false;
        }
        
        // Flush to ensure data is written to disk
        file.flush();
        
        // Generate new random data for next chunk
        if (remaining > bytesToWrite) {
            for (auto& byte : buffer) {
                byte = static_cast<uint8_t>(dist(gen));
            }
        }
        
        remaining -= bytesToWrite;
    }
    
    return true;
}

bool SecureWiper::detectSSDWindows(const std::wstring& driveLetter) {
    if (driveLetter.empty()) {
        return false;
    }
    
    // Prepare the physical drive path (e.g., "\\.\C:")
    std::wstring physicalDrive = L"\\\\.\\" + driveLetter;
    if (physicalDrive.back() == L'\\') {
        physicalDrive.pop_back(); // Remove trailing backslash
    }
    
    // Open the drive
    HANDLE hDrive = CreateFileW(
        physicalDrive.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    if (hDrive == INVALID_HANDLE_VALUE) {
        return false; // Unable to open drive
    }
    
    bool isSSD = false;
    
    // Get the storage device descriptor using DeviceIoControl
    STORAGE_PROPERTY_QUERY query;
    query.PropertyId = StorageDeviceSeekPenaltyProperty;
    query.QueryType = PropertyStandardQuery;
    
    DEVICE_SEEK_PENALTY_DESCRIPTOR seekPenalty;
    DWORD bytesReturned = 0;
    
    if (DeviceIoControl(
        hDrive,
        IOCTL_STORAGE_QUERY_PROPERTY,
        &query,
        sizeof(query),
        &seekPenalty,
        sizeof(seekPenalty),
        &bytesReturned,
        NULL)) {
        
        // No seek penalty typically indicates an SSD
        isSSD = !seekPenalty.IncursSeekPenalty;
    }
    
    CloseHandle(hDrive);
    return isSSD;
}

std::wstring SecureWiper::getDriveLetter(const std::filesystem::path& path) {
    // Extract drive letter or volume root from path
    auto rootPath = path.root_path().wstring();
    
    // If empty, return empty string
    if (rootPath.empty()) {
        return L"";
    }
    
    // Return the root path (e.g., "C:\")
    return rootPath;
}

} // namespace otp
