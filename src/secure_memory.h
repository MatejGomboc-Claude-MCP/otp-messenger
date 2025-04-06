#ifndef SECUREMEMORY_H
#define SECUREMEMORY_H

#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>
#include <stdexcept>
#include <Windows.h>

namespace otp {

/**
 * @brief A class that provides secure memory management for sensitive data.
 * 
 * SecureMemory ensures sensitive data is not written to disk through memory paging
 * by using VirtualLock and secure wiping techniques.
 */
class SecureMemory {
public:
    /**
     * @brief Allocate a block of memory that won't be paged to disk.
     * 
     * @param size Size of memory to allocate in bytes
     * @return Pointer to allocated memory
     */
    static void* allocateSecure(size_t size);
    
    /**
     * @brief Free a block of securely allocated memory.
     * 
     * @param ptr Pointer to memory block
     * @param size Size of memory block in bytes
     */
    static void freeSecure(void* ptr, size_t size);
    
    /**
     * @brief Securely zero memory with prevention of compiler optimization.
     * 
     * @param ptr Pointer to memory
     * @param size Size of memory in bytes
     */
    static void secureZero(void* ptr, size_t size);
    
    /**
     * @brief Enable process privileges for locking memory.
     * 
     * @return true if successful, false otherwise
     */
    static bool enableLockPrivilege();
    
    /**
     * @brief Check if a pointer references secure memory.
     * 
     * @param ptr Pointer to check
     * @return true if secure, false otherwise
     */
    static bool isSecurePointer(void* ptr);

private:
    // Helper methods
    static bool insertMemoryTracker(void* ptr, size_t size);
    static bool removeMemoryTracker(void* ptr);
    
    // Memory tracking structure
    struct MemoryBlock {
        void* address;
        size_t size;
        bool locked;
    };
    
    // Static tracker of allocated memory blocks
    static std::vector<MemoryBlock> memoryBlocks;
};

/**
 * @brief Secure buffer class for storing sensitive data.
 * 
 * This class wraps secure memory allocation/deallocation with RAII principles
 * to ensure proper cleanup of sensitive data.
 */
class SecureBuffer {
public:
    /**
     * @brief Construct a secure buffer of specified size.
     * 
     * @param size Size of buffer in bytes
     */
    explicit SecureBuffer(size_t size);
    
    /**
     * @brief Construct a secure buffer from data.
     * 
     * @param data Pointer to data
     * @param size Size of data in bytes
     */
    SecureBuffer(const void* data, size_t size);
    
    /**
     * @brief Destructor that securely wipes memory.
     */
    ~SecureBuffer();
    
    /**
     * @brief Copy constructor (performs deep copy).
     */
    SecureBuffer(const SecureBuffer& other);
    
    /**
     * @brief Move constructor.
     */
    SecureBuffer(SecureBuffer&& other) noexcept;
    
    /**
     * @brief Copy assignment operator.
     */
    SecureBuffer& operator=(const SecureBuffer& other);
    
    /**
     * @brief Move assignment operator.
     */
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;
    
    /**
     * @brief Access raw buffer data.
     * 
     * @return Pointer to buffer
     */
    uint8_t* data() { return buffer; }
    
    /**
     * @brief Access raw buffer data (const version).
     * 
     * @return Const pointer to buffer
     */
    const uint8_t* data() const { return buffer; }
    
    /**
     * @brief Get buffer size.
     * 
     * @return Size in bytes
     */
    size_t size() const { return bufferSize; }
    
    /**
     * @brief Clear buffer by securely zeroing all bytes.
     */
    void clear();
    
    /**
     * @brief Resize buffer.
     * 
     * @param newSize New size in bytes
     * @param preserve Whether to preserve existing content
     */
    void resize(size_t newSize, bool preserve = true);
    
    /**
     * @brief Get element at index.
     */
    uint8_t& operator[](size_t index);
    
    /**
     * @brief Get const element at index.
     */
    const uint8_t& operator[](size_t index) const;

private:
    uint8_t* buffer;
    size_t bufferSize;
};

} // namespace otp

#endif // SECUREMEMORY_H
