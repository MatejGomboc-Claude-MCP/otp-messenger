#include "secure_memory.h"
#include <algorithm>

namespace otp {

// Initialize static member
std::vector<SecureMemory::MemoryBlock> SecureMemory::memoryBlocks;

void* SecureMemory::allocateSecure(size_t size) {
    // Ensure we have lock privileges
    static bool privilegeEnabled = enableLockPrivilege();
    
    // Allocate memory with read/write access
    void* memory = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!memory) {
        throw std::runtime_error("Failed to allocate secure memory");
    }
    
    // Try to lock memory to prevent paging
    bool locked = false;
    if (privilegeEnabled) {
        locked = (VirtualLock(memory, size) != 0);
    }
    
    // Track this memory block
    insertMemoryTracker(memory, size);
    
    return memory;
}

void SecureMemory::freeSecure(void* ptr, size_t size) {
    if (!ptr) return;
    
    // Find the block in our tracking system
    auto it = std::find_if(memoryBlocks.begin(), memoryBlocks.end(),
                          [ptr](const MemoryBlock& block) { return block.address == ptr; });
    
    if (it != memoryBlocks.end()) {
        // Zero the memory before freeing
        secureZero(ptr, size);
        
        // Unlock if it was locked
        if (it->locked) {
            VirtualUnlock(ptr, size);
        }
        
        // Remove from tracking
        memoryBlocks.erase(it);
    }
    
    // Free the memory
    VirtualFree(ptr, 0, MEM_RELEASE);
}

void SecureMemory::secureZero(void* ptr, size_t size) {
    if (!ptr || size == 0) return;
    
    // Volatile pointer prevents compiler optimization
    volatile uint8_t* volatilePtr = static_cast<volatile uint8_t*>(ptr);
    
    // Fill with zeros
    for (size_t i = 0; i < size; i++) {
        volatilePtr[i] = 0;
    }
    
    // Memory barrier to ensure writes complete
    _mm_mfence();
}

bool SecureMemory::enableLockPrivilege() {
    // Open process token
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }
    
    // Look up the LUID for the privilege
    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_LOCK_MEMORY_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }
    
    // Adjust token privileges
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    bool result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    
    CloseHandle(hToken);
    
    // Check if it was actually assigned
    return (result && GetLastError() != ERROR_NOT_ALL_ASSIGNED);
}

bool SecureMemory::isSecurePointer(void* ptr) {
    if (!ptr) return false;
    
    // Check if this pointer is in our tracking list
    auto it = std::find_if(memoryBlocks.begin(), memoryBlocks.end(),
                          [ptr](const MemoryBlock& block) {
                              uintptr_t ptrAddr = reinterpret_cast<uintptr_t>(ptr);
                              uintptr_t blockStart = reinterpret_cast<uintptr_t>(block.address);
                              uintptr_t blockEnd = blockStart + block.size;
                              return (ptrAddr >= blockStart && ptrAddr < blockEnd);
                          });
    
    return (it != memoryBlocks.end());
}

bool SecureMemory::insertMemoryTracker(void* ptr, size_t size) {
    if (!ptr) return false;
    
    // Add to tracking structure
    MemoryBlock block;
    block.address = ptr;
    block.size = size;
    block.locked = (VirtualLock(ptr, size) != 0);
    
    memoryBlocks.push_back(block);
    return true;
}

bool SecureMemory::removeMemoryTracker(void* ptr) {
    auto it = std::find_if(memoryBlocks.begin(), memoryBlocks.end(),
                          [ptr](const MemoryBlock& block) { return block.address == ptr; });
    
    if (it != memoryBlocks.end()) {
        memoryBlocks.erase(it);
        return true;
    }
    
    return false;
}

// SecureBuffer implementation

SecureBuffer::SecureBuffer(size_t size)
    : buffer(nullptr), bufferSize(size) {
    if (size > 0) {
        buffer = static_cast<uint8_t*>(SecureMemory::allocateSecure(size));
        memset(buffer, 0, size); // Initialize to zeros
    }
}

SecureBuffer::SecureBuffer(const void* data, size_t size)
    : buffer(nullptr), bufferSize(size) {
    if (size > 0) {
        buffer = static_cast<uint8_t*>(SecureMemory::allocateSecure(size));
        if (data) {
            memcpy(buffer, data, size);
        } else {
            memset(buffer, 0, size);
        }
    }
}

SecureBuffer::~SecureBuffer() {
    if (buffer) {
        SecureMemory::freeSecure(buffer, bufferSize);
        buffer = nullptr;
        bufferSize = 0;
    }
}

SecureBuffer::SecureBuffer(const SecureBuffer& other)
    : buffer(nullptr), bufferSize(other.bufferSize) {
    if (bufferSize > 0) {
        buffer = static_cast<uint8_t*>(SecureMemory::allocateSecure(bufferSize));
        memcpy(buffer, other.buffer, bufferSize);
    }
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : buffer(other.buffer), bufferSize(other.bufferSize) {
    other.buffer = nullptr;
    other.bufferSize = 0;
}

SecureBuffer& SecureBuffer::operator=(const SecureBuffer& other) {
    if (this != &other) {
        // Clean up existing resources
        if (buffer) {
            SecureMemory::freeSecure(buffer, bufferSize);
        }
        
        // Allocate new buffer and copy data
        bufferSize = other.bufferSize;
        if (bufferSize > 0) {
            buffer = static_cast<uint8_t*>(SecureMemory::allocateSecure(bufferSize));
            memcpy(buffer, other.buffer, bufferSize);
        } else {
            buffer = nullptr;
        }
    }
    return *this;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        // Clean up existing resources
        if (buffer) {
            SecureMemory::freeSecure(buffer, bufferSize);
        }
        
        // Take ownership of other's resources
        buffer = other.buffer;
        bufferSize = other.bufferSize;
        
        // Clear other
        other.buffer = nullptr;
        other.bufferSize = 0;
    }
    return *this;
}

void SecureBuffer::clear() {
    if (buffer && bufferSize > 0) {
        SecureMemory::secureZero(buffer, bufferSize);
    }
}

void SecureBuffer::resize(size_t newSize, bool preserve) {
    if (newSize == bufferSize) return;
    
    if (newSize == 0) {
        if (buffer) {
            SecureMemory::freeSecure(buffer, bufferSize);
            buffer = nullptr;
            bufferSize = 0;
        }
        return;
    }
    
    uint8_t* newBuffer = static_cast<uint8_t*>(SecureMemory::allocateSecure(newSize));
    
    if (buffer && preserve) {
        // Copy existing data
        size_t copySize = std::min(bufferSize, newSize);
        memcpy(newBuffer, buffer, copySize);
        
        // Zero any new memory
        if (newSize > bufferSize) {
            memset(newBuffer + bufferSize, 0, newSize - bufferSize);
        }
        
        // Free old buffer
        SecureMemory::freeSecure(buffer, bufferSize);
    } else {
        // Just zero the new buffer
        memset(newBuffer, 0, newSize);
        
        // Free old buffer if any
        if (buffer) {
            SecureMemory::freeSecure(buffer, bufferSize);
        }
    }
    
    buffer = newBuffer;
    bufferSize = newSize;
}

uint8_t& SecureBuffer::operator[](size_t index) {
    if (!buffer || index >= bufferSize) {
        throw std::out_of_range("SecureBuffer: index out of range");
    }
    return buffer[index];
}

const uint8_t& SecureBuffer::operator[](size_t index) const {
    if (!buffer || index >= bufferSize) {
        throw std::out_of_range("SecureBuffer: index out of range");
    }
    return buffer[index];
}

} // namespace otp
