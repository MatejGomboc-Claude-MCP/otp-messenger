# OTP Messenger Developer Guide (Pad-Based Architecture)

This document provides implementation details and notes for developers who want to understand, modify, or extend the OTP Messenger application that uses the new pad-based architecture.

## Architecture Overview

OTP Messenger follows a modular design with clear separation of concerns:

```
OTPMessenger
├── src/
│   ├── main.cpp                  # Application entry point
│   ├── mainwindow.h/cpp          # Main UI
│   ├── pad_file_manager.h/cpp    # Pad-based key material management
│   ├── message_protocol.h/cpp    # Message formatting & verification
│   ├── secure_memory.h/cpp       # Secure memory management
│   ├── secure_wiper.h/cpp        # Secure data deletion
│   └── authentication.h/cpp      # Multi-factor authentication
├── resources/                    # Icons, styles, etc.
└── docs/                         # Documentation
```

### Key Classes and Their Responsibilities

1. **MainWindow**: User interface and coordination between components
   - Manages user interactions
   - Coordinates between backend components
   - Provides visual feedback

2. **PadFileManager**: Manages individual pad files
   - Handles file I/O for encrypted pad files
   - Tracks used/unused key material
   - Provides secure wiping of used material

3. **PadVaultManager**: Manages a collection of pads
   - Tracks available pads and their usage
   - Handles metadata for all pads
   - Provides pad selection for messages

4. **MessageProtocol**: Handles message formatting and verification
   - Implements OTP encryption/decryption with MACs
   - Defines message format with header and integrity checking
   - Handles challenge-response and duress protocols

5. **SecureMemory**: Protects sensitive data in memory
   - Prevents key material from being paged to disk
   - Provides secure memory allocation and deallocation
   - Implements secure wiping of memory

6. **SecureWiper**: Implements secure data deletion
   - Different strategies for SSDs vs HDDs
   - Multi-pass overwriting for secure deletion
   - File metadata destruction

7. **Authentication**: Handles user identity verification
   - Implements multi-factor authentication
   - Manages password hashing
   - Handles TOTP and biometric integration

## Class Interactions

The components interact in the following way:

1. **User Interface (MainWindow)** 
   - Creates and initializes all other components
   - Handles user input and events
   - Calls appropriate methods on the backend components
   - Displays results and feedback

2. **PadVaultManager & MessageProtocol**
   - `MessageProtocol` requests key material from `PadVaultManager`
   - `PadVaultManager` selects appropriate pads and manages their lifecycle
   - After using key material, `MessageProtocol` tells `PadVaultManager` to mark it as used

3. **PadVaultManager & PadFileManager**
   - `PadVaultManager` creates and manages multiple `PadFileManager` instances
   - Each `PadFileManager` is responsible for a single pad file
   - `PadVaultManager` tracks pad usage and metadata

4. **SecureMemory & All Components**
   - All components use `SecureMemory` for handling sensitive data
   - Provides protection against data leakage through memory paging

5. **Authentication & MainWindow**
   - `MainWindow` holds a reference to `Authentication`
   - When user needs to authenticate, `MainWindow` calls methods on `Authentication`
   - `Authentication` signals success/failure back to `MainWindow`

## Pad-Based Architecture Implementation

### Pad File Format

Each pad file has the following structure:

1. **Header** (fixed size)
   - Magic identifier ("OTPPAD01")
   - Format version
   - Pad ID (unique identifier)
   - Total size of key material
   - Current position (used/unused boundary)
   - Initialization Vector for encryption
   - Authentication tag
   - Reserved space

2. **Key Material** (variable size)
   - Encrypted random bytes used for OTP encryption

### Encryption Process

1. Get a message to encrypt
2. Determine required key material size (message size + MAC size)
3. Find a pad with sufficient unused space
4. Get key material from the pad
5. Split key material into encryption key and MAC key
6. Perform XOR operation between the message and encryption key
7. Create message header with metadata
8. Generate MAC for the message header + encrypted payload
9. Mark key material as used
10. Return the complete encrypted message (header + encrypted payload + MAC)

### Decryption Process

1. Parse the encrypted message to extract header, payload, and MAC
2. Verify the header format and integrity
3. Get key material from the specified pad
4. Split key material into encryption key and MAC key
5. Verify the MAC to ensure message integrity
6. Perform XOR operation between the encrypted payload and encryption key
7. Return the decrypted message

## Message Format

Messages are structured as follows:

1. **Header**
   - Magic identifier ("OTP1")
   - Version number (1)
   - Message type
   - Pad ID
   - Key offset in pad
   - Message length
   - Timestamp
   - Sequence number
   - Reserved bytes

2. **Encrypted Payload**
   - Variable length encrypted data

3. **MAC**
   - Message Authentication Code (HMAC-SHA256)

## Security Features

### Secure Memory Management

1. **Memory Locking**
   - Uses `VirtualLock` to prevent memory from being paged to disk
   - Acquires necessary privileges to lock memory pages
   - Tracks locked memory regions for proper cleanup

2. **Secure Zeroing**
   - Multiple overwrite passes to prevent data recovery
   - Uses volatile pointers to prevent compiler optimization
   - Memory barriers to ensure completion of writes

### Secure Wiping

1. **Storage Type Detection**
   - Detects if storage is SSD or HDD
   - Uses different strategies based on storage type

2. **HDD Wiping**
   - Multi-pass overwriting with different patterns
   - Zero pass, one pass, random pass, final zero pass
   - Direct writes with flushing to ensure data reaches disk

3. **SSD Handling**
   - Relies on TRIM and garbage collection for secure deletion
   - Avoids excessive writes that could damage the SSD

4. **Metadata Destruction**
   - Renames files multiple times to obscure file system entries
   - Resets file timestamps to default values
   - Changes file permissions

### MAC Generation

1. **Data Authentication**
   - Combines message header and encrypted payload
   - Uses HMAC-SHA256 with a unique key for each message
   - Protects against message tampering and replay attacks

2. **Constant-Time Verification**
   - Uses time-invariant comparison to prevent timing attacks
   - Compares all bytes regardless of first mismatch

## Contributing Guidelines

When contributing to the pad-based architecture:

1. **Memory Management**
   - Always use `SecureBuffer` for sensitive data
   - Avoid copying sensitive data unnecessarily
   - Be mindful of object lifetimes and cleanup

2. **Error Handling**
   - Use exceptions for serious errors
   - Return false/empty for recoverable errors
   - Provide meaningful error messages

3. **Thread Safety**
   - Use appropriate synchronization for shared resources
   - PadVaultManager and PadFileManager methods should be thread-safe

4. **Security Best Practices**
   - Never reuse key material
   - Always verify message integrity
   - Secure all sensitive data in memory and on disk

5. **Testing**
   - Write tests for all security-critical components
   - Test both positive and negative cases
   - Verify secure deletion on different storage types

By following these guidelines, you can help maintain and improve the security of the OTP Messenger application.
