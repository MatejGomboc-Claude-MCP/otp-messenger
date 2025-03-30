# OTP Messenger Developer Guide

This document provides implementation details and notes for developers who want to understand, modify, or extend the OTP Messenger application.

## Architecture Overview

OTP Messenger follows a modular design with clear separation of concerns:

```
OTPMessenger
├── src/
│   ├── main.cpp                  # Application entry point
│   ├── mainwindow.h/cpp          # Main UI
│   ├── codebook.h/cpp            # Key material management
│   ├── cryptoengine.h/cpp        # Encryption/decryption
│   ├── authentication.h/cpp      # Multi-factor authentication
│   └── messageprotocol.h/cpp     # Message formatting & verification
└── resources/                    # Icons, styles, etc.
```

### Key Classes and Their Responsibilities

1. **MainWindow**: User interface and coordination between components
   - Manages user interactions
   - Coordinates between backend components
   - Provides visual feedback

2. **CodeBook**: Manages storage and access to key material
   - Handles file I/O for codebook files
   - Tracks used/unused key material
   - Implements compartmentalization
   - Provides emergency protocols

3. **CryptoEngine**: Performs cryptographic operations
   - Implements OTP encryption/decryption
   - Manages message authentication codes
   - Ensures message integrity

4. **MessageProtocol**: Formats and parses messages
   - Defines message structure
   - Handles challenge-response protocols
   - Implements duress indicators
   - Manages code phrases

5. **Authentication**: Handles user identity verification
   - Implements multi-factor authentication
   - Manages password hashing
   - Handles TOTP generation/verification
   - Integrates with biometric systems

## Class Interactions

The components interact in the following way:

1. **User Interface (MainWindow)** 
   - Creates and initializes all other components
   - Handles user input and events
   - Calls appropriate methods on the backend components
   - Displays results and feedback

2. **Codebook & Crypto Engine**
   - `CryptoEngine` holds a reference to `CodeBook` to get key material
   - When encrypting/decrypting, `CryptoEngine` requests key material from `CodeBook`
   - After using key material, `CryptoEngine` tells `CodeBook` to mark it as used

3. **Message Protocol & Crypto Engine**
   - `MessageProtocol` holds a reference to `CryptoEngine`
   - When creating messages, `MessageProtocol` uses `CryptoEngine` to encrypt data
   - When parsing messages, `MessageProtocol` uses `CryptoEngine` to decrypt data

4. **Authentication & MainWindow**
   - `MainWindow` holds a reference to `Authentication`
   - When user needs to authenticate, `MainWindow` calls methods on `Authentication`
   - `Authentication` signals success/failure back to `MainWindow`

## One-Time Pad Implementation

### Encryption Process

1. Get a message to encrypt
2. Get a portion of random key material from the codebook
3. Perform XOR operation between the message and key material
4. Mark that portion of the key material as used
5. Include metadata with the encrypted message (key offset, length, etc.)
6. Generate a MAC (Message Authentication Code) for integrity
7. Return the complete encrypted message

### Decryption Process

1. Parse the encrypted message to extract metadata
2. Find the appropriate key material in the codebook using the key offset
3. Verify the MAC to ensure message integrity
4. Perform XOR operation between the encrypted data and key material
5. Return the decrypted message

## Codebook Format

The codebook is a binary file with the following structure:

1. **Header** (fixed size)
   - Format version
   - Total size of key material
   - Current position (used/unused boundary)
   - Creation timestamp
   - Header checksum
   - Compartment count
   - Authentication section information
   - Emergency code information
   - Reserved space for future use

2. **Compartment Information** (variable size)
   - Array of compartment structures, each containing:
     - Offset in the file
     - Size of compartment
     - Current position within compartment
     - Checksum
     - Lock status
     - Name

3. **Key Material** (variable size)
   - Random bytes used for encryption

## Message Format

Messages are structured as follows:

1. **Header**
   - Magic identifier ("OTP1")
   - Key offset (position in codebook)
   - Key length used
   - Timestamp

2. **Encrypted Content**
   - Message type
   - Sequence number
   - Message timestamp
   - Message payload

3. **MAC**
   - Message Authentication Code for integrity

## Authentication Implementation

### Password Authentication

1. When setting a password:
   - Generate a random salt
   - Hash the password with the salt using a strong algorithm (SHA-256)
   - Store the salt and hash

2. When verifying a password:
   - Hash the provided password with the stored salt
   - Compare with the stored hash

### TOTP Implementation

1. When setting up TOTP:
   - Generate a random secret
   - Encode it in base32 for compatibility with standard authenticator apps
   - Store the secret

2. When verifying a TOTP code:
   - Calculate the current time step (floor(current_time / period))
   - Generate the expected TOTP code using the secret and time step
   - Compare with the provided code
   - Allow for time skew by checking adjacent time steps

### Biometric Authentication

The biometric authentication is platform-dependent:
- On macOS, it uses Touch ID/Face ID
- On Windows, it uses Windows Hello
- On Android/iOS, it uses the built-in biometric APIs

## Cold War Inspired Features

### Compartmentalization

Inspired by mission-specific sections in Soviet codebooks:
- Each compartment is a separate section of key material
- Compartments can be locked/unlocked independently
- Compartments can have different purposes (regular messages, authentication, etc.)

### Emergency Protocols

Inspired by agent emergency procedures:
- Emergency destruction wipes key material securely
- Multi-pass secure deletion
- Emergency codes trigger automatic destruction

### Duress Indicators

Inspired by duress signaling techniques:
- Hidden markers in messages indicate duress
- Text appears normal but contains subtle patterns
- Can be detected by the recipient

### Challenge-Response

Inspired by agent authentication methods:
- Predefined challenges with expected responses
- Used to verify identity
- Time-limited to prevent replay attacks

### Code Phrases

Inspired by field communication techniques:
- Predefined phrases with specific meanings
- Used for quick, secure signaling
- Meaning only known to authorized parties

## Security Considerations

### Key Material Generation

True randomness is critical for OTP security:
- Ideally use hardware random number generators
- Combine multiple entropy sources when possible
- Never use standard pseudo-random number generators

### Secure Storage

Key material must be protected:
- Codebook files should be encrypted at rest
- Consider OS-level encryption
- Use secure deletion when removing key material

### Synchronization

Both parties must use the same key material:
- Include synchronization metadata in messages
- Track key material usage meticulously
- Provide clear indicators of position

### Never Reuse Key Material

The cardinal rule of OTP:
- Mark key material as used immediately
- Maintain strict tracking of used/unused boundaries
- Provide warnings when key material is running low

## Future Enhancements

### Network Transport

While the current implementation assumes manual exchange of messages (matching the Cold War inspiration), a network transport layer could be added:
- End-to-end encrypted connections
- P2P communication
- Ephemeral messaging

### Hardware Key Generation

Improve randomness with dedicated hardware:
- Hardware random number generator integration
- Quantum random number generation services
- Special-purpose random generation devices

### Group Messaging

Extend to support secure group communications:
- Shared group codebooks
- Multiple recipient management
- Key distribution protocols

### Advanced Authentication

Enhance the authentication system:
- Smart card integration
- Certificate-based authentication
- Integration with standard identity providers

## Debugging Tips

### Codebook Issues

If you're having problems with codebook files:
- Check file permissions
- Verify header integrity
- Use the key material visualizer to inspect usage

### Encryption/Decryption Failures

When messages won't encrypt or decrypt:
- Verify both parties have identical codebooks
- Check if key material has been exhausted
- Ensure proper key offsets are being used

### Authentication Problems

For authentication troubleshooting:
- Reset password if necessary
- Regenerate TOTP secrets
- Check platform-specific biometric setup

## Contributing

When contributing to OTP Messenger:
1. Follow the existing code style and architecture
2. Add comprehensive documentation for new features
3. Maintain backwards compatibility with existing codebooks
4. Preserve the core OTP security principles
5. Respect the Cold War inspirations that make this project unique
