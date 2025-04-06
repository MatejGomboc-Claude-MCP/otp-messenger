# OTP Messenger

A hobby Qt6 C++ encrypted messenger application using One-Time Pad (OTP) encryption with secure pad management and MAC integrity verification.

## DISCLAIMER

This software is a hobby project provided for educational and research purposes only. The creators and contributors are not responsible for any misuse, damage, or illegal activities conducted using this software.

This application implements One-Time Pad encryption which, while theoretically secure, may have practical vulnerabilities in its implementation. The software is provided "AS IS", without warranty of any kind, and should not be used for sensitive communications where professionally audited security solutions are appropriate.

By using this software, you acknowledge that:
1. You will comply with all applicable laws and regulations.
2. You accept full responsibility for your use of the software.
3. The developers cannot guarantee perfect security or absence of bugs.

This project is not intended for production use or in environments requiring high security assurance.

## Project Overview

OTP Messenger implements a theoretically unbreakable encrypted messaging system using the One-Time Pad encryption method with a pad-based architecture. Keys are stored in multiple small encrypted files ("pads") that are managed through a secure vault system and are manually exchanged between parties through offline means (e.g., USB sticks).

### Key Features

- True One-Time Pad encryption implementation
- Pad-based key material management for better compartmentalization
- Message Authentication Codes (MACs) for integrity verification
- Multi-factor authentication options
- Secure memory management to prevent key material exposure
- Biometric authentication support
- Historically inspired verification protocols
- Secure wiping of used key material (with SSD detection)

## Pad-Based Architecture

The new pad-based architecture provides several security advantages over a traditional single codebook approach:

### Why Multiple Pads?

1. **Compartmentalization**: If one pad is compromised, others remain secure
2. **Targeted Exchange**: Only exchange the pads you need for a particular communication
3. **Independent Encryption**: Each pad can have its own encryption keys
4. **Message Size Limits**: Natural limit to key material usage per message
5. **Secure Deletion**: Easier to securely delete individual used pads

### Message Authentication Codes (MACs)

All messages include a Message Authentication Code (MAC) to ensure:

1. **Message Integrity**: Verify messages haven't been tampered with
2. **Authentication**: Confirm messages are from the expected sender
3. **Replay Protection**: Prevent message replay attacks
4. **Error Detection**: Identify transmission or storage errors

### Secure Memory Management

The application is designed to protect sensitive key material in memory:

1. **Memory Protection**: Prevents key material from being swapped to disk
2. **Secure Wiping**: Multi-pass overwriting of memory and files
3. **SSD Detection**: Special handling for SSD storage

## Getting Started

### Prerequisites

- Qt6 (6.2 or newer recommended)
- C++17 compatible compiler
- CMake 3.16 or newer
- Windows OS (for current implementation of secure memory features)

### Building from Source

1. Clone the repository:
```
git clone https://github.com/MatejGomboc-Claude-MCP/otp-messenger.git
cd otp-messenger
```

2. Create a build directory and configure with CMake:
```
mkdir build
cd build
cmake ..
```

3. Build the project:
```
cmake --build .
```

4. Run the application:
```
./OTPMessenger
```

## Documentation

Detailed documentation is available in the docs directory:

- **[User Guide](docs/USER_GUIDE.md)**: Instructions for using the application
- **[Developer Guide](docs/DEVELOPER_GUIDE.md)**: Implementation details and architecture overview
- **[UI Update Guide](docs/UI_UPDATE_GUIDE.md)**: Guide for updating the UI elements

## Core Components

### PadVaultManager and PadFileManager

Manages key material in multiple small encrypted files with:
- Encrypted pad storage
- Pad usage tracking
- Secure wiping of used key material
- Metadata management

### MessageProtocol

Implements message formatting and verification techniques:
- MAC generation and verification
- Challenge-response protocols
- Code phrase verification
- Hidden duress indicators
- Replay protection

### SecureMemory

Provides protection for sensitive data in memory:
- Memory locking to prevent paging to disk
- Secure zeroing of memory
- RAII-based memory handling

### SecureWiper

Implements secure deletion based on the permadelete approach:
- Different strategies for SSDs vs HDDs
- Multi-pass overwriting
- File metadata destruction

### Authentication

Multi-factor authentication system:
- Password-based authentication
- Time-based One-Time Password (TOTP)
- Biometric integration
- Hardware token support
- Tiered security levels

## Historical Context

### Origins of One-Time Pad Encryption

The One-Time Pad encryption method has roots going back to the 19th century:

- **Telegraph Era Origins**: OTP was originally developed in the 19th century to securely transmit sensitive banking and financial information over telegraph lines using Morse code.

- **Vernam Cipher**: The method was formally patented in 1919 by Gilbert Vernam, an engineer at AT&T Bell Labs, although the core concepts had been in use earlier.

- **Mathematical Perfection**: In 1949, Claude Shannon (the father of information theory) mathematically proved that the One-Time Pad is unbreakable when implemented correctly - the only encryption system with this distinction.

## Contributing

This is a hobby project and contributions are welcome. Please feel free to submit issues or pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
