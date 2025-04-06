# OTP Messenger

A cross-platform Qt6 C++ encrypted messenger application using One-Time Pad (OTP) encryption with individual pad files and message authentication.

## DISCLAIMER

This software is a hobby project provided for educational and research purposes only. The creators and contributors are not responsible for any misuse, damage, or illegal activities conducted using this software.

This application implements One-Time Pad encryption which, while theoretically secure, may have practical vulnerabilities in its implementation. The software is provided "AS IS", without warranty of any kind, and should not be used for sensitive communications where professionally audited security solutions are appropriate.

By using this software, you acknowledge that:
1. You will comply with all applicable laws and regulations.
2. You accept full responsibility for your use of the software.
3. The developers cannot guarantee perfect security or absence of bugs.

This project is not intended for production use or in environments requiring high security assurance.

## Project Overview

OTP Messenger implements a theoretically unbreakable encrypted messaging system using the One-Time Pad encryption method. Keys are stored in multiple encrypted pad files (rather than a single large codebook) that are manually exchanged between parties through offline means (e.g., USB sticks).

### Key Features

- True One-Time Pad encryption implementation
- Secure pad management with individual encrypted pad files
- Message Authentication Codes (MACs) for integrity verification
- Qt6-based cross-platform GUI
- Secure memory handling to prevent sensitive data from being paged to disk
- Multi-factor authentication options
- Biometric authentication support
- Historically inspired verification protocols
- Secure destruction of used key material

## Security Architecture

### Individual Pad Files

Instead of using a single large codebook file, OTP Messenger uses multiple smaller pad files:

- Each pad is encrypted when not in use
- Used key material is securely wiped using techniques based on the permadelete project
- Different strategies are used for SSDs vs. HDDs
- Pad files include metadata to track usage status

### Message Authentication Codes (MACs)

All messages include MACs to ensure:

- Message integrity (detecting modifications)
- Authentication (verifying sender)
- Protection against replay attacks

### Memory Protection

Special care is taken to prevent sensitive data from being paged to disk:

- Memory locking using Windows VirtualLock
- Secure zeroing of memory with compiler optimization prevention
- Careful buffer management

### Historical Context Influences

Several features are inspired by historical cryptographic practices:

- **Challenge-Response Protocols**: Verification of the communication partner's identity
- **Duress Indicators**: Hidden markers to indicate the sender is under duress
- **Code Phrases**: Predefined phrases with specific meanings
- **Secure Destruction**: Methods for quickly destroying key material when compromised

## Getting Started

### Prerequisites

- Qt6 (6.2 or newer recommended)
- C++17 compatible compiler
- CMake 3.16 or newer
- Windows OS (currently) due to Windows-specific secure memory handling

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

### PadFileManager

Manages individual encrypted pad files:
- Generation of secure random key material
- Tracking used/unused portions
- Secure wiping of used key material
- Encrypted storage

### MessageProtocol

Handles message formatting with MACs:
- Different message types (text, challenge-response, etc.)
- MAC generation and verification
- Message encryption/decryption

### SecureMemory

Prevents sensitive data from being paged to disk:
- Memory locking and unlocking
- Secure wiping of memory
- Protection against compiler optimization

### SecureWiper

Secure deletion based on the permadelete project:
- Storage-aware wiping (different SSD/HDD approaches)
- Multi-pass overwriting
- File metadata destruction

## Development Roadmap

### Core Encryption
- [x] Implement individual pad file management
- [x] Add Message Authentication Codes
- [x] Implement secure memory handling
- [x] Develop storage-aware secure wiping
- [ ] Add cross-platform support

### Authentication
- [x] Implement basic password authentication
- [ ] Add 2FA support (TOTP)
- [ ] Integrate biometric authentication
- [ ] Create tiered security model

### User Interface
- [x] Design main messenger interface
- [ ] Create pad management UI
- [ ] Implement security settings and preferences
- [ ] Add key material status indicators

### Security Enhancements
- [x] Implement secure storage for pads
- [x] Add message integrity verification
- [x] Develop protection against replay attacks
- [x] Create secure key depletion tracking
- [ ] Implement more historically-inspired security features

## Contributing

This is a hobby project and contributions are welcome. Please feel free to submit issues or pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
