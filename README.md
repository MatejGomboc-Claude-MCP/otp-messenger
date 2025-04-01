# OTP Messenger

A hobby Qt6 C++ encrypted messenger application using One-Time Pad (OTP) encryption.

## DISCLAIMER

This software is a hobby project provided for educational and research purposes only. The creators and contributors are not responsible for any misuse, damage, or illegal activities conducted using this software.

This application implements One-Time Pad encryption which, while theoretically secure, may have practical vulnerabilities in its implementation. The software is provided "AS IS", without warranty of any kind, and should not be used for sensitive communications where professionally audited security solutions are appropriate.

By using this software, you acknowledge that:
1. You will comply with all applicable laws and regulations.
2. You accept full responsibility for your use of the software.
3. The developers cannot guarantee perfect security or absence of bugs.

This project is not intended for production use or in environments requiring high security assurance.

## Project Overview

OTP Messenger implements a theoretically unbreakable encrypted messaging system using the One-Time Pad encryption method. Keys are stored in large binary files ("codebooks") that are manually exchanged between parties through offline means (e.g., USB sticks).

### Key Features

- True One-Time Pad encryption implementation
- Qt6-based cross-platform GUI
- Secure codebook management
- Multi-factor authentication options
- Biometric authentication support
- Historically inspired verification protocols

## Historical Context

### Origins of One-Time Pad Encryption

The One-Time Pad encryption method has roots going back to the 19th century:

- **Telegraph Era Origins**: OTP was originally developed in the 19th century to securely transmit sensitive banking and financial information over telegraph lines using Morse code.

- **Vernam Cipher**: The method was formally patented in 1919 by Gilbert Vernam, an engineer at AT&T Bell Labs, although the core concepts had been in use earlier.

- **Mathematical Perfection**: In 1949, Claude Shannon (the father of information theory) mathematically proved that the One-Time Pad is unbreakable when implemented correctly - the only encryption system with this distinction.

### Historical Applications

Various organizations used One-Time Pad encryption for secure communications:

- **Physical Codebooks**: Agents were issued small, printed booklets with pages of random numbers. Our digital "codebooks" are modeled on these physical artifacts.

- **Usage Tracking**: Users would physically mark off portions of the codebook after use to prevent reuse. Our software implements this through digital tracking of key material.

- **VENONA Project**: When operators reused portions of their one-time pads during WWII and after, cryptanalysts were able to crack some messages - highlighting the critical importance of never reusing key material.

### Authentication Techniques

- **Challenge-Response Patterns**: Predetermined challenge and response phrases to verify identities, which we've implemented digitally.

- **Control Words**: Messages contained special "control words" that helped verify authenticity and integrity. Our message protocol includes similar verification mechanisms.

### Destruction Protocols

- Codebooks were designed to be quickly destroyed if compromised, often using special inks that would dissolve when exposed to water.

- Our digital implementation includes secure wiping features inspired by these emergency protocols.

## Getting Started

### Prerequisites

- Qt6 (6.2 or newer recommended)
- C++17 compatible compiler
- CMake 3.16 or newer

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

### CodeBook

Manages the key material files with historically-inspired features:
- Compartmentalization for mission-specific key sections
- Emergency destruction protocols
- Authentication sections
- Duress codes

### CryptoEngine

Handles the OTP encryption/decryption operations:
- XOR-based encryption (true OTP)
- Message Authentication Codes (MACs) for integrity
- Anti-replay protections

### MessageProtocol

Implements message formatting and verification techniques:
- Challenge-response protocols
- Code phrase verification
- Hidden duress indicators
- Key synchronization messaging

### Authentication

Multi-factor authentication system:
- Password-based authentication
- Time-based One-Time Password (TOTP)
- Biometric integration
- Hardware token support
- Tiered security levels

## Development Roadmap

### Core Encryption
- [x] Implement true random number generation for codebooks
- [x] Create codebook format and management system
- [x] Develop key synchronization mechanism
- [x] Implement message encryption/decryption using OTP

### Authentication
- [x] Implement traditional password authentication
- [x] Add 2FA support (TOTP)
- [x] Integrate biometric authentication (fingerprint, facial recognition)
- [x] Create tiered security model

### User Interface
- [ ] Design main messenger interface
- [ ] Create codebook management UI
- [ ] Implement security settings and preferences
- [ ] Add key material status indicators

### Security Enhancements
- [x] Implement secure storage for codebooks
- [x] Add message integrity verification
- [x] Develop protection against replay attacks
- [x] Create secure key depletion tracking
- [x] Implement historically-inspired security features

## Contributing

This is a hobby project and contributions are welcome. Please feel free to submit issues or pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
