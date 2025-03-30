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

OTP Messenger aims to implement a theoretically unbreakable encrypted messaging system using the One-Time Pad encryption method. Keys are stored in large binary files ("codebooks") that are manually exchanged between parties through offline means (e.g., USB sticks).

### Key Features

- True One-Time Pad encryption implementation
- Qt6-based cross-platform GUI
- Secure codebook management
- Multi-factor authentication options
- Biometric authentication support
- Cold War inspired verification protocols

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

## Usage Guide

### Setting Up

1. **First Launch**
   - On first launch, you'll be presented with a disclaimer that you must accept to use the application
   - You'll be prompted to create a password and set up your desired authentication method

2. **Creating a Codebook**
   - Go to File → New Codebook
   - Choose a file location and size (larger is more secure but uses more storage)
   - The application will generate random key material

3. **Exchanging Codebooks**
   - Copy your codebook file to a USB drive
   - Physically deliver it to your communication partner
   - Both parties must have identical codebook files

### Sending Messages

1. Select your codebook file
2. Type your message
3. Click "Send" to encrypt
4. Copy the encrypted message or save to a file
5. Deliver through any channel (even insecure ones)

### Receiving Messages

1. Paste the encrypted message
2. Click "Decrypt"
3. If successful, the decrypted message will be displayed

### Security Features

- **Authentication Levels**
  - Basic: Password only
  - Standard: Password + TOTP
  - High: Password + Biometric
  - Maximum: Password + Biometric + Hardware token

- **Emergency Protocols**
  - Set up an emergency destruction code
  - If entered, key material will be securely wiped

- **Duress Indicators**
  - Create special messages that appear normal but indicate duress
  - Recipients can detect these indicators

## Implemented Components

### Core Libraries

1. **CypherBook**  
   Manages the key material files with Cold War-inspired features:
   - Compartmentalization for mission-specific key sections
   - Emergency destruction protocols
   - Authentication sections
   - Duress codes

2. **CryptoEngine**  
   Handles the OTP encryption/decryption operations:
   - XOR-based encryption (true OTP)
   - Message Authentication Codes (MACs) for integrity
   - Anti-replay protections

3. **MessageProtocol**  
   Implements message formatting and verification techniques:
   - Challenge-response protocols
   - Code phrase verification
   - Hidden duress indicators
   - Key synchronization messaging

4. **Authentication**  
   Multi-factor authentication system:
   - Password-based authentication
   - Time-based One-Time Password (TOTP)
   - Biometric integration
   - Hardware token support
   - Tiered security levels

## Historical Context: Cold War Cryptography

This project is inspired by actual cryptographic methods used during the Cold War, particularly by Soviet intelligence agencies and their Western counterparts.

### Soviet OTP Systems

The Soviet Union was a dedicated user of One-Time Pad encryption, with KGB and GRU agents relying on physical codebooks for secure communications:

- **Physical Codebooks**: Agents were issued small, printed booklets with pages of random numbers. Our digital "codebooks" are modeled on these physical artifacts.

- **Usage Tracking**: Soviet agents would physically mark off portions of the codebook after use to prevent reuse. Our software implements this through digital tracking of key material.

- **VENONA Project**: When Soviet operators reused portions of their one-time pads during WWII and after, Western cryptanalysts in the VENONA project were able to crack some messages - highlighting the critical importance of never reusing key material.

### Numbers Stations

- Mysterious shortwave radio broadcasts consisting of spoken numbers or musical tones were used to transmit encoded messages to field agents. These broadcasts continue to this day (e.g., UVB-76 "The Buzzer").

- These stations transmitted OTP-encrypted messages that would be meaningless without the corresponding codebook.

### Authentication Techniques

- **Call-Response Patterns**: Field agents used predetermined challenge and response phrases to verify identities, which we've implemented digitally.

- **Control Words**: Messages contained special "control words" that helped verify authenticity and integrity. Our message protocol includes similar verification mechanisms.

### Destruction Protocols

- Codebooks were designed to be quickly destroyed if an agent was compromised. They often used special inks that would dissolve when exposed to water.

- Our digital implementation includes secure wiping features inspired by these emergency protocols.

### Dead Drops & Key Exchange

- Physical key material exchange happened through "dead drops" - predetermined locations where items could be left by one agent and retrieved by another without direct contact.

- Our application's assumption of manual codebook exchange (via USB sticks) mirrors this operational security principle.

## Development Roadmap and TODO List

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
- [x] Implement Cold War-inspired security features

## For Developers

### Architecture Overview

The application follows a modular design with clear separation of concerns:

```
OTPMessenger
├── src/
│   ├── main.cpp                  # Application entry point
│   ├── mainwindow.h/cpp          # Main UI
│   ├── cypherbook.h/cpp          # Key material management
│   ├── cryptoengine.h/cpp        # Encryption/decryption
│   ├── authentication.h/cpp      # Multi-factor authentication
│   └── messageprotocol.h/cpp     # Message formatting & verification
├── resources/                    # Icons, styles, etc.
└── CMakeLists.txt                # Build configuration
```

### Key Classes and Their Responsibilities

- **MainWindow**: User interface and coordination between components
- **CypherBook**: Manages storage and access to key material
- **CryptoEngine**: Performs cryptographic operations
- **Authentication**: Handles user identity verification
- **MessageProtocol**: Formats and parses messages

### Extending the Application

Here are some areas where contributors could enhance the application:

1. **UI Improvements**: The current UI is minimal and could be enhanced
2. **Additional Authentication Methods**: Support for new biometric or token types
3. **Network Transport**: Optional encrypted network transport
4. **Improved Randomness**: Enhanced entropy gathering for key generation
5. **Group Messaging**: Extensions for secure group communications

## Contributing

This is a hobby project and contributions are welcome. Please feel free to submit issues or pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
