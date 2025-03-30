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

OTP Messenger aims to implement a theoretically unbreakable encrypted messaging system using the One-Time Pad encryption method. Keys are stored in large binary files ("cypher books") that are manually exchanged between parties through offline means (e.g., USB sticks).

### Key Features

- True One-Time Pad encryption implementation
- Qt6-based cross-platform GUI
- Secure cypher book management
- Multi-factor authentication options
- Biometric authentication support

### Cold War-Inspired Security Features

This project draws inspiration from historical Cold War-era cryptographic systems, particularly the Soviet codebook approach. Key features inspired by this era include:

- **Compartmentalized Cypher Books**: Separate sections of key material for different purposes, similar to mission-specific sections in Soviet codebooks
- **Emergency Destruction Protocol**: Quick and secure deletion of key material when compromised
- **Authentication Material**: Reserved portions of the key material for verifying the identity of the communicating parties
- **Duress Codes**: Special authentication sequences that silently indicate the user is under duress

## Development Roadmap and TODO List

### Core Encryption
- [ ] Implement true random number generation for cypher books
- [ ] Create cypher book format and management system
- [ ] Develop key synchronization mechanism
- [ ] Implement message encryption/decryption using OTP

### Authentication
- [ ] Implement traditional password authentication
- [ ] Add 2FA support (TOTP)
- [ ] Integrate biometric authentication (fingerprint, facial recognition)
- [ ] Create tiered security model

### User Interface
- [ ] Design main messenger interface
- [ ] Create cypher book management UI
- [ ] Implement security settings and preferences
- [ ] Add key material status indicators

### Security Enhancements
- [ ] Implement secure storage for cypher books
- [ ] Add message integrity verification
- [ ] Develop protection against replay attacks
- [ ] Create secure key depletion tracking
- [ ] Implement Cold War-inspired security features

## Technical Challenges

We've identified several technical challenges that need to be addressed:

### True Randomness Generation
- Computer-generated randomness is typically pseudo-random, not truly random
- Solutions: Hardware RNG, quantum-based services, combined entropy sources

### Key Synchronization
- Both parties must use the same portion of the cypher book in perfect sync
- Solutions: Message counters, timestamps, block IDs, synchronization headers

### Key Depletion
- OTP material is consumed as it's used
- Solutions: Visual indicators, notifications, automated replenishment reminders

### Authentication & Integrity
- OTP provides confidentiality but not authentication or integrity
- Solutions: Separate authentication mechanisms, MACs, encrypted checksums

### Secure Storage
- Cypher books must be protected at rest
- Solutions: OS-level encryption, application encryption, secure deletion

## Contributing

This is a hobby project and contributions are welcome. Please feel free to submit issues or pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
