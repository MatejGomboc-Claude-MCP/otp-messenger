# OTP Messenger User Guide

Welcome to OTP Messenger! This guide will help you get started with using the application to send and receive secure messages using One-Time Pad encryption.

## Table of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Creating a Cypher Book](#creating-a-cypher-book)
4. [Exchanging Cypher Books](#exchanging-cypher-books)
5. [Sending Messages](#sending-messages)
6. [Receiving Messages](#receiving-messages)
7. [Security Features](#security-features)
8. [Troubleshooting](#troubleshooting)

## Introduction

OTP Messenger is a secure messaging application that uses One-Time Pad (OTP) encryption, which is mathematically proven to be unbreakable when implemented correctly. Unlike other messaging apps, OTP Messenger requires both communicating parties to have identical copies of a pre-shared random key file (called a "cypher book").

This approach is inspired by Cold War era cryptographic techniques, particularly those used by intelligence agencies for their most secure communications.

## Getting Started

### Installation

1. Download the latest version from the [Releases](https://github.com/MatejGomboc-Claude-MCP/otp-messenger/releases) page.
2. Install the application following the instructions for your operating system.
3. Launch OTP Messenger.

### First Launch

When you first launch OTP Messenger, you'll see a disclaimer that you must accept to use the application. After accepting, you'll be prompted to set up a password for accessing the application.

## Creating a Cypher Book

Before you can send or receive encrypted messages, you need to create a cypher book:

1. Go to **File → New Cypher Book**
2. Choose a file location to save your cypher book
3. Select the size for your cypher book (larger books can encrypt more messages but use more storage)
4. Wait for the cypher book generation process to complete

**Important**: The security of your messages depends on the randomness of your cypher book. The application uses multiple sources of randomness to generate the most secure key material possible.

## Exchanging Cypher Books

For two people to communicate securely using OTP Messenger:

1. **Both parties** must have identical copies of the same cypher book
2. Copy your cypher book to a secure storage medium (like an encrypted USB drive)
3. Physically deliver the storage medium to your communication partner
4. Never transmit cypher books electronically

**Note**: This physical exchange of key material is intentional and part of what makes OTP encryption so secure. By requiring an offline exchange, we eliminate many potential attack vectors.

## Sending Messages

To send an encrypted message:

1. Open your cypher book (**File → Open Cypher Book**)
2. Type your message in the "Send Message" text area
3. Click the "Encrypt" button
4. The encrypted message will appear in the "Receive Message" area
5. Copy the encrypted message (it's automatically copied to your clipboard)
6. Deliver the encrypted message to your recipient through any channel (email, social media, etc.)

**Note**: Once key material is used for encryption, it cannot be reused without compromising security. The application tracks which portions of the cypher book have been used.

## Receiving Messages

To decrypt a received message:

1. Open your cypher book (**File → Open Cypher Book**)
2. Paste the encrypted message into the "Receive Message" text area
3. Click the "Decrypt" button
4. The decrypted message will appear in the "Send Message" area

**Note**: For successful decryption, you must use the same cypher book that was used for encryption, and the key material must not have been used for any other messages.

## Security Features

OTP Messenger includes several security features inspired by Cold War era cryptographic practices:

### Multi-factor Authentication

The application supports several authentication methods:

1. **Password**: Basic authentication using a password
2. **TOTP**: Time-based One-Time Password, compatible with authenticator apps
3. **Biometric**: Fingerprint or facial recognition (where supported)
4. **Hardware Token**: Support for hardware security tokens (where available)

You can configure your authentication level in the Security tab.

### Compartmentalization

You can divide your cypher book into separate compartments for different purposes:

1. Navigate to the Cypher Book tab
2. Click "Create Compartment"
3. Name your compartment and assign a size
4. Use the Lock/Unlock features to secure individual compartments

This feature is inspired by mission-specific sections in Soviet codebooks.

### Emergency Destruction

If you need to quickly destroy key material:

1. Set up an emergency code in the Security tab
2. In case of emergency, enter this code when prompted for a password

This will securely wipe the key material, making it unrecoverable.

### Duress Indicators

The application allows you to send messages that appear normal but contain hidden indicators that you are under duress:

1. When sending a message, use the special "Duress" checkbox
2. The recipient will be notified about possible duress when decrypting the message

This feature is inspired by covert signaling techniques used during the Cold War.

### Challenge-Response

To verify the identity of your communication partner:

1. Set up challenge-response pairs in the Security tab
2. When communicating, you can send a challenge message
3. The recipient must provide the correct response to verify their identity

This is based on authentication protocols used by field agents.

### Code Phrases

You can define special phrases with specific meanings:

1. Configure code phrases in the Code Phrases tab
2. Use the Code Phrase button when sending messages
3. The recipient will see the associated meaning when decrypting

This feature mirrors how agents would communicate concisely in sensitive situations.

## Troubleshooting

### Message Won't Decrypt

If you're having trouble decrypting a message:

1. Ensure both parties are using the exact same cypher book
2. Verify that the key material hasn't been depleted
3. Check that the entire encrypted message was copied correctly

### Low Key Material Warning

When you receive a warning about low key material:

1. Plan to exchange a new cypher book soon
2. Be selective about which messages you send to conserve remaining key material
3. Consider creating a smaller, emergency-only compartment

### Authentication Problems

If you're having trouble with authentication:

1. Password authentication: Reset your password in the Security tab
2. TOTP: Re-synchronize your authenticator app
3. Biometric: Update your biometric data in your system settings

### Lost Cypher Book

If you lose your cypher book:

1. Notify your communication partners immediately
2. Stop using any copies of that cypher book for new messages
3. Exchange new cypher books as soon as possible

Remember that the security of OTP encryption depends on both the secrecy and the one-time use of the key material.

---

This user guide provides basic information to get started. For more detailed information, please consult the documentation included with the application or visit the [project website](https://github.com/MatejGomboc-Claude-MCP/otp-messenger).
