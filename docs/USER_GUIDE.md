# OTP Messenger User Guide

Welcome to OTP Messenger! This guide will help you get started with using the application to send and receive secure messages using One-Time Pad encryption.

## Table of Contents

1. [Introduction](#introduction)
2. [Historical Background](#historical-background)
3. [Getting Started](#getting-started)
4. [Creating a Codebook](#creating-a-codebook)
5. [Exchanging Codebooks](#exchanging-codebooks)
6. [Sending Messages](#sending-messages)
7. [Receiving Messages](#receiving-messages)
8. [Security Features](#security-features)
9. [Troubleshooting](#troubleshooting)

## Introduction

OTP Messenger is a secure messaging application that uses One-Time Pad (OTP) encryption, which is mathematically proven to be unbreakable when implemented correctly. Unlike other messaging apps, OTP Messenger requires both communicating parties to have identical copies of a pre-shared random key file (called a "codebook").

This approach is inspired by historical cryptographic techniques, from 19th century telegraph communications to Cold War era spy tradecraft.

## Historical Background

### Telegraph Origins (19th Century)

The One-Time Pad encryption method was originally developed in the 19th century to secure sensitive banking and financial information transmitted via telegraph using Morse code. Key features of this early system:

- Random key material was distributed on paper sheets or pads
- Each key could only be used once (hence "one-time")
- Telegraph operators would convert Morse code signals to text, then apply the encryption manually

### Mathematical Perfection

In 1949, Claude Shannon (considered the father of information theory) proved mathematically that the One-Time Pad is the only encryption system that offers "perfect secrecy" when implemented correctly.

### Cold War Applications

During the Cold War, intelligence agencies refined OTP systems for espionage:

- Soviet KGB and GRU agents carried physical codebooks with random numbers
- Numbers stations broadcast coded messages over shortwave radio
- Agents used sophisticated verification and authentication techniques
- Emergency destruction protocols were developed for compromised situations

OTP Messenger implements modern digital versions of these historical techniques, bringing time-tested cryptographic methods into the digital age.

## Getting Started

### Installation

1. Download the latest version from the [Releases](https://github.com/MatejGomboc-Claude-MCP/otp-messenger/releases) page
2. Install the application following the instructions for your operating system
3. Launch OTP Messenger

### First Launch

When you first launch OTP Messenger, you'll see a disclaimer that you must accept to use the application. After accepting, you'll be prompted to set up a password for accessing the application.

## Creating a Codebook

Before you can send or receive encrypted messages, you need to create a codebook:

1. Go to **File → New Codebook**
2. Choose a file location to save your codebook
3. Select the size for your codebook (larger books can encrypt more messages but use more storage)
4. Wait for the codebook generation process to complete

**Important**: The security of your messages depends on the randomness of your codebook. The application uses multiple sources of randomness to generate the most secure key material possible.

## Exchanging Codebooks

For two people to communicate securely using OTP Messenger:

1. **Both parties** must have identical copies of the same codebook
2. Copy your codebook to a secure storage medium (like an encrypted USB drive)
3. Physically deliver the storage medium to your communication partner
4. Never transmit codebooks electronically

**Note**: This physical exchange of key material is intentional and part of what makes OTP encryption so secure. By requiring an offline exchange, we eliminate many potential attack vectors.

## Sending Messages

To send an encrypted message:

1. Open your codebook (**File → Open Codebook**)
2. Type your message in the "Send Message" text area
3. Click the "Encrypt" button
4. The encrypted message will appear in the "Receive Message" area
5. Copy the encrypted message (it's automatically copied to your clipboard)
6. Deliver the encrypted message to your recipient through any channel (email, social media, etc.)

**Note**: Once key material is used for encryption, it cannot be reused without compromising security. The application tracks which portions of the codebook have been used.

## Receiving Messages

To decrypt a received message:

1. Open your codebook (**File → Open Codebook**)
2. Paste the encrypted message into the "Receive Message" text area
3. Click the "Decrypt" button
4. The decrypted message will appear in the "Send Message" area

**Note**: For successful decryption, you must use the same codebook that was used for encryption, and the key material must not have been used for any other messages.

## Security Features

OTP Messenger includes several security features inspired by historical cryptographic practices:

### Multi-factor Authentication

The application supports several authentication methods:

1. **Password**: Basic authentication using a password
2. **TOTP**: Time-based One-Time Password, compatible with authenticator apps
3. **Biometric**: Fingerprint or facial recognition (where supported)
4. **Hardware Token**: Support for hardware security tokens (where available)

You can configure your authentication level in the Security tab.

### Compartmentalization

You can divide your codebook into separate compartments for different purposes:

1. Navigate to the Codebook tab
2. Click "Create Compartment"
3. Name your compartment and assign a size
4. Use the Lock/Unlock features to secure individual compartments

This feature is inspired by mission-specific sections in codebooks.

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

1. Ensure both parties are using the exact same codebook
2. Verify that the key material hasn't been depleted
3. Check that the entire encrypted message was copied correctly

### Low Key Material Warning

When you receive a warning about low key material:

1. Plan to exchange a new codebook soon
2. Be selective about which messages you send to conserve remaining key material
3. Consider creating a smaller, emergency-only compartment

### Authentication Problems

If you're having trouble with authentication:

1. Password authentication: Reset your password in the Security tab
2. TOTP: Re-synchronize your authenticator app
3. Biometric: Update your biometric data in your system settings

### Lost Codebook

If you lose your codebook:

1. Notify your communication partners immediately
2. Stop using any copies of that codebook for new messages
3. Exchange new codebooks as soon as possible

Remember that the security of OTP encryption depends on both the secrecy and the one-time use of the key material.

---

This user guide provides basic information to get started. For more detailed information, please consult the documentation included with the application or visit the [project website](https://github.com/MatejGomboc-Claude-MCP/otp-messenger).
