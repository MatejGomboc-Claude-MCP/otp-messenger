#include "cryptoengine.h"
#include <QCryptographicHash>
#include <QDateTime>
#include <QDebug>

// Constants for message format
const char OTP_MAGIC_HEADER[] = "OTP1"; // Magic identifier for OTP messages
const int MAC_SIZE = 32; // Size of MAC in bytes (SHA-256)

CryptoEngine::CryptoEngine(QObject *parent)
    : QObject(parent), cypherBook(nullptr)
{
}

bool CryptoEngine::setCypherBook(CypherBook *book)
{
    if (!book) {
        emit error(tr("Invalid cypher book"));
        return false;
    }
    
    if (!book->isOpen()) {
        emit error(tr("Cypher book is not open"));
        return false;
    }
    
    cypherBook = book;
    
    // Connect signals from the cypher book
    connect(cypherBook, &CypherBook::keyMaterialLow, this, &CryptoEngine::keyMaterialLow);
    
    return true;
}

QByteArray CryptoEngine::encrypt(const QByteArray &plaintext, quint64 &keyOffset)
{
    if (!cypherBook) {
        emit error(tr("No cypher book set"));
        return QByteArray();
    }
    
    // Calculate required key length
    quint64 requiredLength = calculateRequiredKeyLength(plaintext);
    
    // Check if we have enough key material
    if (!hasEnoughKeyMaterial(plaintext)) {
        emit error(tr("Not enough key material for encryption"));
        return QByteArray();
    }
    
    // Use the current position in the cypher book
    keyOffset = cypherBook->getCurrentPosition();
    
    // Get key material from the cypher book
    QByteArray keyMaterial = cypherBook->getKeyMaterial(keyOffset, requiredLength);
    if (keyMaterial.isEmpty()) {
        // Error message already emitted by cypherBook
        return QByteArray();
    }
    
    // Perform OTP encryption (XOR with key material)
    QByteArray ciphertext = xorWithKey(plaintext, keyMaterial);
    
    // Mark key material as used
    if (!cypherBook->markAsUsed(keyOffset, requiredLength)) {
        // Error message already emitted by cypherBook
        return QByteArray();
    }
    
    // Add header and format information
    QByteArray result;
    result.append(OTP_MAGIC_HEADER, 4); // Magic header
    result.append(reinterpret_cast<char*>(&keyOffset), sizeof(keyOffset)); // Key position
    result.append(reinterpret_cast<char*>(&requiredLength), sizeof(requiredLength)); // Key length
    
    // Add current timestamp (to prevent replay attacks)
    quint64 timestamp = QDateTime::currentSecsSinceEpoch();
    result.append(reinterpret_cast<char*>(&timestamp), sizeof(timestamp));
    
    // Add the ciphertext
    result.append(ciphertext);
    
    // Generate and append MAC for integrity
    QByteArray mac = generateMAC(result, keyOffset);
    result.append(mac);
    
    emit encryptionSuccessful(requiredLength);
    
    return result;
}

QByteArray CryptoEngine::decrypt(const QByteArray &ciphertext, quint64 keyOffset)
{
    if (!cypherBook) {
        emit error(tr("No cypher book set"));
        return QByteArray();
    }
    
    // Check if the ciphertext has a valid format
    if (!isValidOTPMessage(ciphertext)) {
        emit error(tr("Invalid OTP message format"));
        return QByteArray();
    }
    
    // Extract header information
    quint64 storedKeyOffset;
    quint64 keyLength;
    quint64 timestamp;
    
    memcpy(&storedKeyOffset, ciphertext.constData() + 4, sizeof(storedKeyOffset));
    memcpy(&keyLength, ciphertext.constData() + 4 + sizeof(storedKeyOffset), sizeof(keyLength));
    memcpy(&timestamp, ciphertext.constData() + 4 + sizeof(storedKeyOffset) + sizeof(keyLength), sizeof(timestamp));
    
    // If a specific key offset was provided, use it (for case when we know the exact position)
    if (keyOffset != 0) {
        storedKeyOffset = keyOffset;
    }
    
    // Get the MAC from the end of the message
    QByteArray receivedMAC = ciphertext.right(MAC_SIZE);
    
    // Verify MAC (message authentication code)
    QByteArray messageWithoutMAC = ciphertext.left(ciphertext.size() - MAC_SIZE);
    if (!verifyMAC(messageWithoutMAC, receivedMAC, storedKeyOffset)) {
        emit error(tr("Message integrity check failed"));
        return QByteArray();
    }
    
    // Get key material from the cypher book
    QByteArray keyMaterial = cypherBook->getKeyMaterial(storedKeyOffset, keyLength);
    if (keyMaterial.isEmpty()) {
        // Error message already emitted by cypherBook
        return QByteArray();
    }
    
    // Calculate header size
    int headerSize = 4 + sizeof(storedKeyOffset) + sizeof(keyLength) + sizeof(timestamp);
    
    // Extract the actual ciphertext (without header and MAC)
    QByteArray actualCiphertext = ciphertext.mid(headerSize, ciphertext.size() - headerSize - MAC_SIZE);
    
    // Perform OTP decryption (XOR with key material)
    QByteArray plaintext = xorWithKey(actualCiphertext, keyMaterial);
    
    emit decryptionSuccessful(keyLength);
    
    return plaintext;
}

quint64 CryptoEngine::calculateRequiredKeyLength(const QByteArray &message)
{
    // For pure OTP, we need exactly as many key bytes as message bytes
    return message.size();
}

bool CryptoEngine::hasEnoughKeyMaterial(const QByteArray &message)
{
    if (!cypherBook) {
        return false;
    }
    
    quint64 requiredLength = calculateRequiredKeyLength(message);
    return (cypherBook->getUnusedSize() >= requiredLength);
}

QByteArray CryptoEngine::generateMAC(const QByteArray &message, quint64 &keyOffset)
{
    if (!cypherBook) {
        emit error(tr("No cypher book set"));
        return QByteArray();
    }
    
    // For a true OTP-like MAC, we need additional key material
    // We'll use 32 bytes (256 bits) for the MAC
    quint64 macKeyOffset = cypherBook->getCurrentPosition();
    QByteArray macKeyMaterial = cypherBook->getKeyMaterial(macKeyOffset, MAC_SIZE);
    
    if (macKeyMaterial.isEmpty()) {
        // Error message already emitted by cypherBook
        return QByteArray();
    }
    
    // Mark MAC key material as used
    if (!cypherBook->markAsUsed(macKeyOffset, MAC_SIZE)) {
        // Error message already emitted by cypherBook
        return QByteArray();
    }
    
    // Create MAC by combining the message with the MAC key material and hashing
    QByteArray combinedData = message + macKeyMaterial;
    QByteArray mac = QCryptographicHash::hash(combinedData, QCryptographicHash::Sha256);
    
    // XOR the hash with the key material for additional security
    QByteArray xorMac = xorWithKey(mac, macKeyMaterial);
    
    return xorMac;
}

bool CryptoEngine::verifyMAC(const QByteArray &message, const QByteArray &mac, quint64 keyOffset)
{
    if (!cypherBook) {
        emit error(tr("No cypher book set"));
        return false;
    }
    
    // For verification, we need the same key material that was used for MAC generation
    // This is typically right after the message key material
    quint64 macKeyOffset = keyOffset + calculateRequiredKeyLength(message) - (4 + sizeof(keyOffset) + sizeof(quint64) + sizeof(quint64));
    QByteArray macKeyMaterial = cypherBook->getKeyMaterial(macKeyOffset, MAC_SIZE);
    
    if (macKeyMaterial.isEmpty()) {
        // Error message already emitted by cypherBook
        return false;
    }
    
    // Create MAC using the same method as in generateMAC
    QByteArray combinedData = message + macKeyMaterial;
    QByteArray calculatedMac = QCryptographicHash::hash(combinedData, QCryptographicHash::Sha256);
    
    // XOR the hash with the key material
    QByteArray xorMac = xorWithKey(calculatedMac, macKeyMaterial);
    
    // Compare the calculated MAC with the received MAC
    return (xorMac == mac);
}

QByteArray CryptoEngine::xorWithKey(const QByteArray &data, const QByteArray &key)
{
    if (key.size() < data.size()) {
        emit error(tr("Key material too short for XOR operation"));
        return QByteArray();
    }
    
    QByteArray result(data.size(), 0);
    
    // Perform XOR operation byte by byte
    for (int i = 0; i < data.size(); ++i) {
        result[i] = data[i] ^ key[i];
    }
    
    return result;
}

bool CryptoEngine::isValidOTPMessage(const QByteArray &data)
{
    // Check if the message is at least long enough to contain the header and MAC
    int minLength = 4 + sizeof(quint64) + sizeof(quint64) + sizeof(quint64) + MAC_SIZE;
    if (data.size() < minLength) {
        return false;
    }
    
    // Check if the message starts with the magic header
    if (data.left(4) != QByteArray(OTP_MAGIC_HEADER, 4)) {
        return false;
    }
    
    // Extract key offset and length
    quint64 keyOffset;
    quint64 keyLength;
    memcpy(&keyOffset, data.constData() + 4, sizeof(keyOffset));
    memcpy(&keyLength, data.constData() + 4 + sizeof(keyOffset), sizeof(keyLength));
    
    // Basic sanity checks
    if (keyLength == 0 || keyLength > 1000000000) { // 1GB max for sanity
        return false;
    }
    
    // Check if the message length matches what we expect based on header info
    int expectedLen = 4 + sizeof(quint64) + sizeof(quint64) + sizeof(quint64) + keyLength + MAC_SIZE;
    if (data.size() != expectedLen) {
        return false;
    }
    
    return true;
}
