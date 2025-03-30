#ifndef MESSAGEPROTOCOL_H
#define MESSAGEPROTOCOL_H

#include <QObject>
#include <QByteArray>
#include <QString>
#include <QDateTime>
#include <QJsonObject>
#include "cryptoengine.h"

class MessageProtocol : public QObject
{
    Q_OBJECT

public:
    // Message types
    enum class MessageType {
        Text,           // Standard text message
        FileTransfer,   // File transfer details
        SystemControl,  // System control message
        KeySync,        // Key synchronization message
        Authentication, // Authentication challenge/response
        Challenge,      // Challenge code (inspired by agent challenge codes)
        Duress,         // Hidden duress indicator message
        CodePhrase      // Special code phrase message (inspired by Cold War terminology)
    };
    
    // Message structure (analogous to how agents would structure encoded messages)
    struct Message {
        MessageType type;         // Type of message
        quint32 sequenceNumber;   // Message sequence number (for ordering and replay protection)
        quint64 keyOffset;        // Position in the cypher book used
        quint64 keyLength;        // Length of key material used
        QDateTime timestamp;      // Message timestamp
        QByteArray payload;       // Encrypted message payload
        QByteArray signature;     // Message authentication code
        QByteArray challenge;     // Optional challenge code (for verification)
    };

    explicit MessageProtocol(QObject *parent = nullptr);
    
    // Set the crypto engine to use
    void setCryptoEngine(CryptoEngine *engine);
    
    // Create a text message
    QByteArray createTextMessage(const QString &text);
    
    // Create a file transfer message
    QByteArray createFileTransferMessage(const QString &filename, quint64 fileSize);
    
    // Create a key synchronization message
    QByteArray createKeySyncMessage(quint64 syncPoint);
    
    // Create an authentication message
    QByteArray createAuthenticationMessage(const QByteArray &authData);
    
    // Cold War inspired: Create a challenge message (for agent verification)
    QByteArray createChallengeMessage(const QString &challenge);
    
    // Cold War inspired: Create a response to a challenge
    QByteArray createChallengeResponse(const QByteArray &challengeMessage, const QString &response);
    
    // Cold War inspired: Create a code phrase message
    QByteArray createCodePhraseMessage(const QString &codePhrase);
    
    // Cold War inspired: Create a duress message (appears normal but indicates duress)
    QByteArray createDuressMessage(const QString &text);
    
    // Parse a received message
    Message parseMessage(const QByteArray &data);
    
    // Extract text from a message
    QString extractTextMessage(const Message &message);
    
    // Extract file transfer details
    QJsonObject extractFileTransferDetails(const Message &message);
    
    // Extract key sync information
    quint64 extractKeySyncPoint(const Message &message);
    
    // Extract authentication data
    QByteArray extractAuthenticationData(const Message &message);
    
    // Cold War inspired: Extract challenge from a message
    QString extractChallenge(const Message &message);
    
    // Cold War inspired: Extract challenge response
    QString extractChallengeResponse(const Message &message);
    
    // Cold War inspired: Extract code phrase
    QString extractCodePhrase(const Message &message);
    
    // Verify a message's integrity
    bool verifyMessage(const Message &message);
    
    // Cold War inspired: Check if a message contains a hidden duress indicator
    bool isDuressMessage(const Message &message);
    
signals:
    void messageSent(quint32 sequenceNumber);
    void messageReceived(quint32 sequenceNumber);
    void error(const QString &errorMessage);
    
    // Cold War inspired signals
    void duressDetected();
    void challengeReceived(const QString &challenge);
    void invalidResponseReceived();
    void codePhraseReceived(const QString &codePhrase);
    
private:
    CryptoEngine *cryptoEngine;
    quint32 nextSequenceNumber;
    
    // Common message creation functionality
    QByteArray createMessageInternal(MessageType type, const QByteArray &payload);
    
    // Sign a message
    QByteArray signMessage(const Message &message);
    
    // Cold War inspired: Add hidden duress markers to a message
    QByteArray addDuressMarkers(const QByteArray &data);
    
    // Cold War inspired: Check for hidden duress markers
    bool checkDuressMarkers(const QByteArray &data);
    
    // Serialize a message to binary format
    QByteArray serializeMessage(const Message &message);
    
    // Deserialize binary data to a message
    Message deserializeMessage(const QByteArray &data);
};

#endif // MESSAGEPROTOCOL_H
