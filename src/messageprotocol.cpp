#include "messageprotocol.h"
#include <QJsonDocument>
#include <QJsonObject>
#include <QDataStream>
#include <QByteArray>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDebug>

// Constants for special message markers
const char DURESS_MARKER[] = "XRAY"; // Cold War inspired duress indicator
const int CHALLENGE_TIMEOUT = 300; // Challenge valid for 5 minutes (300 seconds)

MessageProtocol::MessageProtocol(QObject *parent)
    : QObject(parent), cryptoEngine(nullptr), nextSequenceNumber(0)
{
}

void MessageProtocol::setCryptoEngine(CryptoEngine *engine)
{
    if (!engine) {
        emit error(tr("Invalid crypto engine"));
        return;
    }
    
    cryptoEngine = engine;
}

QByteArray MessageProtocol::createTextMessage(const QString &text)
{
    if (!cryptoEngine) {
        emit error(tr("No crypto engine set"));
        return QByteArray();
    }
    
    // Create JSON payload
    QJsonObject json;
    json["text"] = text;
    
    QByteArray payload = QJsonDocument(json).toJson(QJsonDocument::Compact);
    
    // Create message
    return createMessageInternal(MessageType::Text, payload);
}

QByteArray MessageProtocol::createFileTransferMessage(const QString &filename, quint64 fileSize)
{
    if (!cryptoEngine) {
        emit error(tr("No crypto engine set"));
        return QByteArray();
    }
    
    // Create JSON payload
    QJsonObject json;
    json["filename"] = filename;
    json["size"] = QString::number(fileSize); // JSON doesn't handle 64-bit integers well
    
    QByteArray payload = QJsonDocument(json).toJson(QJsonDocument::Compact);
    
    // Create message
    return createMessageInternal(MessageType::FileTransfer, payload);
}

QByteArray MessageProtocol::createKeySyncMessage(quint64 syncPoint)
{
    if (!cryptoEngine) {
        emit error(tr("No crypto engine set"));
        return QByteArray();
    }
    
    // Create JSON payload
    QJsonObject json;
    json["syncPoint"] = QString::number(syncPoint); // JSON doesn't handle 64-bit integers well
    
    QByteArray payload = QJsonDocument(json).toJson(QJsonDocument::Compact);
    
    // Create message
    return createMessageInternal(MessageType::KeySync, payload);
}

QByteArray MessageProtocol::createAuthenticationMessage(const QByteArray &authData)
{
    if (!cryptoEngine) {
        emit error(tr("No crypto engine set"));
        return QByteArray();
    }
    
    // Create message (authData is already binary, no need for JSON)
    return createMessageInternal(MessageType::Authentication, authData);
}

QByteArray MessageProtocol::createChallengeMessage(const QString &challenge)
{
    if (!cryptoEngine) {
        emit error(tr("No crypto engine set"));
        return QByteArray();
    }
    
    // Create JSON payload with challenge and timestamp
    QJsonObject json;
    json["challenge"] = challenge;
    json["timestamp"] = QString::number(QDateTime::currentSecsSinceEpoch());
    
    QByteArray payload = QJsonDocument(json).toJson(QJsonDocument::Compact);
    
    // Create message
    return createMessageInternal(MessageType::Challenge, payload);
}

QByteArray MessageProtocol::createChallengeResponse(const QByteArray &challengeMessage, const QString &response)
{
    if (!cryptoEngine) {
        emit error(tr("No crypto engine set"));
        return QByteArray();
    }
    
    // Parse the challenge message
    Message message = parseMessage(challengeMessage);
    if (message.type != MessageType::Challenge) {
        emit error(tr("Not a challenge message"));
        return QByteArray();
    }
    
    // Extract challenge
    QString challenge = extractChallenge(message);
    
    // Create JSON payload with original challenge, response, and timestamp
    QJsonObject json;
    json["challenge"] = challenge;
    json["response"] = response;
    json["timestamp"] = QString::number(QDateTime::currentSecsSinceEpoch());
    
    QByteArray payload = QJsonDocument(json).toJson(QJsonDocument::Compact);
    
    // Create message
    return createMessageInternal(MessageType::Challenge, payload);
}

QByteArray MessageProtocol::createCodePhraseMessage(const QString &codePhrase)
{
    if (!cryptoEngine) {
        emit error(tr("No crypto engine set"));
        return QByteArray();
    }
    
    // Create JSON payload
    QJsonObject json;
    json["codePhrase"] = codePhrase;
    
    QByteArray payload = QJsonDocument(json).toJson(QJsonDocument::Compact);
    
    // Create message
    return createMessageInternal(MessageType::CodePhrase, payload);
}

QByteArray MessageProtocol::createDuressMessage(const QString &text)
{
    if (!cryptoEngine) {
        emit error(tr("No crypto engine set"));
        return QByteArray();
    }
    
    // Create JSON payload with text and hidden duress marker
    QJsonObject json;
    json["text"] = text;
    json["marker"] = DURESS_MARKER; // This will be encrypted but signals duress
    
    QByteArray payload = QJsonDocument(json).toJson(QJsonDocument::Compact);
    
    // Add additional duress markers in binary format
    payload = addDuressMarkers(payload);
    
    // Create message
    return createMessageInternal(MessageType::Duress, payload);
}

MessageProtocol::Message MessageProtocol::parseMessage(const QByteArray &data)
{
    Message msg;
    
    // Initialize with defaults
    msg.type = MessageType::Text;
    msg.sequenceNumber = 0;
    msg.keyOffset = 0;
    msg.keyLength = 0;
    
    if (data.isEmpty()) {
        emit error(tr("Empty message data"));
        return msg;
    }
    
    // Deserialize the message
    msg = deserializeMessage(data);
    
    // Check for duress indicators
    if (checkDuressMarkers(msg.payload)) {
        msg.type = MessageType::Duress;
        emit duressDetected();
    }
    
    return msg;
}

QString MessageProtocol::extractTextMessage(const Message &message)
{
    // Only process Text type messages
    if (message.type != MessageType::Text && message.type != MessageType::Duress) {
        emit error(tr("Not a text message"));
        return QString();
    }
    
    // Parse JSON payload
    QJsonDocument doc = QJsonDocument::fromJson(message.payload);
    if (doc.isNull() || !doc.isObject()) {
        emit error(tr("Invalid message format"));
        return QString();
    }
    
    QJsonObject json = doc.object();
    if (!json.contains("text")) {
        emit error(tr("Message does not contain text"));
        return QString();
    }
    
    return json["text"].toString();
}

QJsonObject MessageProtocol::extractFileTransferDetails(const Message &message)
{
    // Only process FileTransfer type messages
    if (message.type != MessageType::FileTransfer) {
        emit error(tr("Not a file transfer message"));
        return QJsonObject();
    }
    
    // Parse JSON payload
    QJsonDocument doc = QJsonDocument::fromJson(message.payload);
    if (doc.isNull() || !doc.isObject()) {
        emit error(tr("Invalid message format"));
        return QJsonObject();
    }
    
    return doc.object();
}

quint64 MessageProtocol::extractKeySyncPoint(const Message &message)
{
    // Only process KeySync type messages
    if (message.type != MessageType::KeySync) {
        emit error(tr("Not a key sync message"));
        return 0;
    }
    
    // Parse JSON payload
    QJsonDocument doc = QJsonDocument::fromJson(message.payload);
    if (doc.isNull() || !doc.isObject()) {
        emit error(tr("Invalid message format"));
        return 0;
    }
    
    QJsonObject json = doc.object();
    if (!json.contains("syncPoint")) {
        emit error(tr("Message does not contain sync point"));
        return 0;
    }
    
    QString syncPointStr = json["syncPoint"].toString();
    bool ok;
    quint64 syncPoint = syncPointStr.toULongLong(&ok);
    if (!ok) {
        emit error(tr("Invalid sync point format"));
        return 0;
    }
    
    return syncPoint;
}

QByteArray MessageProtocol::extractAuthenticationData(const Message &message)
{
    // Only process Authentication type messages
    if (message.type != MessageType::Authentication) {
        emit error(tr("Not an authentication message"));
        return QByteArray();
    }
    
    // Authentication data is raw binary, no need to parse JSON
    return message.payload;
}

QString MessageProtocol::extractChallenge(const Message &message)
{
    // Only process Challenge type messages
    if (message.type != MessageType::Challenge) {
        emit error(tr("Not a challenge message"));
        return QString();
    }
    
    // Parse JSON payload
    QJsonDocument doc = QJsonDocument::fromJson(message.payload);
    if (doc.isNull() || !doc.isObject()) {
        emit error(tr("Invalid message format"));
        return QString();
    }
    
    QJsonObject json = doc.object();
    if (!json.contains("challenge")) {
        emit error(tr("Message does not contain challenge"));
        return QString();
    }
    
    // Check timestamp if present
    if (json.contains("timestamp")) {
        bool ok;
        quint64 timestamp = json["timestamp"].toString().toULongLong(&ok);
        if (ok) {
            quint64 currentTime = QDateTime::currentSecsSinceEpoch();
            if (currentTime - timestamp > CHALLENGE_TIMEOUT) {
                emit error(tr("Challenge has expired"));
                return QString();
            }
        }
    }
    
    return json["challenge"].toString();
}

QString MessageProtocol::extractChallengeResponse(const Message &message)
{
    // Only process Challenge type messages
    if (message.type != MessageType::Challenge) {
        emit error(tr("Not a challenge message"));
        return QString();
    }
    
    // Parse JSON payload
    QJsonDocument doc = QJsonDocument::fromJson(message.payload);
    if (doc.isNull() || !doc.isObject()) {
        emit error(tr("Invalid message format"));
        return QString();
    }
    
    QJsonObject json = doc.object();
    if (!json.contains("response")) {
        emit error(tr("Message does not contain response"));
        return QString();
    }
    
    return json["response"].toString();
}

QString MessageProtocol::extractCodePhrase(const Message &message)
{
    // Only process CodePhrase type messages
    if (message.type != MessageType::CodePhrase) {
        emit error(tr("Not a code phrase message"));
        return QString();
    }
    
    // Parse JSON payload
    QJsonDocument doc = QJsonDocument::fromJson(message.payload);
    if (doc.isNull() || !doc.isObject()) {
        emit error(tr("Invalid message format"));
        return QString();
    }
    
    QJsonObject json = doc.object();
    if (!json.contains("codePhrase")) {
        emit error(tr("Message does not contain code phrase"));
        return QString();
    }
    
    return json["codePhrase"].toString();
}

bool MessageProtocol::verifyMessage(const Message &message)
{
    // Basic validity checks
    if (message.payload.isEmpty()) {
        return false;
    }
    
    // For Challenge messages, verify timestamp is recent
    if (message.type == MessageType::Challenge) {
        QJsonDocument doc = QJsonDocument::fromJson(message.payload);
        if (!doc.isNull() && doc.isObject()) {
            QJsonObject json = doc.object();
            if (json.contains("timestamp")) {
                bool ok;
                quint64 timestamp = json["timestamp"].toString().toULongLong(&ok);
                if (ok) {
                    quint64 currentTime = QDateTime::currentSecsSinceEpoch();
                    if (currentTime - timestamp > CHALLENGE_TIMEOUT) {
                        emit error(tr("Challenge has expired"));
                        return false;
                    }
                }
            }
        }
    }
    
    // Message integrity was already verified during decryption by the crypto engine
    
    return true;
}

bool MessageProtocol::isDuressMessage(const Message &message)
{
    // Check for explicit duress type
    if (message.type == MessageType::Duress) {
        return true;
    }
    
    // Check for hidden duress markers in the payload
    if (checkDuressMarkers(message.payload)) {
        emit duressDetected();
        return true;
    }
    
    // For text messages, check for duress marker in JSON
    if (message.type == MessageType::Text) {
        QJsonDocument doc = QJsonDocument::fromJson(message.payload);
        if (!doc.isNull() && doc.isObject()) {
            QJsonObject json = doc.object();
            if (json.contains("marker") && json["marker"].toString() == DURESS_MARKER) {
                emit duressDetected();
                return true;
            }
        }
    }
    
    return false;
}

// Private methods

QByteArray MessageProtocol::createMessageInternal(MessageType type, const QByteArray &payload)
{
    if (!cryptoEngine) {
        emit error(tr("No crypto engine set"));
        return QByteArray();
    }
    
    // Prepare message structure
    Message msg;
    msg.type = type;
    msg.sequenceNumber = nextSequenceNumber++;
    msg.timestamp = QDateTime::currentDateTime();
    msg.payload = payload;
    
    // Serialize the message
    QByteArray serializedMsg = serializeMessage(msg);
    
    // Encrypt the message
    quint64 keyOffset;
    QByteArray encryptedMsg = cryptoEngine->encrypt(serializedMsg, keyOffset);
    
    if (encryptedMsg.isEmpty()) {
        // Error message already emitted by cryptoEngine
        return QByteArray();
    }
    
    // Store the key offset in the message structure
    msg.keyOffset = keyOffset;
    msg.keyLength = cryptoEngine->calculateRequiredKeyLength(serializedMsg);
    
    emit messageSent(msg.sequenceNumber);
    
    return encryptedMsg;
}

QByteArray MessageProtocol::signMessage(const Message &message)
{
    // In a real implementation, this would use a digital signature
    // For now, we'll use a simple hash-based approach
    
    // Create a string representation of the message
    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    stream << static_cast<int>(message.type);
    stream << message.sequenceNumber;
    stream << message.timestamp.toSecsSinceEpoch();
    stream << message.payload;
    
    // Create a hash of the data
    return QCryptographicHash::hash(data, QCryptographicHash::Sha256);
}

QByteArray MessageProtocol::addDuressMarkers(const QByteArray &data)
{
    // In a real implementation, this would add subtle, hidden markers
    // For demonstration, we'll add a simple marker
    
    QByteArray result = data;
    
    // Add a special byte sequence at positions calculated from data length
    int pos1 = (data.size() / 3) % data.size();
    int pos2 = (data.size() * 2 / 3) % data.size();
    
    // Make sure the positions are different
    if (pos1 == pos2) {
        pos2 = (pos2 + 1) % data.size();
    }
    
    // XOR the bytes at these positions with a special value
    result[pos1] = result[pos1] ^ 0x3A;
    result[pos2] = result[pos2] ^ 0x5C;
    
    return result;
}

bool MessageProtocol::checkDuressMarkers(const QByteArray &data)
{
    // Check for the duress markers added by addDuressMarkers
    if (data.size() < 3) {
        return false;
    }
    
    int pos1 = (data.size() / 3) % data.size();
    int pos2 = (data.size() * 2 / 3) % data.size();
    
    // Make sure the positions are different
    if (pos1 == pos2) {
        pos2 = (pos2 + 1) % data.size();
    }
    
    // Check if the bytes at these positions, when XORed with our special value,
    // have a specific pattern (this is just demonstrative, not a real security feature)
    unsigned char byte1 = data[pos1] ^ 0x3A;
    unsigned char byte2 = data[pos2] ^ 0x5C;
    
    // Check for a specific pattern that would be unlikely to occur randomly
    return (byte1 == byte2) && ((byte1 & 0xF0) == 0x50);
}

QByteArray MessageProtocol::serializeMessage(const Message &message)
{
    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    
    // Serialize header
    stream << static_cast<int>(message.type);
    stream << message.sequenceNumber;
    stream << message.timestamp.toSecsSinceEpoch();
    
    // Add the payload
    stream << message.payload;
    
    return data;
}

MessageProtocol::Message MessageProtocol::deserializeMessage(const QByteArray &data)
{
    Message message;
    
    // Check if this is an encrypted message that needs decryption
    if (data.startsWith(QByteArray("OTP1", 4))) {
        // Extract key offset from the encrypted message
        quint64 keyOffset;
        memcpy(&keyOffset, data.constData() + 4, sizeof(keyOffset));
        message.keyOffset = keyOffset;
        
        // Decrypt the message
        QByteArray decryptedData = cryptoEngine->decrypt(data, keyOffset);
        if (decryptedData.isEmpty()) {
            // Error message already emitted by cryptoEngine
            return message;
        }
        
        // Parse the decrypted data
        QDataStream stream(decryptedData);
        
        // Read header
        int typeInt;
        quint64 timestamp;
        stream >> typeInt;
        stream >> message.sequenceNumber;
        stream >> timestamp;
        
        message.type = static_cast<MessageType>(typeInt);
        message.timestamp = QDateTime::fromSecsSinceEpoch(timestamp);
        
        // Read payload
        stream >> message.payload;
        
        emit messageReceived(message.sequenceNumber);
    } else {
        // This is already a deserialized message (internal use)
        QDataStream stream(data);
        
        // Read header
        int typeInt;
        quint64 timestamp;
        stream >> typeInt;
        stream >> message.sequenceNumber;
        stream >> timestamp;
        
        message.type = static_cast<MessageType>(typeInt);
        message.timestamp = QDateTime::fromSecsSinceEpoch(timestamp);
        
        // Read payload
        stream >> message.payload;
    }
    
    return message;
}
