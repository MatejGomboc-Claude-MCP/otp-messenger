#ifndef CRYPTOENGINE_H
#define CRYPTOENGINE_H

#include <QObject>
#include <QByteArray>
#include <QString>
#include <QVector>
#include "codebook.h"

// Forward declaration for backward compatibility
class CypherBook;

class CryptoEngine : public QObject
{
    Q_OBJECT

public:
    explicit CryptoEngine(QObject *parent = nullptr);
    
    // Set the codebook to use for encryption/decryption
    bool setCodeBook(CodeBook *book);
    
    // Backward compatibility method for CypherBook -> CodeBook transition
    bool setCypherBook(CodeBook *book);
    
    // Encrypt a message using OTP
    QByteArray encrypt(const QByteArray &plaintext, quint64 &keyOffset);
    
    // Decrypt a message using OTP
    QByteArray decrypt(const QByteArray &ciphertext, quint64 keyOffset);
    
    // Calculate how much key material is needed for a message
    quint64 calculateRequiredKeyLength(const QByteArray &message);
    
    // Check if we have enough key material for a message
    bool hasEnoughKeyMaterial(const QByteArray &message);
    
    // Generate a message authentication code for integrity checking
    QByteArray generateMAC(const QByteArray &message, quint64 &keyOffset);
    
    // Verify a message authentication code
    bool verifyMAC(const QByteArray &message, const QByteArray &mac, quint64 keyOffset);
    
signals:
    void keyMaterialLow(double percentageRemaining);
    void encryptionSuccessful(quint64 bytesUsed);
    void decryptionSuccessful(quint64 bytesUsed);
    void error(const QString &errorMessage);
    
private:
    CodeBook *codeBook;
    
    // Perform XOR operation (the core of OTP)
    QByteArray xorWithKey(const QByteArray &data, const QByteArray &key);
    
    // Format verification to ensure we're dealing with OTP messages
    bool isValidOTPMessage(const QByteArray &data);
};

#endif // CRYPTOENGINE_H
