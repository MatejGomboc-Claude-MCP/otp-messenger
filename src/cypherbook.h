#ifndef CYPHERBOOK_H
#define CYPHERBOOK_H

#include <QObject>
#include <QString>
#include <QFile>
#include <QByteArray>
#include <QMutex>

class CypherBook : public QObject
{
    Q_OBJECT

public:
    // File format version for compatibility checks
    static const quint32 CURRENT_FORMAT_VERSION = 1;
    
    // Header structure for cypher book files
    struct Header {
        quint32 formatVersion;       // File format version
        quint64 totalSize;           // Total size of key material in bytes
        quint64 currentPosition;     // Current position in the key material
        quint64 created;             // Unix timestamp when created
        quint32 checksumHeader;      // Checksum for header integrity
        quint8 reserved[32];         // Reserved for future use
    };

    explicit CypherBook(QObject *parent = nullptr);
    ~CypherBook();
    
    // Open an existing cypher book file
    bool open(const QString &filename);
    
    // Create a new cypher book file
    bool create(const QString &filename, quint64 size);
    
    // Close the current cypher book
    void close();
    
    // Check if a cypher book is currently open
    bool isOpen() const;
    
    // Get a portion of the key material at a specific position
    QByteArray getKeyMaterial(quint64 position, quint64 length);
    
    // Mark a portion of the key material as used
    bool markAsUsed(quint64 position, quint64 length);
    
    // Get the current position in the cypher book
    quint64 getCurrentPosition() const;
    
    // Get the total amount of key material in the book
    quint64 getTotalSize() const;
    
    // Get the amount of unused key material
    quint64 getUnusedSize() const;
    
    // Get percentage of key material remaining
    double getPercentageRemaining() const;
    
    // Save changes to the cypher book
    bool save();
    
    // Generate truly random key material
    static QByteArray generateRandomKeyMaterial(quint64 size);
    
signals:
    void keyMaterialLow(double percentageRemaining);
    void error(const QString &errorMessage);
    
private:
    QString filename;
    QFile file;
    Header header;
    bool modified;
    QMutex accessMutex;
    
    // Read the header from the file
    bool readHeader();
    
    // Write the header to the file
    bool writeHeader();
    
    // Calculate header checksum
    quint32 calculateHeaderChecksum() const;
    
    // Validate file integrity
    bool validateIntegrity();
};

#endif // CYPHERBOOK_H
