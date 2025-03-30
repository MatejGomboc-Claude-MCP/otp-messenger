#ifndef CODEBOOK_H
#define CODEBOOK_H

#include <QObject>
#include <QString>
#include <QFile>
#include <QByteArray>
#include <QMutex>
#include <QList>

class CodeBook : public QObject
{
    Q_OBJECT

public:
    // File format version for compatibility checks
    static const quint32 CURRENT_FORMAT_VERSION = 1;
    
    // Header structure for codebook files
    struct Header {
        quint32 formatVersion;       // File format version
        quint64 totalSize;           // Total size of key material in bytes
        quint64 currentPosition;     // Current position in the key material
        quint64 created;             // Unix timestamp when created
        quint32 checksumHeader;      // Checksum for header integrity
        quint32 compartmentCount;    // Number of compartments in the book
        quint64 authSectionOffset;   // Offset to authentication section
        quint64 authSectionSize;     // Size of authentication section
        quint64 emergencyCodeOffset; // Offset to emergency destruction code
        quint8 reserved[32];         // Reserved for future use
    };
    
    // Compartment structure - inspired by mission-specific sections in Soviet codebooks
    struct Compartment {
        quint64 offset;              // Offset in the codebook
        quint64 size;                // Size of this compartment
        quint64 currentPosition;     // Current position in this compartment
        quint32 checksum;            // Compartment data checksum
        bool locked;                 // Whether this compartment is locked
        char name[32];               // Compartment name/identifier
    };

    explicit CodeBook(QObject *parent = nullptr);
    ~CodeBook();
    
    // Open an existing codebook file
    bool open(const QString &filename);
    
    // Create a new codebook file
    bool create(const QString &filename, quint64 size);
    
    // Close the current codebook
    void close();
    
    // Check if a codebook is currently open
    bool isOpen() const;
    
    // Get a portion of the key material at a specific position
    QByteArray getKeyMaterial(quint64 position, quint64 length);
    
    // Mark a portion of the key material as used
    bool markAsUsed(quint64 position, quint64 length);
    
    // Get the current position in the codebook
    quint64 getCurrentPosition() const;
    
    // Get the total amount of key material in the book
    quint64 getTotalSize() const;
    
    // Get the amount of unused key material
    quint64 getUnusedSize() const;
    
    // Get percentage of key material remaining
    double getPercentageRemaining() const;
    
    // Save changes to the codebook
    bool save();
    
    // Generate truly random key material
    static QByteArray generateRandomKeyMaterial(quint64 size);
    
    // Compartment management (inspired by mission-specific sections)
    bool createCompartment(const QString &name, quint64 size);
    bool lockCompartment(const QString &name);
    bool unlockCompartment(const QString &name, const QByteArray &key);
    QList<QString> getCompartmentNames() const;
    
    // Authentication section (inspired by agent verification codes)
    QByteArray getAuthenticationMaterial(quint64 length);
    bool markAuthenticationUsed(quint64 position, quint64 length);
    
    // Emergency protocols (inspired by emergency destruction procedures)
    void setEmergencyDestruction(const QString &code);
    bool executeEmergencyProtocol(const QString &code);
    
    // Duress signaling (inspired by agent duress codes)
    void setDuressCode(const QString &code);
    bool isDuressCode(const QString &code) const;
    
signals:
    void keyMaterialLow(double percentageRemaining);
    void error(const QString &errorMessage);
    void emergencyProtocolExecuted();
    void duressDetected();
    
private:
    QString filename;
    QFile file;
    Header header;
    QList<Compartment> compartments;
    bool modified;
    QMutex accessMutex;
    QByteArray duressCodeHash;
    QByteArray emergencyCodeHash;
    
    // Read the header from the file
    bool readHeader();
    
    // Write the header to the file
    bool writeHeader();
    
    // Read compartment information
    bool readCompartments();
    
    // Write compartment information
    bool writeCompartments();
    
    // Calculate header checksum
    quint32 calculateHeaderChecksum() const;
    
    // Validate file integrity
    bool validateIntegrity();
    
    // Securely wipe key material (for emergency protocols)
    bool secureWipe(quint64 offset, quint64 length);
    
    // Create hash from password/code
    static QByteArray hashCode(const QString &code);
};

#endif // CODEBOOK_H
