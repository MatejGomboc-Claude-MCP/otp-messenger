#include "cypherbook.h"
#include <QCryptographicHash>
#include <QDateTime>
#include <QRandomGenerator>
#include <QFile>
#include <QFileInfo>
#include <QMutexLocker>
#include <QtEndian>
#include <QIODevice>
#include <QDebug>

// Size of the header in bytes
constexpr quint64 HEADER_SIZE = sizeof(CypherBook::Header);
// Threshold for key material warning (20%)
constexpr double LOW_KEY_THRESHOLD = 0.20;

CypherBook::CypherBook(QObject *parent)
    : QObject(parent), modified(false)
{
    // Initialize header with zeros
    memset(&header, 0, sizeof(Header));
    header.formatVersion = CURRENT_FORMAT_VERSION;
}

CypherBook::~CypherBook()
{
    // Ensure the file is closed when the object is destroyed
    close();
}

bool CypherBook::open(const QString &filename)
{
    QMutexLocker locker(&accessMutex);
    
    // Close any open file first
    if (file.isOpen()) {
        close();
    }
    
    this->filename = filename;
    file.setFileName(filename);
    
    // Open file for reading and writing
    if (!file.open(QIODevice::ReadWrite)) {
        emit error(tr("Failed to open cypher book: %1").arg(file.errorString()));
        return false;
    }
    
    // Check if file size is at least as large as the header
    if (file.size() < static_cast<qint64>(HEADER_SIZE)) {
        emit error(tr("Invalid cypher book file format"));
        file.close();
        return false;
    }
    
    // Read header
    if (!readHeader()) {
        file.close();
        return false;
    }
    
    // Read compartment information
    if (!readCompartments()) {
        file.close();
        return false;
    }
    
    // Validate file integrity
    if (!validateIntegrity()) {
        emit error(tr("Cypher book integrity check failed"));
        file.close();
        return false;
    }
    
    // Check if key material is running low
    double percentRemaining = getPercentageRemaining();
    if (percentRemaining < LOW_KEY_THRESHOLD) {
        emit keyMaterialLow(percentRemaining);
    }
    
    return true;
}

bool CypherBook::create(const QString &filename, quint64 size)
{
    QMutexLocker locker(&accessMutex);
    
    // Close any open file first
    if (file.isOpen()) {
        close();
    }
    
    // Check if size is reasonable
    if (size < 1024) {
        emit error(tr("Cypher book size is too small"));
        return false;
    }
    
    this->filename = filename;
    file.setFileName(filename);
    
    // Open file for reading and writing
    if (!file.open(QIODevice::ReadWrite | QIODevice::Truncate)) {
        emit error(tr("Failed to create cypher book: %1").arg(file.errorString()));
        return false;
    }
    
    // Initialize the header
    memset(&header, 0, sizeof(Header));
    header.formatVersion = CURRENT_FORMAT_VERSION;
    header.totalSize = size;
    header.currentPosition = 0;
    header.created = QDateTime::currentSecsSinceEpoch();
    header.compartmentCount = 1; // Start with a single main compartment
    header.authSectionOffset = 0; // No authentication section initially
    header.authSectionSize = 0;
    header.emergencyCodeOffset = 0; // No emergency code initially
    
    // Calculate and set the header checksum
    header.checksumHeader = calculateHeaderChecksum();
    
    // Write the header to the file
    if (!writeHeader()) {
        file.close();
        return false;
    }
    
    // Create main compartment
    Compartment mainCompartment;
    mainCompartment.offset = HEADER_SIZE;
    mainCompartment.size = size;
    mainCompartment.currentPosition = 0;
    mainCompartment.checksum = 0; // Will be calculated later
    mainCompartment.locked = false;
    strncpy(mainCompartment.name, "main", sizeof(mainCompartment.name) - 1);
    mainCompartment.name[sizeof(mainCompartment.name) - 1] = '\0';
    
    compartments.append(mainCompartment);
    
    // Write compartment information to the file
    if (!writeCompartments()) {
        file.close();
        return false;
    }
    
    // Generate random key material
    QByteArray keyMaterial = generateRandomKeyMaterial(size);
    
    // Write the key material to the file
    file.seek(HEADER_SIZE + header.compartmentCount * sizeof(Compartment));
    if (file.write(keyMaterial) != keyMaterial.size()) {
        emit error(tr("Failed to write key material: %1").arg(file.errorString()));
        file.close();
        return false;
    }
    
    // Ensure all data is written to disk
    file.flush();
    
    return true;
}

void CypherBook::close()
{
    QMutexLocker locker(&accessMutex);
    
    // Save changes if the file is open and modified
    if (file.isOpen() && modified) {
        save();
    }
    
    file.close();
    filename.clear();
    compartments.clear();
    
    // Reset header
    memset(&header, 0, sizeof(Header));
    header.formatVersion = CURRENT_FORMAT_VERSION;
    
    modified = false;
}

bool CypherBook::isOpen() const
{
    return file.isOpen();
}

QByteArray CypherBook::getKeyMaterial(quint64 position, quint64 length)
{
    QMutexLocker locker(&accessMutex);
    
    if (!file.isOpen()) {
        emit error(tr("Cypher book is not open"));
        return QByteArray();
    }
    
    // Check if position and length are valid
    if (position + length > header.totalSize) {
        emit error(tr("Requested key material exceeds cypher book size"));
        return QByteArray();
    }
    
    // Calculate the actual file position
    quint64 filePosition = HEADER_SIZE + header.compartmentCount * sizeof(Compartment) + position;
    
    // Seek to the position
    if (!file.seek(filePosition)) {
        emit error(tr("Failed to seek in cypher book: %1").arg(file.errorString()));
        return QByteArray();
    }
    
    // Read the key material
    QByteArray keyMaterial = file.read(length);
    if (keyMaterial.size() != static_cast<int>(length)) {
        emit error(tr("Failed to read key material: %1").arg(file.errorString()));
        return QByteArray();
    }
    
    return keyMaterial;
}

bool CypherBook::markAsUsed(quint64 position, quint64 length)
{
    QMutexLocker locker(&accessMutex);
    
    if (!file.isOpen()) {
        emit error(tr("Cypher book is not open"));
        return false;
    }
    
    // Check if position and length are valid
    if (position + length > header.totalSize) {
        emit error(tr("Marked key material exceeds cypher book size"));
        return false;
    }
    
    // Update current position if needed
    if (position + length > header.currentPosition) {
        header.currentPosition = position + length;
        modified = true;
    }
    
    // Find which compartment this belongs to and update its position
    for (int i = 0; i < compartments.size(); ++i) {
        Compartment &comp = compartments[i];
        
        // If this position falls within this compartment
        if (position >= comp.offset && position < comp.offset + comp.size) {
            quint64 relativePos = position - comp.offset;
            
            // Update the compartment's current position if needed
            if (relativePos + length > comp.currentPosition) {
                comp.currentPosition = relativePos + length;
                modified = true;
            }
            break;
        }
    }
    
    // Check if key material is running low
    double percentRemaining = getPercentageRemaining();
    if (percentRemaining < LOW_KEY_THRESHOLD) {
        emit keyMaterialLow(percentRemaining);
    }
    
    // Write changes to disk if modified
    if (modified) {
        return writeHeader() && writeCompartments();
    }
    
    return true;
}

quint64 CypherBook::getCurrentPosition() const
{
    return header.currentPosition;
}

quint64 CypherBook::getTotalSize() const
{
    return header.totalSize;
}

quint64 CypherBook::getUnusedSize() const
{
    return header.totalSize - header.currentPosition;
}

double CypherBook::getPercentageRemaining() const
{
    if (header.totalSize == 0) {
        return 0.0;
    }
    
    return static_cast<double>(getUnusedSize()) / static_cast<double>(header.totalSize);
}

bool CypherBook::save()
{
    QMutexLocker locker(&accessMutex);
    
    if (!file.isOpen()) {
        emit error(tr("Cypher book is not open"));
        return false;
    }
    
    // Write header and compartments if modified
    if (modified) {
        // Update header checksum before writing
        header.checksumHeader = calculateHeaderChecksum();
        
        if (!writeHeader() || !writeCompartments()) {
            return false;
        }
        
        // Ensure all data is written to disk
        file.flush();
        modified = false;
    }
    
    return true;
}

QByteArray CypherBook::generateRandomKeyMaterial(quint64 size)
{
    QByteArray keyMaterial;
    keyMaterial.resize(size);
    
    // In a real implementation, this would use multiple entropy sources
    // For demonstration, we'll use Qt's random generator with a secure seed
    
    // Seed the random generator with current time, process ID, etc.
    QRandomGenerator generator(QRandomGenerator::securelySeeded());
    
    // Fill the byte array with random data
    for (quint64 i = 0; i < size; ++i) {
        keyMaterial[i] = static_cast<char>(generator.bounded(256));
    }
    
    // In a production implementation, we would combine multiple entropy sources:
    // 1. Hardware random number generator if available
    // 2. System entropy pool (/dev/urandom on Unix, CryptGenRandom on Windows)
    // 3. User-provided entropy (mouse movements, keyboard timings)
    // 4. External entropy services (e.g., quantum-based randomness services)
    
    return keyMaterial;
}

bool CypherBook::createCompartment(const QString &name, quint64 size)
{
    QMutexLocker locker(&accessMutex);
    
    if (!file.isOpen()) {
        emit error(tr("Cypher book is not open"));
        return false;
    }
    
    // Check if we have enough unused space for this compartment
    if (size > getUnusedSize()) {
        emit error(tr("Not enough unused space for new compartment"));
        return false;
    }
    
    // Check if a compartment with this name already exists
    for (const Compartment &comp : compartments) {
        if (QString(comp.name) == name) {
            emit error(tr("Compartment with name '%1' already exists").arg(name));
            return false;
        }
    }
    
    // Create new compartment
    Compartment newComp;
    newComp.offset = header.currentPosition;
    newComp.size = size;
    newComp.currentPosition = 0;
    newComp.checksum = 0; // Will be calculated later
    newComp.locked = false;
    strncpy(newComp.name, name.toUtf8().constData(), sizeof(newComp.name) - 1);
    newComp.name[sizeof(newComp.name) - 1] = '\0';
    
    // Add to compartments list
    compartments.append(newComp);
    
    // Update header
    header.compartmentCount = compartments.size();
    header.currentPosition += size;
    modified = true;
    
    // Save changes
    return save();
}

bool CypherBook::lockCompartment(const QString &name)
{
    QMutexLocker locker(&accessMutex);
    
    if (!file.isOpen()) {
        emit error(tr("Cypher book is not open"));
        return false;
    }
    
    // Find compartment by name
    for (int i = 0; i < compartments.size(); ++i) {
        if (QString(compartments[i].name) == name) {
            compartments[i].locked = true;
            modified = true;
            return save();
        }
    }
    
    emit error(tr("Compartment '%1' not found").arg(name));
    return false;
}

bool CypherBook::unlockCompartment(const QString &name, const QByteArray &key)
{
    QMutexLocker locker(&accessMutex);
    
    if (!file.isOpen()) {
        emit error(tr("Cypher book is not open"));
        return false;
    }
    
    // Find compartment by name
    for (int i = 0; i < compartments.size(); ++i) {
        if (QString(compartments[i].name) == name) {
            // In a real implementation, we would verify the key here
            // For now, just unlock the compartment
            compartments[i].locked = false;
            modified = true;
            return save();
        }
    }
    
    emit error(tr("Compartment '%1' not found").arg(name));
    return false;
}

QList<QString> CypherBook::getCompartmentNames() const
{
    QList<QString> names;
    
    for (const Compartment &comp : compartments) {
        names.append(QString(comp.name));
    }
    
    return names;
}

QByteArray CypherBook::getAuthenticationMaterial(quint64 length)
{
    QMutexLocker locker(&accessMutex);
    
    if (!file.isOpen()) {
        emit error(tr("Cypher book is not open"));
        return QByteArray();
    }
    
    // Check if authentication section exists
    if (header.authSectionOffset == 0 || header.authSectionSize == 0) {
        emit error(tr("Authentication section not configured"));
        return QByteArray();
    }
    
    // Check if there's enough material left
    if (header.authSectionSize < length) {
        emit error(tr("Not enough authentication material available"));
        return QByteArray();
    }
    
    // Calculate the file position for auth material
    quint64 filePosition = HEADER_SIZE + header.compartmentCount * sizeof(Compartment) + header.authSectionOffset;
    
    // Seek to the position
    if (!file.seek(filePosition)) {
        emit error(tr("Failed to seek in cypher book: %1").arg(file.errorString()));
        return QByteArray();
    }
    
    // Read the authentication material
    QByteArray authMaterial = file.read(length);
    if (authMaterial.size() != static_cast<int>(length)) {
        emit error(tr("Failed to read authentication material: %1").arg(file.errorString()));
        return QByteArray();
    }
    
    return authMaterial;
}

bool CypherBook::markAuthenticationUsed(quint64 position, quint64 length)
{
    // Similar to markAsUsed but for authentication section
    QMutexLocker locker(&accessMutex);
    
    if (!file.isOpen()) {
        emit error(tr("Cypher book is not open"));
        return false;
    }
    
    // Check if authentication section exists
    if (header.authSectionOffset == 0 || header.authSectionSize == 0) {
        emit error(tr("Authentication section not configured"));
        return false;
    }
    
    // Check if position and length are valid within auth section
    if (position + length > header.authSectionSize) {
        emit error(tr("Marked authentication material exceeds section size"));
        return false;
    }
    
    // In a real implementation, we would mark this portion as used
    // For now, just return success
    
    return true;
}

void CypherBook::setEmergencyDestruction(const QString &code)
{
    QMutexLocker locker(&accessMutex);
    
    // Hash the emergency code
    emergencyCodeHash = hashCode(code);
    modified = true;
    save();
}

bool CypherBook::executeEmergencyProtocol(const QString &code)
{
    QMutexLocker locker(&accessMutex);
    
    if (!file.isOpen()) {
        emit error(tr("Cypher book is not open"));
        return false;
    }
    
    // Verify the emergency code
    if (emergencyCodeHash.isEmpty() || hashCode(code) != emergencyCodeHash) {
        // Wrong code, but don't give specific error for security
        emit error(tr("Emergency protocol failed"));
        return false;
    }
    
    // Securely wipe the entire key material
    bool success = secureWipe(HEADER_SIZE + header.compartmentCount * sizeof(Compartment), header.totalSize);
    
    if (success) {
        emit emergencyProtocolExecuted();
    }
    
    return success;
}

void CypherBook::setDuressCode(const QString &code)
{
    QMutexLocker locker(&accessMutex);
    
    // Hash the duress code
    duressCodeHash = hashCode(code);
    modified = true;
    save();
}

bool CypherBook::isDuressCode(const QString &code) const
{
    if (duressCodeHash.isEmpty()) {
        return false;
    }
    
    return hashCode(code) == duressCodeHash;
}

// Private methods

bool CypherBook::readHeader()
{
    // Seek to beginning of file
    if (!file.seek(0)) {
        emit error(tr("Failed to seek in cypher book: %1").arg(file.errorString()));
        return false;
    }
    
    // Read header
    if (file.read(reinterpret_cast<char*>(&header), sizeof(Header)) != sizeof(Header)) {
        emit error(tr("Failed to read cypher book header: %1").arg(file.errorString()));
        return false;
    }
    
    // Check format version
    if (header.formatVersion > CURRENT_FORMAT_VERSION) {
        emit error(tr("Unsupported cypher book format version %1").arg(header.formatVersion));
        return false;
    }
    
    // Verify header checksum
    quint32 expectedChecksum = header.checksumHeader;
    header.checksumHeader = 0; // Zero out checksum for calculation
    quint32 calculatedChecksum = calculateHeaderChecksum();
    header.checksumHeader = expectedChecksum; // Restore checksum
    
    if (calculatedChecksum != expectedChecksum) {
        emit error(tr("Cypher book header checksum mismatch"));
        return false;
    }
    
    return true;
}

bool CypherBook::writeHeader()
{
    // Seek to beginning of file
    if (!file.seek(0)) {
        emit error(tr("Failed to seek in cypher book: %1").arg(file.errorString()));
        return false;
    }
    
    // Write header
    if (file.write(reinterpret_cast<char*>(&header), sizeof(Header)) != sizeof(Header)) {
        emit error(tr("Failed to write cypher book header: %1").arg(file.errorString()));
        return false;
    }
    
    return true;
}

bool CypherBook::readCompartments()
{
    // Clear existing compartments
    compartments.clear();
    
    // Check if there are any compartments
    if (header.compartmentCount == 0) {
        return true; // No compartments to read
    }
    
    // Seek to position after header
    if (!file.seek(HEADER_SIZE)) {
        emit error(tr("Failed to seek to compartments: %1").arg(file.errorString()));
        return false;
    }
    
    // Read each compartment
    for (quint32 i = 0; i < header.compartmentCount; ++i) {
        Compartment comp;
        if (file.read(reinterpret_cast<char*>(&comp), sizeof(Compartment)) != sizeof(Compartment)) {
            emit error(tr("Failed to read compartment %1: %2").arg(i).arg(file.errorString()));
            return false;
        }
        compartments.append(comp);
    }
    
    return true;
}

bool CypherBook::writeCompartments()
{
    // Check if there are any compartments
    if (compartments.isEmpty()) {
        return true; // No compartments to write
    }
    
    // Seek to position after header
    if (!file.seek(HEADER_SIZE)) {
        emit error(tr("Failed to seek to compartments: %1").arg(file.errorString()));
        return false;
    }
    
    // Write each compartment
    for (const Compartment &comp : compartments) {
        if (file.write(reinterpret_cast<const char*>(&comp), sizeof(Compartment)) != sizeof(Compartment)) {
            emit error(tr("Failed to write compartment: %1").arg(file.errorString()));
            return false;
        }
    }
    
    return true;
}

quint32 CypherBook::calculateHeaderChecksum() const
{
    // Create a copy of the header with checksum field zeroed
    Header headerCopy = header;
    headerCopy.checksumHeader = 0;
    
    // Calculate CRC32 checksum
    QByteArray headerData(reinterpret_cast<const char*>(&headerCopy), sizeof(Header));
    return qChecksum(headerData);
}

bool CypherBook::validateIntegrity()
{
    // Basic validation has already been done in readHeader()
    
    // Check if total size matches file size
    quint64 expectedFileSize = HEADER_SIZE + header.compartmentCount * sizeof(Compartment) + header.totalSize;
    if (file.size() != static_cast<qint64>(expectedFileSize)) {
        emit error(tr("Cypher book file size mismatch"));
        return false;
    }
    
    // In a full implementation, we would also validate compartment checksums
    
    return true;
}

bool CypherBook::secureWipe(quint64 offset, quint64 length)
{
    // Seek to the position to wipe
    if (!file.seek(offset)) {
        emit error(tr("Failed to seek during secure wipe: %1").arg(file.errorString()));
        return false;
    }
    
    // Multi-pass secure wiping (simplified for demonstration)
    
    // Pass 1: All zeros
    QByteArray zeros(4096, 0);
    for (quint64 written = 0; written < length; written += zeros.size()) {
        int chunkSize = qMin(static_cast<quint64>(zeros.size()), length - written);
        if (file.write(zeros.data(), chunkSize) != chunkSize) {
            emit error(tr("Secure wipe failed on pass 1: %1").arg(file.errorString()));
            return false;
        }
    }
    
    // Pass 2: All ones
    QByteArray ones(4096, 0xFF);
    file.seek(offset);
    for (quint64 written = 0; written < length; written += ones.size()) {
        int chunkSize = qMin(static_cast<quint64>(ones.size()), length - written);
        if (file.write(ones.data(), chunkSize) != chunkSize) {
            emit error(tr("Secure wipe failed on pass 2: %1").arg(file.errorString()));
            return false;
        }
    }
    
    // Pass 3: Random data
    QByteArray random = generateRandomKeyMaterial(4096);
    file.seek(offset);
    for (quint64 written = 0; written < length; written += random.size()) {
        int chunkSize = qMin(static_cast<quint64>(random.size()), length - written);
        if (file.write(random.data(), chunkSize) != chunkSize) {
            emit error(tr("Secure wipe failed on pass 3: %1").arg(file.errorString()));
            return false;
        }
    }
    
    // Flush changes to disk
    file.flush();
    
    return true;
}

QByteArray CypherBook::hashCode(const QString &code)
{
    // Use a strong hash function (SHA-256) with a salt
    QByteArray salt = "OTPMessenger-Salt"; // In production, this should be unique per installation
    QByteArray combined = salt + code.toUtf8();
    
    return QCryptographicHash::hash(combined, QCryptographicHash::Sha256);
}
