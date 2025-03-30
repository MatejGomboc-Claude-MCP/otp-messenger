#include "authentication.h"
#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QDateTime>
#include <QtEndian>
#include <QDebug>
#include <QSettings>

// Time-based OTP constants
const int TOTP_PERIOD = 30; // 30-second TOTP period
const int TOTP_DIGITS = 6;  // 6-digit TOTP code
const int TOTP_HASH_ALGO = QCryptographicHash::Sha1; // SHA-1 for TOTP (for compatibility with standard authenticators)

Authentication::Authentication(QObject *parent)
    : QObject(parent), securityLevel(SecurityLevel::Basic), 
      biometricEnabled(false), hardwareTokenEnabled(false)
{
    // Load stored authentication settings from QSettings
    loadSettings();
}

void Authentication::setSecurityLevel(SecurityLevel level)
{
    securityLevel = level;
    
    // Save to settings
    QSettings settings;
    settings.setValue("Authentication/SecurityLevel", static_cast<int>(level));
    
    // Check if the required authentication methods are available for this level
    QList<Method> requiredMethods = getRequiredMethodsForLevel(level);
    bool allAvailable = true;
    
    for (Method method : requiredMethods) {
        switch (method) {
            case Method::Biometric:
                if (!isBiometricAvailable()) {
                    allAvailable = false;
                    emit authenticationFailed(tr("Biometric authentication is required but not available"));
                }
                break;
            case Method::HardwareToken:
                if (!isHardwareTokenAvailable()) {
                    allAvailable = false;
                    emit authenticationFailed(tr("Hardware token is required but not available"));
                }
                break;
            default:
                // Password and TOTP are always available
                break;
        }
    }
    
    if (!allAvailable) {
        // Revert to a lower security level if required methods aren't available
        if (level == SecurityLevel::Maximum) {
            setSecurityLevel(SecurityLevel::High);
        } else if (level == SecurityLevel::High) {
            setSecurityLevel(SecurityLevel::Standard);
        } else if (level == SecurityLevel::Standard) {
            setSecurityLevel(SecurityLevel::Basic);
        }
    }
}

Authentication::SecurityLevel Authentication::getSecurityLevel() const
{
    return securityLevel;
}

bool Authentication::setPassword(const QString &password)
{
    if (password.isEmpty()) {
        emit authenticationFailed(tr("Password cannot be empty"));
        return false;
    }
    
    // Generate a new random salt
    QByteArray salt = generateSalt();
    
    // Hash the password with the salt
    QByteArray hash = hashPassword(password, salt);
    
    // Store the salt and hash
    passwordSalt = salt;
    passwordHash = hash;
    
    // Save to settings
    QSettings settings;
    settings.setValue("Authentication/PasswordHash", passwordHash.toBase64());
    settings.setValue("Authentication/PasswordSalt", passwordSalt.toBase64());
    
    return true;
}

bool Authentication::verifyPassword(const QString &password)
{
    if (passwordHash.isEmpty() || passwordSalt.isEmpty()) {
        emit authenticationFailed(tr("No password has been set"));
        return false;
    }
    
    // Hash the provided password with the stored salt
    QByteArray hash = hashPassword(password, passwordSalt);
    
    // Compare with stored hash
    bool result = (hash == passwordHash);
    
    if (!result) {
        emit authenticationFailed(tr("Incorrect password"));
    }
    
    return result;
}

QString Authentication::generateTOTPSecret()
{
    // Generate a random 20-byte secret (160 bits)
    QByteArray secret;
    secret.resize(20);
    
    QRandomGenerator *generator = QRandomGenerator::system();
    for (int i = 0; i < secret.size(); ++i) {
        secret[i] = static_cast<char>(generator->bounded(256));
    }
    
    // Encode in base32 (simplified for demonstration)
    static const char base32Chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    QString base32Secret;
    
    for (int i = 0; i < secret.size(); i += 5) {
        int remaining = qMin(5, secret.size() - i);
        quint64 buffer = 0;
        
        // Combine up to 5 bytes into a 40-bit buffer
        for (int j = 0; j < remaining; ++j) {
            buffer |= static_cast<quint64>(static_cast<unsigned char>(secret[i + j])) << ((4 - j) * 8);
        }
        
        // Extract 5-bit chunks and convert to base32 characters
        for (int j = 0; j < (remaining * 8 + 4) / 5; ++j) {
            int index = (buffer >> (35 - j * 5)) & 0x1F;
            base32Secret.append(base32Chars[index]);
        }
    }
    
    // Save the secret
    totpSecret = base32Secret;
    
    // Save to settings
    QSettings settings;
    settings.setValue("Authentication/TOTPSecret", totpSecret);
    
    return totpSecret;
}

QString Authentication::getTOTPSecret() const
{
    return totpSecret;
}

bool Authentication::verifyTOTP(const QString &code)
{
    if (totpSecret.isEmpty()) {
        emit authenticationFailed(tr("TOTP has not been set up"));
        return false;
    }
    
    // Allow for time skew by checking the current and adjacent intervals
    quint64 currentTime = QDateTime::currentSecsSinceEpoch();
    
    for (int offset = -1; offset <= 1; ++offset) {
        QString expectedCode = calculateTOTP(totpSecret, currentTime + offset * TOTP_PERIOD);
        if (code == expectedCode) {
            return true;
        }
    }
    
    emit authenticationFailed(tr("Invalid TOTP code"));
    return false;
}

QString Authentication::getCurrentTOTP() const
{
    if (totpSecret.isEmpty()) {
        return QString();
    }
    
    quint64 currentTime = QDateTime::currentSecsSinceEpoch();
    return calculateTOTP(totpSecret, currentTime);
}

bool Authentication::isBiometricAvailable() const
{
    // In a real implementation, we would check the system capabilities
    // For demonstration, we'll assume it's available on certain platforms
    
#ifdef Q_OS_MACOS
    // macOS with Touch ID
    return true;
#elif defined(Q_OS_WIN)
    // Windows with Windows Hello
    return true;
#elif defined(Q_OS_ANDROID) || defined(Q_OS_IOS)
    // Mobile platforms with biometric sensors
    return true;
#else
    // Other platforms - would need to check for specific capabilities
    return false;
#endif
}

bool Authentication::enableBiometric()
{
    if (!isBiometricAvailable()) {
        emit authenticationFailed(tr("Biometric authentication is not available on this device"));
        return false;
    }
    
    // In a real implementation, we would initialize the biometric system
    // For demonstration, we'll just set a flag
    
    biometricEnabled = true;
    
    // Save to settings
    QSettings settings;
    settings.setValue("Authentication/BiometricEnabled", biometricEnabled);
    
    return true;
}

bool Authentication::verifyBiometric()
{
    if (!biometricEnabled) {
        emit authenticationFailed(tr("Biometric authentication is not enabled"));
        return false;
    }
    
    if (!isBiometricAvailable()) {
        emit authenticationFailed(tr("Biometric authentication is not available on this device"));
        return false;
    }
    
    // In a real implementation, we would prompt for biometric verification
    // For demonstration, we'll just emit a signal for the UI to handle
    
    emit biometricPromptRequired();
    
    // The actual verification would be handled asynchronously by the UI
    // and would call back to complete the authentication process
    
    // For now, we'll return true to indicate the process has started
    return true;
}

bool Authentication::isHardwareTokenAvailable() const
{
    // In a real implementation, we would check for connected hardware tokens
    // For demonstration, we'll assume it's not available
    
    return false;
}

bool Authentication::enableHardwareToken()
{
    if (!isHardwareTokenAvailable()) {
        emit authenticationFailed(tr("Hardware token is not available"));
        return false;
    }
    
    // In a real implementation, we would initialize the hardware token
    // For demonstration, we'll just set a flag
    
    hardwareTokenEnabled = true;
    
    // Save to settings
    QSettings settings;
    settings.setValue("Authentication/HardwareTokenEnabled", hardwareTokenEnabled);
    
    return true;
}

bool Authentication::verifyHardwareToken(const QByteArray &response)
{
    if (!hardwareTokenEnabled) {
        emit authenticationFailed(tr("Hardware token authentication is not enabled"));
        return false;
    }
    
    if (!isHardwareTokenAvailable()) {
        emit authenticationFailed(tr("Hardware token is not available"));
        return false;
    }
    
    // In a real implementation, we would verify the token response
    // For demonstration, we'll just emit a signal for the UI to handle
    
    emit hardwareTokenPromptRequired();
    
    // The actual verification would be handled asynchronously by the UI
    // and would call back to complete the authentication process
    
    // For now, we'll return true to indicate the process has started
    return true;
}

bool Authentication::startAuthentication()
{
    // Clear any previous authentication state
    activeAuthMethods.clear();
    
    // Get the required authentication methods for the current security level
    activeAuthMethods = getRequiredMethodsForLevel(securityLevel);
    
    // Check if we have the necessary methods enabled
    for (Method method : activeAuthMethods) {
        switch (method) {
            case Method::Password:
                if (passwordHash.isEmpty()) {
                    emit authenticationFailed(tr("Password has not been set"));
                    return false;
                }
                break;
            case Method::TOTP:
                if (totpSecret.isEmpty()) {
                    emit authenticationFailed(tr("TOTP has not been set up"));
                    return false;
                }
                break;
            case Method::Biometric:
                if (!biometricEnabled || !isBiometricAvailable()) {
                    emit authenticationFailed(tr("Biometric authentication is required but not available"));
                    return false;
                }
                break;
            case Method::HardwareToken:
                if (!hardwareTokenEnabled || !isHardwareTokenAvailable()) {
                    emit authenticationFailed(tr("Hardware token is required but not available"));
                    return false;
                }
                break;
        }
    }
    
    return true;
}

bool Authentication::completeAuthentication(const QMap<Method, QString> &factors)
{
    // Make sure we're in the middle of an authentication process
    if (activeAuthMethods.isEmpty()) {
        emit authenticationFailed(tr("No authentication process is active"));
        return false;
    }
    
    // Verify each required factor
    for (Method method : activeAuthMethods) {
        if (!factors.contains(method)) {
            emit authenticationFailed(tr("Missing authentication factor: %1").arg(methodToString(method)));
            return false;
        }
        
        bool factorVerified = false;
        
        switch (method) {
            case Method::Password:
                factorVerified = verifyPassword(factors[method]);
                break;
            case Method::TOTP:
                factorVerified = verifyTOTP(factors[method]);
                break;
            case Method::Biometric:
                // Biometric verification should have been done via verifyBiometric()
                // and the result passed in the factors map
                factorVerified = (factors[method] == "verified");
                break;
            case Method::HardwareToken:
                // Hardware token verification should have been done via verifyHardwareToken()
                // and the result passed in the factors map
                factorVerified = (factors[method] == "verified");
                break;
        }
        
        if (!factorVerified) {
            // Error message already emitted by the individual verification methods
            return false;
        }
    }
    
    // If we got here, all factors were verified successfully
    lastAuthentication = QDateTime::currentDateTime();
    
    emit authenticationSuccessful();
    
    return true;
}

QList<Authentication::Method> Authentication::getRequiredMethodsForLevel(SecurityLevel level)
{
    QList<Method> methods;
    
    switch (level) {
        case SecurityLevel::Basic:
            methods.append(Method::Password);
            break;
            
        case SecurityLevel::Standard:
            methods.append(Method::Password);
            methods.append(Method::TOTP);
            break;
            
        case SecurityLevel::High:
            methods.append(Method::Password);
            methods.append(Method::Biometric);
            break;
            
        case SecurityLevel::Maximum:
            methods.append(Method::Password);
            methods.append(Method::Biometric);
            methods.append(Method::HardwareToken);
            break;
    }
    
    return methods;
}

QString Authentication::methodToString(Method method)
{
    switch (method) {
        case Method::Password:
            return tr("Password");
        case Method::TOTP:
            return tr("One-Time Password");
        case Method::Biometric:
            return tr("Biometric");
        case Method::HardwareToken:
            return tr("Hardware Token");
        default:
            return tr("Unknown");
    }
}

// Private methods

QByteArray Authentication::hashPassword(const QString &password, const QByteArray &salt)
{
    // Use a strong hash function with multiple iterations
    // PBKDF2 would be better, but for demonstration we'll use a simple approach
    
    QByteArray passwordBytes = password.toUtf8();
    QByteArray combined = salt + passwordBytes;
    
    // Multiple iterations to slow down brute force attacks
    QByteArray hash = combined;
    for (int i = 0; i < 10000; ++i) {
        hash = QCryptographicHash::hash(hash, QCryptographicHash::Sha256);
    }
    
    return hash;
}

QByteArray Authentication::generateSalt()
{
    // Generate a random 16-byte salt
    QByteArray salt;
    salt.resize(16);
    
    QRandomGenerator *generator = QRandomGenerator::system();
    for (int i = 0; i < salt.size(); ++i) {
        salt[i] = static_cast<char>(generator->bounded(256));
    }
    
    return salt;
}

QString Authentication::calculateTOTP(const QString &secret, quint64 time)
{
    // Decode base32 secret
    QByteArray key;
    QString base32Secret = secret.toUpper();
    
    static const char base32Chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    QByteArray charMap(256, -1);
    for (int i = 0; i < 32; ++i) {
        charMap[base32Chars[i]] = i;
    }
    
    // Process 8 characters (40 bits) at a time
    for (int i = 0; i < base32Secret.length(); i += 8) {
        quint64 buffer = 0;
        int bitsLeft = 0;
        
        // Process up to 8 characters
        for (int j = 0; j < 8 && i + j < base32Secret.length(); ++j) {
            char c = base32Secret[i + j].toLatin1();
            if (charMap[c] == -1) {
                continue; // Skip invalid characters
            }
            
            buffer <<= 5;
            buffer |= charMap[c] & 0x1F;
            bitsLeft += 5;
            
            // If we have at least 8 bits, extract a byte
            if (bitsLeft >= 8) {
                bitsLeft -= 8;
                key.append(static_cast<char>((buffer >> bitsLeft) & 0xFF));
            }
        }
    }
    
    // Calculate time counter (floor(time / period))
    quint64 counter = time / TOTP_PERIOD;
    
    // Convert counter to big-endian bytes
    QByteArray counterBytes(8, 0);
    for (int i = 7; i >= 0; --i) {
        counterBytes[i] = counter & 0xFF;
        counter >>= 8;
    }
    
    // Calculate HMAC-SHA1(key, counter)
    QByteArray hmac = QMessageAuthenticationCode::hash(counterBytes, key, TOTP_HASH_ALGO);
    
    // Dynamic truncation
    int offset = hmac[hmac.size() - 1] & 0x0F;
    int binary = ((hmac[offset] & 0x7F) << 24) |
                 ((hmac[offset + 1] & 0xFF) << 16) |
                 ((hmac[offset + 2] & 0xFF) << 8) |
                 (hmac[offset + 3] & 0xFF);
    
    // Generate TOTP code
    int code = binary % static_cast<int>(qPow(10, TOTP_DIGITS));
    
    // Format with leading zeros if needed
    return QString("%1").arg(code, TOTP_DIGITS, 10, QChar('0'));
}

void Authentication::loadSettings()
{
    QSettings settings;
    
    // Load security level
    int levelInt = settings.value("Authentication/SecurityLevel", static_cast<int>(SecurityLevel::Basic)).toInt();
    securityLevel = static_cast<SecurityLevel>(levelInt);
    
    // Load password hash and salt
    QByteArray hashBase64 = settings.value("Authentication/PasswordHash").toByteArray();
    QByteArray saltBase64 = settings.value("Authentication/PasswordSalt").toByteArray();
    
    if (!hashBase64.isEmpty() && !saltBase64.isEmpty()) {
        passwordHash = QByteArray::fromBase64(hashBase64);
        passwordSalt = QByteArray::fromBase64(saltBase64);
    }
    
    // Load TOTP secret
    totpSecret = settings.value("Authentication/TOTPSecret").toString();
    
    // Load biometric and hardware token flags
    biometricEnabled = settings.value("Authentication/BiometricEnabled", false).toBool();
    hardwareTokenEnabled = settings.value("Authentication/HardwareTokenEnabled", false).toBool();
}
