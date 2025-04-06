#include "authentication.h"
#include <random>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <QDateTime>
#include <QDebug>
#include <Windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

namespace otp {

Authentication::Authentication(QObject *parent)
    : QObject(parent), 
      securityLevel(SecurityLevel::Basic),
      biometricEnabled(false), 
      hardwareTokenEnabled(false) {
}

Authentication::~Authentication() {
    // Secure cleanup is handled by SecureBuffer destructors
}

bool Authentication::initialize(const std::filesystem::path& path) {
    configPath = path;
    
    // Create directory if it doesn't exist
    try {
        if (!std::filesystem::exists(configPath)) {
            std::filesystem::create_directories(configPath);
        }
        
        // Load configuration if it exists
        if (std::filesystem::exists(configPath / "auth_config.dat")) {
            return loadConfig();
        }
        
        // Otherwise create a new configuration
        return saveConfig();
    }
    catch (const std::exception&) {
        return false;
    }
}

void Authentication::setSecurityLevel(SecurityLevel level) {
    securityLevel = level;
    saveConfig();
}

Authentication::SecurityLevel Authentication::getSecurityLevel() const {
    return securityLevel;
}

bool Authentication::setPassword(const std::string& password) {
    try {
        // Generate a new salt
        passwordSalt = generateSalt();
        
        // Hash the password with the salt
        passwordHash = hashPassword(password, passwordSalt);
        
        // Save configuration
        return saveConfig();
    }
    catch (const std::exception&) {
        return false;
    }
}

bool Authentication::verifyPassword(const std::string& password) {
    try {
        // Hash the provided password with the stored salt
        SecureBuffer testHash = hashPassword(password, passwordSalt);
        
        // Constant-time comparison of hashes (critical for security!)
        if (testHash.size() != passwordHash.size()) {
            return false;
        }
        
        // Constant-time comparison
        unsigned char result = 0;
        for (size_t i = 0; i < testHash.size(); i++) {
            result |= testHash[i] ^ passwordHash[i];
        }
        
        return (result == 0);
    }
    catch (const std::exception&) {
        return false;
    }
}

std::string Authentication::generateTOTPSecret() {
    try {
        // Generate 20 bytes of random data (160 bits)
        const size_t secretSize = 20;
        SecureBuffer randomBytes = generateSalt(secretSize);
        
        // Base32 encoding character set
        const char base32Chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        
        // Encode as Base32
        std::string base32Secret;
        base32Secret.reserve((secretSize * 8 + 4) / 5);
        
        unsigned int buffer = 0;
        int bitsLeft = 0;
        
        for (size_t i = 0; i < secretSize; ++i) {
            buffer = (buffer << 8) | randomBytes[i];
            bitsLeft += 8;
            
            while (bitsLeft >= 5) {
                bitsLeft -= 5;
                base32Secret += base32Chars[(buffer >> bitsLeft) & 0x1F];
            }
        }
        
        // Handle remaining bits if any
        if (bitsLeft > 0) {
            base32Secret += base32Chars[(buffer << (5 - bitsLeft)) & 0x1F];
        }
        
        // Store and save the new secret
        totpSecret = base32Secret;
        saveConfig();
        
        return base32Secret;
    }
    catch (const std::exception&) {
        return "";
    }
}

std::string Authentication::getTOTPSecret() const {
    return totpSecret;
}

bool Authentication::verifyTOTP(const std::string& code) {
    return validateTOTPCode(code, totpSecret);
}

std::string Authentication::getCurrentTOTP() const {
    // This is a simplified implementation - a real one would calculate
    // the current TOTP code based on the secret and current time
    
    // Get current time step (30-second interval)
    uint64_t timeStep = QDateTime::currentSecsSinceEpoch() / 30;
    
    // In a real implementation, this would be:
    // 1. Calculate HMAC-SHA1(secret, timeStep)
    // 2. Extract 31 bits using dynamic truncation
    // 3. Take modulo 10^digits (usually 6 digits)
    
    // For demo purposes, just return a simple hash of time
    std::stringstream ss;
    ss << std::setw(6) << std::setfill('0') << (timeStep % 1000000);
    return ss.str();
}

bool Authentication::isBiometricAvailable() const {
    // On Windows, check WBF (Windows Biometric Framework) availability
    // This is a simplified check - a real implementation would be more thorough
    HMODULE wbfModule = LoadLibrary(TEXT("winbio.dll"));
    if (wbfModule != NULL) {
        FreeLibrary(wbfModule);
        return true;
    }
    return false;
}

bool Authentication::enableBiometric() {
    if (isBiometricAvailable()) {
        biometricEnabled = true;
        saveConfig();
        return true;
    }
    return false;
}

bool Authentication::verifyBiometric() {
    if (!biometricEnabled || !isBiometricAvailable()) {
        return false;
    }
    
    // In a real implementation, this would prompt for biometric verification
    // using Windows Hello or other platform-specific APIs
    
    // For demo purposes, just emit the prompt required signal
    emit biometricPromptRequired();
    
    // Always return false here - the real verification would be asynchronous
    return false;
}

bool Authentication::isHardwareTokenAvailable() const {
    // Check for hardware token support
    // This would typically involve checking for connected USB devices
    // or other hardware token interfaces
    
    // For demo purposes, always return true
    return true;
}

bool Authentication::enableHardwareToken() {
    if (isHardwareTokenAvailable()) {
        hardwareTokenEnabled = true;
        saveConfig();
        return true;
    }
    return false;
}

bool Authentication::verifyHardwareToken(const std::string& response) {
    if (!hardwareTokenEnabled || !isHardwareTokenAvailable()) {
        return false;
    }
    
    // In a real implementation, this would verify the response from a hardware token
    // For demo purposes, just check if the response is non-empty
    return !response.empty();
}

bool Authentication::startAuthentication() {
    // Reset active methods
    activeAuthMethods = getRequiredMethods();
    
    // Record start time
    lastAuthentication = QDateTime::currentDateTime();
    
    return !activeAuthMethods.empty();
}

bool Authentication::completeAuthentication(const std::map<Method, std::string>& factors) {
    // Check if authentication is in progress
    if (activeAuthMethods.empty()) {
        emit authenticationFailed(tr("No authentication in progress"));
        return false;
    }
    
    // Check if too much time has passed
    QDateTime now = QDateTime::currentDateTime();
    if (lastAuthentication.secsTo(now) > 300) { // 5 minute timeout
        emit authenticationFailed(tr("Authentication timed out"));
        return false;
    }
    
    // Verify each required method
    for (const auto& method : activeAuthMethods) {
        auto it = factors.find(method);
        if (it == factors.end()) {
            // Factor not provided
            emit authenticationFailed(tr("Missing authentication factor: %1")
                                     .arg(QString::fromStdString(methodToString(method))));
            return false;
        }
        
        bool verified = false;
        switch (method) {
            case Method::Password:
                verified = verifyPassword(it->second);
                break;
            case Method::TOTP:
                verified = verifyTOTP(it->second);
                break;
            case Method::Biometric:
                verified = verifyBiometric(); // This will be async in a real implementation
                break;
            case Method::HardwareToken:
                verified = verifyHardwareToken(it->second);
                break;
        }
        
        if (!verified) {
            // Factor verification failed
            emit authenticationFailed(tr("Verification failed for: %1")
                                     .arg(QString::fromStdString(methodToString(method))));
            return false;
        }
    }
    
    // All factors verified
    emit authenticationSuccessful();
    return true;
}

std::vector<Authentication::Method> Authentication::getRequiredMethods() const {
    std::vector<Method> methods;
    
    // Password is always required
    methods.push_back(Method::Password);
    
    // Add other methods based on security level
    switch (securityLevel) {
        case SecurityLevel::Basic:
            // Only password
            break;
        case SecurityLevel::Standard:
            methods.push_back(Method::TOTP);
            break;
        case SecurityLevel::High:
            methods.push_back(Method::Biometric);
            break;
        case SecurityLevel::Maximum:
            methods.push_back(Method::Biometric);
            methods.push_back(Method::HardwareToken);
            break;
    }
    
    return methods;
}

std::string Authentication::methodToString(Method method) {
    switch (method) {
        case Method::Password:
            return "Password";
        case Method::TOTP:
            return "TOTP";
        case Method::Biometric:
            return "Biometric";
        case Method::HardwareToken:
            return "Hardware Token";
        default:
            return "Unknown";
    }
}

SecureBuffer Authentication::hashPassword(const std::string& password, const SecureBuffer& salt) {
    // Create a secure buffer for the hash
    const size_t hashSize = 32; // SHA-256 output size
    SecureBuffer hash(hashSize);
    
    // Use BCrypt to compute SHA-256
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        0);
    
    if (NT_SUCCESS(status)) {
        // Create hash object
        BCRYPT_HASH_HANDLE hHash = NULL;
        status = BCryptCreateHash(
            hAlg,
            &hHash,
            NULL,
            0,
            NULL,
            0,
            0);
        
        if (NT_SUCCESS(status)) {
            // Hash password
            status = BCryptHashData(
                hHash,
                reinterpret_cast<PUCHAR>(const_cast<char*>(password.c_str())),
                static_cast<ULONG>(password.size()),
                0);
            
            // Hash salt
            if (NT_SUCCESS(status)) {
                status = BCryptHashData(
                    hHash,
                    salt.data(),
                    static_cast<ULONG>(salt.size()),
                    0);
            }
            
            // Finalize hash
            if (NT_SUCCESS(status)) {
                status = BCryptFinishHash(
                    hHash,
                    hash.data(),
                    static_cast<ULONG>(hash.size()),
                    0);
            }
            
            // Clean up hash
            BCryptDestroyHash(hHash);
        }
        
        // Clean up algorithm
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    
    if (!NT_SUCCESS(status)) {
        throw std::runtime_error("Failed to hash password");
    }
    
    return hash;
}

SecureBuffer Authentication::generateSalt(size_t length) {
    // Create a buffer for the salt
    SecureBuffer salt(length);
    
    // Use BCrypt to generate random bytes
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_RNG_ALGORITHM,
        NULL,
        0);
    
    if (NT_SUCCESS(status)) {
        // Generate random salt
        status = BCryptGenRandom(
            hAlg,
            salt.data(),
            static_cast<ULONG>(salt.size()),
            0);
        
        // Clean up
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    
    if (!NT_SUCCESS(status)) {
        throw std::runtime_error("Failed to generate salt");
    }
    
    return salt;
}

bool Authentication::validateTOTPCode(const std::string& code, const std::string& secret) {
    // This is a simplified implementation - a real one would:
    // 1. Decode the Base32 secret
    // 2. Calculate HMAC-SHA1 for current time step and ±1 time step
    // 3. Compare with the provided code
    
    // For demo purposes, just compare with getCurrentTOTP()
    return (code == getCurrentTOTP());
}

bool Authentication::saveConfig() {
    try {
        // Create the config file path
        auto configFile = configPath / "auth_config.dat";
        
        // Open file for writing
        std::ofstream file(configFile, std::ios::binary | std::ios::trunc);
        if (!file) {
            return false;
        }
        
        // Write security level
        uint32_t level = static_cast<uint32_t>(securityLevel);
        file.write(reinterpret_cast<char*>(&level), sizeof(level));
        
        // Write password hash size and hash
        uint32_t hashSize = static_cast<uint32_t>(passwordHash.size());
        file.write(reinterpret_cast<char*>(&hashSize), sizeof(hashSize));
        file.write(reinterpret_cast<char*>(passwordHash.data()), hashSize);
        
        // Write salt size and salt
        uint32_t saltSize = static_cast<uint32_t>(passwordSalt.size());
        file.write(reinterpret_cast<char*>(&saltSize), sizeof(saltSize));
        file.write(reinterpret_cast<char*>(passwordSalt.data()), saltSize);
        
        // Write TOTP secret length and secret
        uint32_t secretLength = static_cast<uint32_t>(totpSecret.size());
        file.write(reinterpret_cast<char*>(&secretLength), sizeof(secretLength));
        file.write(totpSecret.c_str(), secretLength);
        
        // Write biometric and hardware token flags
        file.write(reinterpret_cast<char*>(&biometricEnabled), sizeof(biometricEnabled));
        file.write(reinterpret_cast<char*>(&hardwareTokenEnabled), sizeof(hardwareTokenEnabled));
        
        file.close();
        return true;
    }
    catch (const std::exception&) {
        return false;
    }
}

bool Authentication::loadConfig() {
    try {
        // Create the config file path
        auto configFile = configPath / "auth_config.dat";
        
        // Check if file exists
        if (!std::filesystem::exists(configFile)) {
            return false;
        }
        
        // Open file for reading
        std::ifstream file(configFile, std::ios::binary);
        if (!file) {
            return false;
        }
        
        // Read security level
        uint32_t level;
        file.read(reinterpret_cast<char*>(&level), sizeof(level));
        securityLevel = static_cast<SecurityLevel>(level);
        
        // Read password hash
        uint32_t hashSize;
        file.read(reinterpret_cast<char*>(&hashSize), sizeof(hashSize));
        passwordHash.resize(hashSize);
        file.read(reinterpret_cast<char*>(passwordHash.data()), hashSize);
        
        // Read salt
        uint32_t saltSize;
        file.read(reinterpret_cast<char*>(&saltSize), sizeof(saltSize));
        passwordSalt.resize(saltSize);
        file.read(reinterpret_cast<char*>(passwordSalt.data()), saltSize);
        
        // Read TOTP secret
        uint32_t secretLength;
        file.read(reinterpret_cast<char*>(&secretLength), sizeof(secretLength));
        std::vector<char> secretBuffer(secretLength + 1, 0);
        file.read(secretBuffer.data(), secretLength);
        totpSecret = std::string(secretBuffer.data(), secretLength);
        
        // Read biometric and hardware token flags
        file.read(reinterpret_cast<char*>(&biometricEnabled), sizeof(biometricEnabled));
        file.read(reinterpret_cast<char*>(&hardwareTokenEnabled), sizeof(hardwareTokenEnabled));
        
        file.close();
        return true;
    }
    catch (const std::exception&) {
        return false;
    }
}

} // namespace otp
