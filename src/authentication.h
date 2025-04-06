#ifndef AUTHENTICATION_H
#define AUTHENTICATION_H

#include <QObject>
#include <QString>
#include <QByteArray>
#include <QDateTime>
#include <QMap>
#include <string>
#include <memory>
#include <vector>
#include <filesystem>
#include "secure_memory.h"

namespace otp {

/**
 * @brief The Authentication class provides multi-factor authentication for the OTP Messenger.
 * 
 * This class handles password-based authentication, TOTP, biometric authentication,
 * and hardware token-based authentication.
 */
class Authentication : public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Authentication methods supported by the system.
     */
    enum class Method {
        Password,     ///< Password-based authentication
        TOTP,         ///< Time-based One-Time Password
        Biometric,    ///< Fingerprint, face, etc.
        HardwareToken ///< External hardware token
    };
    
    /**
     * @brief Security levels with different authentication requirements.
     */
    enum class SecurityLevel {
        Basic,      ///< Password only
        Standard,   ///< Password + TOTP
        High,       ///< Password + Biometric
        Maximum     ///< Password + Biometric + Hardware token
    };

    /**
     * @brief Constructor for the Authentication class.
     * @param parent The parent QObject
     */
    explicit Authentication(QObject *parent = nullptr);
    
    /**
     * @brief Destructor ensuring secure memory cleanup.
     */
    ~Authentication();
    
    /**
     * @brief Initialize the authentication system.
     * 
     * @param configPath Path to store configuration
     * @return true if successful, false otherwise
     */
    bool initialize(const std::filesystem::path& configPath);
    
    /**
     * @brief Set the security level.
     * 
     * @param level The desired security level
     */
    void setSecurityLevel(SecurityLevel level);
    
    /**
     * @brief Get the current security level.
     * 
     * @return Current security level
     */
    SecurityLevel getSecurityLevel() const;
    
    /**
     * @brief Set the master password.
     * 
     * @param password The password to set
     * @return true if successful, false otherwise
     */
    bool setPassword(const std::string& password);
    
    /**
     * @brief Verify the master password.
     * 
     * @param password The password to verify
     * @return true if correct, false otherwise
     */
    bool verifyPassword(const std::string& password);
    
    /**
     * @brief Generate a new TOTP secret.
     * 
     * @return The generated secret in Base32 format
     */
    std::string generateTOTPSecret();
    
    /**
     * @brief Get the current TOTP secret.
     * 
     * @return The current TOTP secret
     */
    std::string getTOTPSecret() const;
    
    /**
     * @brief Verify a TOTP code.
     * 
     * @param code The TOTP code to verify
     * @return true if valid, false otherwise
     */
    bool verifyTOTP(const std::string& code);
    
    /**
     * @brief Get the current TOTP code.
     * 
     * @return The current TOTP code
     */
    std::string getCurrentTOTP() const;
    
    /**
     * @brief Check if biometric authentication is available.
     * 
     * @return true if available, false otherwise
     */
    bool isBiometricAvailable() const;
    
    /**
     * @brief Enable biometric authentication.
     * 
     * @return true if successful, false otherwise
     */
    bool enableBiometric();
    
    /**
     * @brief Verify biometric authentication.
     * 
     * @return true if successful, false otherwise
     */
    bool verifyBiometric();
    
    /**
     * @brief Check if hardware token is available.
     * 
     * @return true if available, false otherwise
     */
    bool isHardwareTokenAvailable() const;
    
    /**
     * @brief Enable hardware token authentication.
     * 
     * @return true if successful, false otherwise
     */
    bool enableHardwareToken();
    
    /**
     * @brief Verify hardware token response.
     * 
     * @param response The response from the hardware token
     * @return true if valid, false otherwise
     */
    bool verifyHardwareToken(const std::string& response);
    
    /**
     * @brief Start the authentication process.
     * 
     * @return true if started successfully, false otherwise
     */
    bool startAuthentication();
    
    /**
     * @brief Complete the authentication process with provided factors.
     * 
     * @param factors Map of authentication methods and their responses
     * @return true if authentication successful, false otherwise
     */
    bool completeAuthentication(const std::map<Method, std::string>& factors);
    
    /**
     * @brief Get methods required for the current security level.
     * 
     * @return List of required authentication methods
     */
    std::vector<Method> getRequiredMethods() const;
    
    /**
     * @brief Convert authentication method to string.
     * 
     * @param method The authentication method
     * @return String representation
     */
    static std::string methodToString(Method method);

signals:
    /**
     * @brief Signal emitted when authentication succeeds.
     */
    void authenticationSuccessful();
    
    /**
     * @brief Signal emitted when authentication fails.
     * 
     * @param reason Reason for failure
     */
    void authenticationFailed(const QString& reason);
    
    /**
     * @brief Signal emitted when biometric authentication is required.
     */
    void biometricPromptRequired();
    
    /**
     * @brief Signal emitted when hardware token verification is required.
     */
    void hardwareTokenPromptRequired();

private:
    // Configuration path
    std::filesystem::path configPath;
    
    // Security level
    SecurityLevel securityLevel;
    
    // Authentication data
    SecureBuffer passwordHash;
    SecureBuffer passwordSalt;
    std::string totpSecret;
    bool biometricEnabled;
    bool hardwareTokenEnabled;
    
    // Authentication state
    QDateTime lastAuthentication;
    std::vector<Method> activeAuthMethods;
    
    // Secure hash function
    SecureBuffer hashPassword(const std::string& password, const SecureBuffer& salt);
    
    // Generate secure random salt
    SecureBuffer generateSalt(size_t length = 16);
    
    // TOTP validation
    bool validateTOTPCode(const std::string& code, const std::string& secret);
    
    // Save/load configuration
    bool saveConfig();
    bool loadConfig();
};

} // namespace otp

#endif // AUTHENTICATION_H
