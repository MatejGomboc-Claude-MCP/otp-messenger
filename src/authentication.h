#ifndef AUTHENTICATION_H
#define AUTHENTICATION_H

#include <QObject>
#include <QString>
#include <QByteArray>
#include <QDateTime>
#include <QMap>

class Authentication : public QObject
{
    Q_OBJECT

public:
    // Authentication methods available
    enum class Method {
        Password,
        TOTP,
        Biometric,
        HardwareToken
    };
    
    // Security levels
    enum class SecurityLevel {
        Basic,      // Password only
        Standard,   // Password + TOTP
        High,       // Password + Biometric
        Maximum     // Password + Biometric + Hardware token
    };
    
    explicit Authentication(QObject *parent = nullptr);
    
    // Set/get the current security level
    void setSecurityLevel(SecurityLevel level);
    SecurityLevel getSecurityLevel() const;
    
    // Password authentication
    bool setPassword(const QString &password);
    bool verifyPassword(const QString &password);
    
    // TOTP (Time-based One-Time Password) authentication
    QString generateTOTPSecret();
    QString getTOTPSecret() const;
    bool verifyTOTP(const QString &code);
    QString getCurrentTOTP() const; // For display/setup
    
    // Biometric authentication
    bool isBiometricAvailable() const;
    bool enableBiometric();
    bool verifyBiometric();
    
    // Hardware token authentication
    bool isHardwareTokenAvailable() const;
    bool enableHardwareToken();
    bool verifyHardwareToken(const QByteArray &response);
    
    // Multi-factor authentication process
    bool startAuthentication();
    bool completeAuthentication(const QMap<Method, QString> &factors);
    
    // Helper functions
    static QList<Method> getRequiredMethodsForLevel(SecurityLevel level);
    static QString methodToString(Method method);
    
signals:
    void authenticationSuccessful();
    void authenticationFailed(const QString &reason);
    void biometricPromptRequired();
    void hardwareTokenPromptRequired();
    
private:
    SecurityLevel securityLevel;
    QByteArray passwordHash;
    QByteArray passwordSalt;
    QString totpSecret;
    bool biometricEnabled;
    bool hardwareTokenEnabled;
    QDateTime lastAuthentication;
    
    // Authentication methods being used in the current session
    QList<Method> activeAuthMethods;
    
    // Helper functions
    QByteArray hashPassword(const QString &password, const QByteArray &salt);
    QByteArray generateSalt();
    bool validateTOTPCode(const QString &code, const QString &secret);
};

#endif // AUTHENTICATION_H
