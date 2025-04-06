#include <QApplication>
#include <QCommandLineParser>
#include <QDir>
#include <QMessageBox>
#include <iostream>
#include <filesystem>
#include "mainwindow.h"
#include "secure_memory.h"
#include "pad_file_manager.h"
#include "message_protocol.h"
#include "secure_wiper.h"

// Enable memory protection early in the application
bool enableMemoryProtection() {
    // Tell Qt not to use temporary files
    qputenv("QT_NO_TMPDIR", "1");
    
    // Disable Qt's use of crash backup files
    qputenv("QT_NO_CRASH_HANDLER", "1");
    
    // Try to enable lock memory privileges
    return otp::SecureMemory::enableLockPrivilege();
}

int main(int argc, char *argv[]) {
    // Enable memory protection before creating any Qt objects
    bool memoryProtectionEnabled = enableMemoryProtection();
    
    QApplication app(argc, argv);
    
    // Set application metadata
    QCoreApplication::setOrganizationName("OTP Messenger");
    QCoreApplication::setApplicationName("OTP Messenger");
    QCoreApplication::setApplicationVersion("1.0.0");
    
    // Parse command line arguments
    QCommandLineParser parser;
    parser.setApplicationDescription("Encrypted messenger using One-Time Pad encryption");
    parser.addHelpOption();
    parser.addVersionOption();
    
    // Add command line options
    QCommandLineOption debugOption(QStringList() << "d" << "debug", "Enable debug output");
    parser.addOption(debugOption);
    
    QCommandLineOption vaultPathOption(QStringList() << "v" << "vault", "Set the pad vault path", "path");
    parser.addOption(vaultPathOption);
    
    parser.process(app);
    
    // Check if memory protection was enabled
    if (!memoryProtectionEnabled) {
        QMessageBox::warning(nullptr, "Security Warning", 
                          "Failed to enable memory protection. Your sensitive data may be paged to disk.");
    }
    
    try {
        // Initialize vault path
        std::filesystem::path vaultPath;
        if (parser.isSet(vaultPathOption)) {
            vaultPath = parser.value(vaultPathOption).toStdString();
        } else {
            // Default vault path
            vaultPath = QDir::homePath().toStdString() + "/.otp-messenger/vault";
        }
        
        // Create vault directory if it doesn't exist
        std::filesystem::create_directories(vaultPath);
        
        // Initialize the main window
        MainWindow w(vaultPath.string());
        w.show();
        
        return app.exec();
    }
    catch (const std::exception& e) {
        QMessageBox::critical(nullptr, "Error", 
                           QString("Failed to initialize application: %1").arg(e.what()));
        return 1;
    }
}
