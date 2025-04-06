#include <QApplication>
#include <QDir>
#include <QStandardPaths>
#include <QMessageBox>
#include "mainwindow.h"
#include "secure_memory.h"

int main(int argc, char *argv[])
{
    // Prevent Qt from using temporary files
    qputenv("QT_NO_TMPDIR", "1");
    
    // Disable Qt's crash handler (which would write to disk)
    qputenv("QT_NO_CRASH_HANDLER", "1");
    
    // Create application
    QApplication app(argc, argv);
    
    // Set application information
    QApplication::setApplicationName("OTP Messenger");
    QApplication::setApplicationVersion("1.0.0");
    QApplication::setOrganizationName("MatejGomboc-Claude-MCP");
    QApplication::setOrganizationDomain("github.com/MatejGomboc-Claude-MCP");
    
    // Enable memory protection
    try {
        if (!otp::SecureMemory::enableLockPrivilege()) {
            QMessageBox::warning(nullptr, "Memory Protection",
                               "Failed to enable memory protection. "
                               "Sensitive data might be swapped to disk.");
        }
    }
    catch (const std::exception& ex) {
        QMessageBox::warning(nullptr, "Memory Protection Error",
                           QString("Error enabling memory protection: %1").arg(ex.what()));
    }
    
    // Create application data directory if it doesn't exist
    QDir appDataDir(QStandardPaths::writableLocation(QStandardPaths::AppDataLocation));
    if (!appDataDir.exists()) {
        appDataDir.mkpath(".");
    }
    
    // Create the main window
    MainWindow mainWindow;
    mainWindow.show();
    
    // Run the application
    return app.exec();
}
