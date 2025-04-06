#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QByteArray>
#include <QString>
#include <QTimer>
#include <QThread>
#include <QTemporaryFile>
#include <memory>
#include "pad_file_manager.h"
#include "message_protocol.h"
#include "authentication.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    // Pad management
    void on_actionCreatePads_triggered();
    void on_actionOpenVault_triggered();
    void on_actionCloseVault_triggered();
    
    // Message operations
    void on_encryptButton_clicked();
    void on_decryptButton_clicked();
    void on_clearSendButton_clicked();
    void on_clearReceiveButton_clicked();
    void on_copySendButton_clicked();
    void on_copyReceiveButton_clicked();
    
    // Authentication
    void on_actionLogin_triggered();
    void on_actionLogout_triggered();
    void on_actionChangePassword_triggered();
    
    // Settings
    void on_actionSettings_triggered();
    
    // About
    void on_actionAbout_triggered();
    void on_actionAboutQt_triggered();
    
    // Exit
    void on_actionExit_triggered();
    
    // Status updates
    void updateKeyStatus();

private:
    // UI
    Ui::MainWindow *ui;
    
    // Pad management
    std::unique_ptr<otp::PadVaultManager> padVault;
    std::unique_ptr<otp::MessageProtocol> messageProtocol;
    std::unique_ptr<Authentication> authentication;
    
    // Status tracking
    bool vaultOpen;
    bool authenticated;
    
    // Status update timer
    QTimer statusUpdateTimer;
    
    // Helper methods
    void initializeUI();
    void updateUIState();
    void displayError(const QString& message);
    void displaySuccess(const QString& message);
    
    // Settings
    QString vaultPath;
    QString masterPassword;
    
    // Load/save settings
    void loadSettings();
    void saveSettings();
};

#endif // MAINWINDOW_H
