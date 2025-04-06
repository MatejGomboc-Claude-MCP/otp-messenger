#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QString>
#include <QTimer>
#include <QLabel>
#include <memory>
#include <string>
#include <filesystem>
#include "pad_file_manager.h"
#include "message_protocol.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    /**
     * @brief Constructor.
     * 
     * @param vaultPath Path to the pad vault
     * @param parent Parent widget
     */
    MainWindow(const std::string& vaultPath, QWidget *parent = nullptr);
    
    /**
     * @brief Destructor.
     */
    ~MainWindow();

private slots:
    // Menu actions
    void on_actionExit_triggered();
    void on_actionAbout_triggered();
    void on_actionCreatePads_triggered();
    void on_actionManagePads_triggered();
    void on_actionSettings_triggered();
    
    // Message operations
    void on_encryptButton_clicked();
    void on_decryptButton_clicked();
    void on_clearButton_clicked();
    
    // Status updates
    void updateStatus();

private:
    // UI components
    Ui::MainWindow *ui;
    QLabel* statusKeyMaterial;
    QLabel* statusPadCount;
    QTimer* statusTimer;
    
    // Core components
    std::filesystem::path vaultPath;
    std::unique_ptr<otp::PadVaultManager> padVault;
    std::unique_ptr<otp::MessageProtocol> messageProtocol;
    
    // State
    bool isVaultInitialized;
    std::string vaultPassword;
    
    // Helper methods
    void initializeVault();
    bool initializeVaultWithPassword(const QString& password);
    void updateStatusBar();
    
    // Security methods
    void zeroMemoryOnExit();
};

#endif // MAINWINDOW_H
