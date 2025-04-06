#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>
#include <QInputDialog>
#include <QFileDialog>
#include <QClipboard>
#include <QStatusBar>
#include <QApplication>
#include <QTimer>
#include <QString>
#include <QDebug>
#include <QDateTime>
#include <QSettings>
#include <memory>
#include <string>
#include <algorithm>
#include <stdexcept>
#include "secure_memory.h"
#include "secure_wiper.h"

MainWindow::MainWindow(const std::string& vaultPath, QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , vaultPath(vaultPath)
    , isVaultInitialized(false)
{
    ui->setupUi(this);
    
    // Initialize status bar
    statusKeyMaterial = new QLabel(this);
    statusPadCount = new QLabel(this);
    
    ui->statusbar->addPermanentWidget(statusPadCount);
    ui->statusbar->addPermanentWidget(statusKeyMaterial);
    
    // Create status update timer
    statusTimer = new QTimer(this);
    connect(statusTimer, &QTimer::timeout, this, &MainWindow::updateStatus);
    statusTimer->start(5000); // Update every 5 seconds
    
    // Initialize pad vault and message protocol
    padVault = std::make_unique<otp::PadVaultManager>();
    messageProtocol = std::make_unique<otp::MessageProtocol>();
    
    // Initialize the vault
    initializeVault();
    
    // Initial status update
    updateStatusBar();
}

MainWindow::~MainWindow()
{
    // Secure cleanup
    zeroMemoryOnExit();
    
    // Delete UI
    delete ui;
}

void MainWindow::initializeVault()
{
    // Check if the vault directory exists
    if (!std::filesystem::exists(vaultPath)) {
        // Create the directory
        std::filesystem::create_directories(vaultPath);
    }
    
    // Check if any pads exist in the vault
    bool needsCreation = true;
    
    for (const auto& entry : std::filesystem::directory_iterator(vaultPath)) {
        if (entry.is_regular_file() && entry.path().filename().string().substr(0, 4) == "pad_") {
            needsCreation = false;
            break;
        }
    }
    
    if (needsCreation) {
        QMessageBox::information(this, tr("OTP Messenger"),
                              tr("Welcome to OTP Messenger!\n\nNo pads found in the vault. "
                                 "Please create some pads before sending messages."));
    } else {
        // Ask for vault password
        bool ok;
        QString password = QInputDialog::getText(this, tr("Vault Password"),
                                             tr("Enter vault password:"), QLineEdit::Password,
                                             QString(), &ok);
        if (ok && !password.isEmpty()) {
            // Initialize vault with password
            if (initializeVaultWithPassword(password)) {
                QMessageBox::information(this, tr("OTP Messenger"),
                                      tr("Vault opened successfully!"));
            } else {
                QMessageBox::critical(this, tr("Error"),
                                   tr("Failed to open vault. Please check your password."));
            }
        }
    }
}

bool MainWindow::initializeVaultWithPassword(const QString& password)
{
    try {
        // Store password securely
        vaultPassword = password.toStdString();
        
        // Initialize vault
        isVaultInitialized = padVault->initialize(vaultPath, vaultPassword);
        
        return isVaultInitialized;
    }
    catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Error"),
                           tr("Failed to initialize vault: %1").arg(e.what()));
        return false;
    }
}

void MainWindow::updateStatusBar()
{
    // Update status bar with current vault info
    if (isVaultInitialized) {
        // Get key material status
        uint64_t totalKeyMaterial = padVault->getTotalAvailableKeyMaterial();
        size_t padCount = padVault->getAvailablePadCount();
        
        // Format values
        QString keyMaterialText;
        if (totalKeyMaterial < 1024) {
            keyMaterialText = tr("%1 bytes").arg(totalKeyMaterial);
        } else if (totalKeyMaterial < 1024 * 1024) {
            keyMaterialText = tr("%1 KB").arg(totalKeyMaterial / 1024.0, 0, 'f', 1);
        } else {
            keyMaterialText = tr("%1 MB").arg(totalKeyMaterial / (1024.0 * 1024.0), 0, 'f', 1);
        }
        
        // Update labels
        statusKeyMaterial->setText(tr("Available Key Material: %1").arg(keyMaterialText));
        statusPadCount->setText(tr("Available Pads: %1").arg(padCount));
    } else {
        statusKeyMaterial->setText(tr("Vault not initialized"));
        statusPadCount->setText(tr("No pads available"));
    }
}

void MainWindow::updateStatus()
{
    // Called by timer to update status
    if (isVaultInitialized) {
        // Refresh metadata
        padVault->refreshMetadata();
    }
    
    // Update status bar
    updateStatusBar();
}

void MainWindow::zeroMemoryOnExit()
{
    // Secure cleanup of sensitive data
    if (!vaultPassword.empty()) {
        std::fill(vaultPassword.begin(), vaultPassword.end(), 0);
    }
    
    // Close vault
    if (padVault) {
        padVault->closeAllPads();
    }
}

void MainWindow::on_actionExit_triggered()
{
    // Secure cleanup before exit
    zeroMemoryOnExit();
    
    // Close application
    QApplication::quit();
}

void MainWindow::on_actionAbout_triggered()
{
    QMessageBox::about(this, tr("About OTP Messenger"),
                     tr("OTP Messenger v1.0.0\n\n"
                        "A secure messenger using One-Time Pad encryption "
                        "with individual pad files and message authentication codes.\n\n"
                        "© 2025 OTP Messenger Team"));
}

void MainWindow::on_actionCreatePads_triggered()
{
    // Check if vault is initialized
    if (!isVaultInitialized) {
        // Ask for password to initialize vault
        bool ok;
        QString password = QInputDialog::getText(this, tr("Vault Password"),
                                             tr("Enter new vault password:"),
                                             QLineEdit::Password, QString(), &ok);
        if (ok && !password.isEmpty()) {
            if (!initializeVaultWithPassword(password)) {
                return;
            }
        } else {
            return;
        }
    }
    
    // Ask for pad parameters
    bool ok;
    int padSize = QInputDialog::getInt(this, tr("Create Pads"),
                                    tr("Pad size (KB):"), 512, 1, 10240, 1, &ok);
    if (!ok) {
        return;
    }
    
    int padCount = QInputDialog::getInt(this, tr("Create Pads"),
                                     tr("Number of pads:"), 10, 1, 1000, 1, &ok);
    if (!ok) {
        return;
    }
    
    // Create pads
    try {
        if (padVault->createPads(padSize * 1024, padCount, vaultPassword)) {
            QMessageBox::information(this, tr("Success"),
                                   tr("Successfully created %1 pads of %2 KB each.")
                                   .arg(padCount).arg(padSize));
        } else {
            QMessageBox::critical(this, tr("Error"),
                               tr("Failed to create pads."));
        }
    }
    catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Error"),
                           tr("Failed to create pads: %1").arg(e.what()));
    }
    
    // Update status
    updateStatusBar();
}

void MainWindow::on_actionManagePads_triggered()
{
    // TODO: Implement pad management dialog
    QMessageBox::information(this, tr("Coming Soon"),
                          tr("Pad management functionality is coming soon."));
}

void MainWindow::on_actionSettings_triggered()
{
    // TODO: Implement settings dialog
    QMessageBox::information(this, tr("Coming Soon"),
                          tr("Settings functionality is coming soon."));
}

void MainWindow::on_encryptButton_clicked()
{
    // Check if vault is initialized
    if (!isVaultInitialized) {
        QMessageBox::warning(this, tr("Warning"),
                          tr("Please initialize the vault first."));
        return;
    }
    
    // Get message from text edit
    QString plaintext = ui->plainTextEdit->toPlainText();
    if (plaintext.isEmpty()) {
        QMessageBox::warning(this, tr("Warning"),
                          tr("Please enter a message to encrypt."));
        return;
    }
    
    try {
        // Encrypt message
        otp::SecureBuffer encryptedMessage = messageProtocol->createTextMessage(
            plaintext.toStdString(), *padVault);
        
        // Convert to Base64 for easier handling
        QByteArray base64Data = QByteArray(
            reinterpret_cast<const char*>(encryptedMessage.data()),
            static_cast<int>(encryptedMessage.size())).toBase64();
        
        // Display in cipherTextEdit
        ui->cipherTextEdit->setPlainText(QString(base64Data));
        
        // Copy to clipboard
        QApplication::clipboard()->setText(QString(base64Data));
        
        // Update status
        updateStatusBar();
        
        QMessageBox::information(this, tr("Success"),
                              tr("Message encrypted and copied to clipboard."));
    }
    catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Error"),
                           tr("Failed to encrypt message: %1").arg(e.what()));
    }
}

void MainWindow::on_decryptButton_clicked()
{
    // Check if vault is initialized
    if (!isVaultInitialized) {
        QMessageBox::warning(this, tr("Warning"),
                          tr("Please initialize the vault first."));
        return;
    }
    
    // Get ciphertext from text edit
    QString base64Ciphertext = ui->cipherTextEdit->toPlainText();
    if (base64Ciphertext.isEmpty()) {
        QMessageBox::warning(this, tr("Warning"),
                          tr("Please enter a message to decrypt."));
        return;
    }
    
    try {
        // Decode Base64
        QByteArray encryptedData = QByteArray::fromBase64(base64Ciphertext.toLatin1());
        
        // Convert to SecureBuffer
        otp::SecureBuffer encryptedMessage(
            reinterpret_cast<const uint8_t*>(encryptedData.constData()),
            encryptedData.size());
        
        // Decrypt message
        otp::MessageProtocol::MessageType type;
        otp::SecureBuffer decryptedPayload;
        
        if (messageProtocol->parseMessage(encryptedMessage, *padVault, type, decryptedPayload)) {
            // Check message type
            if (type == otp::MessageProtocol::MessageType::Text) {
                // Extract text
                std::string text = messageProtocol->extractText(decryptedPayload);
                
                // Display in plainTextEdit
                ui->plainTextEdit->setPlainText(QString::fromStdString(text));
                
                // Update status
                updateStatusBar();
                
                QMessageBox::information(this, tr("Success"),
                                      tr("Message decrypted successfully."));
            } 
            else if (type == otp::MessageProtocol::MessageType::Duress) {
                // Handle duress message - in a real app, you might have special handling
                // Extract text
                std::string text = messageProtocol->extractText(decryptedPayload);
                
                // Display in plainTextEdit
                ui->plainTextEdit->setPlainText(QString::fromStdString(text));
                
                // Warn about duress
                QMessageBox::warning(this, tr("Duress Message"),
                                  tr("Warning: This appears to be a duress message!"));
            }
            else {
                QMessageBox::warning(this, tr("Warning"),
                                  tr("Unsupported message type."));
            }
        } else {
            QMessageBox::critical(this, tr("Error"),
                               tr("Failed to decrypt message. It may be corrupted or "
                                  "you may not have the correct pad."));
        }
    }
    catch (const std::exception& e) {
        QMessageBox::critical(this, tr("Error"),
                           tr("Failed to decrypt message: %1").arg(e.what()));
    }
}

void MainWindow::on_clearButton_clicked()
{
    // Clear both text fields
    ui->plainTextEdit->clear();
    ui->cipherTextEdit->clear();
}
