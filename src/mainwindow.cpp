#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>
#include <QFileDialog>
#include <QSettings>
#include <QClipboard>
#include <QInputDialog>
#include <QDateTime>
#include <QGraphicsScene>
#include <QGraphicsRectItem>
#include <QTableWidgetItem>
#include <QDebug>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow), 
      codeBook(nullptr), cryptoEngine(nullptr), messageProtocol(nullptr),
      authentication(nullptr), codeBookModified(false)
{
    ui->setupUi(this);
    
    // Initialize components
    initializeComponents();
    
    // Setup UI connections
    setupConnections();
    
    // Load settings
    loadSettings();
    
    // Update status bar
    updateStatusBar();
}

MainWindow::~MainWindow()
{
    // Save settings
    saveSettings();
    
    // Close codebook if open
    if (codeBook && codeBook->isOpen()) {
        codeBook->close();
    }
    
    // Delete components
    delete messageProtocol;
    delete cryptoEngine;
    delete codeBook;
    delete authentication;
    
    delete ui;
}

// File menu actions

void MainWindow::on_actionNew_Cypher_Book_triggered()
{
    // Note: Action name in UI still needs to be updated
    
    // Check if we need to save any changes
    if (!maybeSave()) {
        return;
    }
    
    // Ask for file location
    QString fileName = QFileDialog::getSaveFileName(this,
        tr("Create New Codebook"), QString(),
        tr("Codebooks (*.codebook);;All Files (*)"));
    
    if (fileName.isEmpty()) {
        return;
    }
    
    // Ensure the file has the correct extension
    if (!fileName.endsWith(".codebook", Qt::CaseInsensitive)) {
        fileName.append(".codebook");
    }
    
    // Ask for size
    bool ok;
    int sizeMB = QInputDialog::getInt(this, tr("Codebook Size"),
        tr("Enter size in megabytes (1-1024):"), 10, 1, 1024, 1, &ok);
    
    if (!ok) {
        return;
    }
    
    // Convert to bytes
    quint64 sizeBytes = static_cast<quint64>(sizeMB) * 1024 * 1024;
    
    // Create new codebook
    if (codeBook->create(fileName, sizeBytes)) {
        codeBookPath = fileName;
        codeBookModified = false;
        ui->lineEditCypherBook->setText(fileName);
        
        // Update codebook information
        updateCodeBookInfo();
        
        QMessageBox::information(this, tr("Codebook Created"),
            tr("New codebook created successfully."));
    } else {
        QMessageBox::critical(this, tr("Error"),
            tr("Failed to create codebook."));
    }
}

void MainWindow::on_actionOpen_Cypher_Book_triggered()
{
    // Note: Action name in UI still needs to be updated
    
    // Check if we need to save any changes
    if (!maybeSave()) {
        return;
    }
    
    // Ask for file location
    QString fileName = QFileDialog::getOpenFileName(this,
        tr("Open Codebook"), QString(),
        tr("Codebooks (*.codebook);;All Files (*)"));
    
    if (fileName.isEmpty()) {
        return;
    }
    
    // Open codebook
    if (loadCodeBook(fileName)) {
        codeBookPath = fileName;
        codeBookModified = false;
        ui->lineEditCypherBook->setText(fileName);
        
        // Update codebook information
        updateCodeBookInfo();
    } else {
        QMessageBox::critical(this, tr("Error"),
            tr("Failed to open codebook."));
    }
}

void MainWindow::on_actionSave_Cypher_Book_triggered()
{
    // Note: Action name in UI still needs to be updated
    
    // Save the codebook
    if (!codeBook || !codeBook->isOpen()) {
        QMessageBox::warning(this, tr("Warning"),
            tr("No codebook is currently open."));
        return;
    }
    
    if (codeBook->save()) {
        codeBookModified = false;
        statusBar()->showMessage(tr("Codebook saved"), 3000);
    } else {
        QMessageBox::critical(this, tr("Error"),
            tr("Failed to save codebook."));
    }
}

void MainWindow::on_actionExit_triggered()
{
    close();
}

// Message menu actions

void MainWindow::on_actionSend_Message_triggered()
{
    // Switch to the Message tab
    ui->tabWidget->setCurrentIndex(0);
    
    // Focus the send text area
    ui->plainTextEditSend->setFocus();
}

void MainWindow::on_actionReceive_Message_triggered()
{
    // Switch to the Message tab
    ui->tabWidget->setCurrentIndex(0);
    
    // Focus the receive text area
    ui->plainTextEditReceive->setFocus();
}

void MainWindow::on_actionClear_Messages_triggered()
{
    // Clear both message areas
    ui->plainTextEditSend->clear();
    ui->plainTextEditReceive->clear();
}

// Settings menu actions

void MainWindow::on_actionPreferences_triggered()
{
    // Show preferences dialog (not implemented)
    QMessageBox::information(this, tr("Preferences"),
        tr("Preferences dialog is not implemented in this version."));
}

void MainWindow::on_actionAuthentication_triggered()
{
    // Switch to the Security tab
    ui->tabWidget->setCurrentIndex(2);
}

// Help menu actions

void MainWindow::on_actionAbout_triggered()
{
    QMessageBox::about(this, tr("About OTP Messenger"),
        tr("<h3>OTP Messenger</h3>"
           "<p>Version 0.1</p>"
           "<p>A hobby Qt6 C++ encrypted messenger application using "
           "One-Time Pad (OTP) encryption.</p>"
           "<p>This is an educational project inspired by Cold War era "
           "cryptographic techniques.</p>"
           "<p>&copy; 2025 OTP Messenger Contributors</p>"));
}

// Message tab buttons

void MainWindow::on_pushButtonOpenCypherBook_clicked()
{
    // Note: Button name in UI still needs to be updated
    on_actionOpen_Cypher_Book_triggered();
}

void MainWindow::on_pushButtonNewCypherBook_clicked()
{
    // Note: Button name in UI still needs to be updated
    on_actionNew_Cypher_Book_triggered();
}

void MainWindow::on_pushButtonSend_clicked()
{
    // Check if a codebook is open
    if (!codeBook || !codeBook->isOpen()) {
        QMessageBox::warning(this, tr("Warning"),
            tr("You must open a codebook first."));
        return;
    }
    
    // Get the message text
    QString messageText = ui->plainTextEditSend->toPlainText();
    if (messageText.isEmpty()) {
        QMessageBox::warning(this, tr("Warning"),
            tr("Please enter a message to encrypt."));
        return;
    }
    
    // Create a message using the message protocol
    QByteArray encryptedMessage = messageProtocol->createTextMessage(messageText);
    
    if (encryptedMessage.isEmpty()) {
        QMessageBox::critical(this, tr("Error"),
            tr("Failed to encrypt message."));
        return;
    }
    
    // Display the encrypted message
    ui->plainTextEditReceive->setPlainText(encryptedMessage.toBase64());
    
    // Copy to clipboard
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(encryptedMessage.toBase64());
    
    statusBar()->showMessage(tr("Message encrypted and copied to clipboard"), 3000);
}

void MainWindow::on_pushButtonClear_clicked()
{
    ui->plainTextEditSend->clear();
}

void MainWindow::on_pushButtonPaste_clicked()
{
    // Paste from clipboard
    QClipboard *clipboard = QApplication::clipboard();
    ui->plainTextEditReceive->setPlainText(clipboard->text());
}

void MainWindow::on_pushButtonClearReceive_clicked()
{
    ui->plainTextEditReceive->clear();
}

void MainWindow::on_pushButtonDecrypt_clicked()
{
    // Check if a codebook is open
    if (!codeBook || !codeBook->isOpen()) {
        QMessageBox::warning(this, tr("Warning"),
            tr("You must open a codebook first."));
        return;
    }
    
    // Get the encrypted message
    QString base64Text = ui->plainTextEditReceive->toPlainText();
    if (base64Text.isEmpty()) {
        QMessageBox::warning(this, tr("Warning"),
            tr("Please enter an encrypted message to decrypt."));
        return;
    }
    
    // Convert from base64
    QByteArray encryptedMessage = QByteArray::fromBase64(base64Text.toUtf8());
    if (encryptedMessage.isEmpty()) {
        QMessageBox::critical(this, tr("Error"),
            tr("Invalid message format. The message must be base64 encoded."));
        return;
    }
    
    // Parse the message
    MessageProtocol::Message message = messageProtocol->parseMessage(encryptedMessage);
    
    // Check for duress indicators
    if (messageProtocol->isDuressMessage(message)) {
        QMessageBox::warning(this, tr("Duress Warning"),
            tr("This message contains duress indicators!"));
    }
    
    // Extract the actual content based on message type
    QString decryptedText;
    
    switch (message.type) {
        case MessageProtocol::MessageType::Text:
        case MessageProtocol::MessageType::Duress:
            decryptedText = messageProtocol->extractTextMessage(message);
            break;
            
        case MessageProtocol::MessageType::FileTransfer:
            handleFileTransferMessage(message);
            return;
            
        case MessageProtocol::MessageType::Challenge:
            handleChallengeMessage(message);
            return;
            
        case MessageProtocol::MessageType::CodePhrase:
            handleCodePhraseMessage(message);
            return;
            
        default:
            QMessageBox::information(this, tr("Message Info"),
                tr("Special message type: %1").arg(
                    static_cast<int>(message.type)));
            return;
    }
    
    if (decryptedText.isEmpty()) {
        QMessageBox::critical(this, tr("Error"),
            tr("Failed to decrypt message."));
        return;
    }
    
    // Display the decrypted message
    ui->plainTextEditSend->setPlainText(decryptedText);
    
    statusBar()->showMessage(tr("Message decrypted successfully"), 3000);
}

void MainWindow::on_pushButtonAttach_clicked()
{
    // Not implemented
    QMessageBox::information(this, tr("Not Implemented"),
        tr("File attachment functionality is not implemented in this version."));
}

void MainWindow::on_pushButtonChallenge_clicked()
{
    // Not implemented
    QMessageBox::information(this, tr("Not Implemented"),
        tr("Challenge functionality is not implemented in this version."));
}

void MainWindow::on_pushButtonCodePhrase_clicked()
{
    // Not implemented
    QMessageBox::information(this, tr("Not Implemented"),
        tr("Code phrase functionality is not implemented in this version."));
}

void MainWindow::on_pushButtonLoadFromFile_clicked()
{
    // Ask for file location
    QString fileName = QFileDialog::getOpenFileName(this,
        tr("Load Encrypted Message"), QString(),
        tr("Text Files (*.txt);;All Files (*)"));
    
    if (fileName.isEmpty()) {
        return;
    }
    
    // Open the file
    QFile file(fileName);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::critical(this, tr("Error"),
            tr("Failed to open file."));
        return;
    }
    
    // Read the file
    QTextStream in(&file);
    QString content = in.readAll();
    file.close();
    
    // Set the content
    ui->plainTextEditReceive->setPlainText(content);
}

// Private helper methods

void MainWindow::initializeComponents()
{
    // Create components
    codeBook = new CodeBook(this);
    cryptoEngine = new CryptoEngine(this);
    messageProtocol = new MessageProtocol(this);
    authentication = new Authentication(this);
    
    // Connect components
    cryptoEngine->setCodeBook(codeBook);
    messageProtocol->setCryptoEngine(cryptoEngine);
}

void MainWindow::setupConnections()
{
    // Connect codebook signals
    connect(codeBook, &CodeBook::error, this, &MainWindow::handleError);
    connect(codeBook, &CodeBook::keyMaterialLow, this, &MainWindow::handleKeyMaterialLow);
    connect(codeBook, &CodeBook::emergencyProtocolExecuted, this, &MainWindow::handleEmergencyProtocol);
    connect(codeBook, &CodeBook::duressDetected, this, &MainWindow::handleDuressDetected);
    
    // Connect crypto engine signals
    connect(cryptoEngine, &CryptoEngine::error, this, &MainWindow::handleError);
    connect(cryptoEngine, &CryptoEngine::keyMaterialLow, this, &MainWindow::handleKeyMaterialLow);
    
    // Connect message protocol signals
    connect(messageProtocol, &MessageProtocol::error, this, &MainWindow::handleError);
    connect(messageProtocol, &MessageProtocol::duressDetected, this, &MainWindow::handleDuressDetected);
    connect(messageProtocol, &MessageProtocol::challengeReceived, this, &MainWindow::handleChallengeReceived);
    connect(messageProtocol, &MessageProtocol::codePhraseReceived, this, &MainWindow::handleCodePhraseReceived);
    
    // Connect authentication signals
    connect(authentication, &Authentication::error, this, &MainWindow::handleError);
    connect(authentication, &Authentication::authenticationFailed, this, &MainWindow::handleAuthenticationFailed);
    connect(authentication, &Authentication::authenticationSuccessful, this, &MainWindow::handleAuthenticationSuccessful);
    connect(authentication, &Authentication::biometricPromptRequired, this, &MainWindow::handleBiometricPrompt);
    connect(authentication, &Authentication::hardwareTokenPromptRequired, this, &MainWindow::handleHardwareTokenPrompt);
}

void MainWindow::loadSettings()
{
    QSettings settings;
    
    // Load window geometry
    restoreGeometry(settings.value("MainWindow/Geometry").toByteArray());
    restoreState(settings.value("MainWindow/State").toByteArray());
    
    // Load last codebook path
    QString lastPath = settings.value("CodeBook/LastPath").toString();
    if (!lastPath.isEmpty()) {
        // Don't automatically open it, just store the path
        codeBookPath = lastPath;
    }
}

void MainWindow::saveSettings()
{
    QSettings settings;
    
    // Save window geometry
    settings.setValue("MainWindow/Geometry", saveGeometry());
    settings.setValue("MainWindow/State", saveState());
    
    // Save last codebook path
    if (!codeBookPath.isEmpty()) {
        settings.setValue("CodeBook/LastPath", codeBookPath);
    }
}

bool MainWindow::maybeSave()
{
    if (!codeBook || !codeBook->isOpen() || !codeBookModified) {
        return true;
    }
    
    QMessageBox::StandardButton ret = QMessageBox::warning(this, tr("OTP Messenger"),
        tr("The codebook has been modified.\nDo you want to save your changes?"),
        QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel);
    
    if (ret == QMessageBox::Save) {
        return codeBook->save();
    } else if (ret == QMessageBox::Cancel) {
        return false;
    }
    
    return true;
}

bool MainWindow::loadCodeBook(const QString &path)
{
    if (codeBook->isOpen()) {
        codeBook->close();
    }
    
    return codeBook->open(path);
}

void MainWindow::updateStatusBar()
{
    if (codeBook && codeBook->isOpen()) {
        double percentRemaining = codeBook->getPercentageRemaining() * 100.0;
        statusBar()->showMessage(tr("Codebook: %1 - Remaining: %2%")
            .arg(QFileInfo(codeBookPath).fileName())
            .arg(percentRemaining, 0, 'f', 1));
    } else {
        statusBar()->showMessage(tr("No codebook open"));
    }
}

void MainWindow::updateCodeBookInfo()
{
    if (!codeBook || !codeBook->isOpen()) {
        // Clear the info fields
        ui->labelFileNameValue->setText(tr("Not loaded"));
        ui->labelSizeValue->setText(tr("0 bytes"));
        ui->labelUsedValue->setText(tr("0 bytes (0%)"));
        ui->labelRemainingValue->setText(tr("0 bytes (0%)"));
        ui->labelCompartmentsValue->setText(tr("0"));
        ui->labelCreatedValue->setText(tr("N/A"));
        
        // Clear the compartments table
        ui->tableWidgetCompartments->setRowCount(0);
        
        // Clear the visualizer
        ui->graphicsViewKeyMaterial->scene()->clear();
        
        return;
    }
    
    // Set the file name
    ui->labelFileNameValue->setText(QFileInfo(codeBookPath).fileName());
    
    // Set the size
    quint64 totalSize = codeBook->getTotalSize();
    ui->labelSizeValue->setText(formatByteSize(totalSize));
    
    // Set the used space
    quint64 usedSize = totalSize - codeBook->getUnusedSize();
    double usedPercent = static_cast<double>(usedSize) / static_cast<double>(totalSize) * 100.0;
    ui->labelUsedValue->setText(tr("%1 (%2%)")
        .arg(formatByteSize(usedSize))
        .arg(usedPercent, 0, 'f', 1));
    
    // Set the remaining space
    quint64 remainingSize = codeBook->getUnusedSize();
    double remainingPercent = static_cast<double>(remainingSize) / static_cast<double>(totalSize) * 100.0;
    ui->labelRemainingValue->setText(tr("%1 (%2%)")
        .arg(formatByteSize(remainingSize))
        .arg(remainingPercent, 0, 'f', 1));
    
    // Set the number of compartments
    QList<QString> compartmentNames = codeBook->getCompartmentNames();
    ui->labelCompartmentsValue->setText(QString::number(compartmentNames.size()));
    
    // Set the created date (not implemented in CodeBook class yet)
    ui->labelCreatedValue->setText(tr("Unavailable"));
    
    // Update the compartments table
    updateCompartmentsTable();
    
    // Update the key material visualizer
    updateKeyMaterialVisualizer();
    
    // Update the status bar
    updateStatusBar();
}

void MainWindow::updateCompartmentsTable()
{
    // Clear the table first
    ui->tableWidgetCompartments->setRowCount(0);
    
    if (!codeBook || !codeBook->isOpen()) {
        return;
    }
    
    // Get compartment names
    QList<QString> compartmentNames = codeBook->getCompartmentNames();
    
    // Set the row count
    ui->tableWidgetCompartments->setRowCount(compartmentNames.size());
    
    // Populate the table (actual compartment details would need additional API in CodeBook class)
    for (int i = 0; i < compartmentNames.size(); ++i) {
        // Name
        ui->tableWidgetCompartments->setItem(i, 0, new QTableWidgetItem(compartmentNames[i]));
        
        // Size (placeholder)
        ui->tableWidgetCompartments->setItem(i, 1, new QTableWidgetItem(tr("Unknown")));
        
        // Used (placeholder)
        ui->tableWidgetCompartments->setItem(i, 2, new QTableWidgetItem(tr("Unknown")));
        
        // Remaining (placeholder)
        ui->tableWidgetCompartments->setItem(i, 3, new QTableWidgetItem(tr("Unknown")));
        
        // Status (placeholder)
        ui->tableWidgetCompartments->setItem(i, 4, new QTableWidgetItem(tr("Active")));
    }
}

void MainWindow::updateKeyMaterialVisualizer()
{
    // Create a new scene
    QGraphicsScene *scene = new QGraphicsScene(this);
    ui->graphicsViewKeyMaterial->setScene(scene);
    
    if (!codeBook || !codeBook->isOpen()) {
        return;
    }
    
    // Get codebook details
    quint64 totalSize = codeBook->getTotalSize();
    quint64 usedSize = totalSize - codeBook->getUnusedSize();
    
    // Calculate dimensions
    int width = ui->graphicsViewKeyMaterial->width() - 10;
    int height = 50;
    
    // Create a rectangle for the total size
    QGraphicsRectItem *totalRect = scene->addRect(0, 0, width, height);
    totalRect->setBrush(Qt::lightGray);
    
    // Create a rectangle for the used portion
    int usedWidth = static_cast<int>((static_cast<double>(usedSize) / static_cast<double>(totalSize)) * width);
    QGraphicsRectItem *usedRect = scene->addRect(0, 0, usedWidth, height);
    usedRect->setBrush(Qt::darkBlue);
    
    // Add a text label with percentage
    double usedPercent = static_cast<double>(usedSize) / static_cast<double>(totalSize) * 100.0;
    QString label = tr("Used: %1%").arg(usedPercent, 0, 'f', 1);
    scene->addText(label)->setPos(10, 15);
}

QString MainWindow::formatByteSize(quint64 bytes)
{
    const quint64 KB = 1024;
    const quint64 MB = KB * 1024;
    const quint64 GB = MB * 1024;
    
    if (bytes >= GB) {
        return tr("%1 GB").arg(static_cast<double>(bytes) / GB, 0, 'f', 2);
    } else if (bytes >= MB) {
        return tr("%1 MB").arg(static_cast<double>(bytes) / MB, 0, 'f', 2);
    } else if (bytes >= KB) {
        return tr("%1 KB").arg(static_cast<double>(bytes) / KB, 0, 'f', 2);
    } else {
        return tr("%1 bytes").arg(bytes);
    }
}

// Handler methods for special message types

void MainWindow::handleFileTransferMessage(const MessageProtocol::Message &message)
{
    QJsonObject fileInfo = messageProtocol->extractFileTransferDetails(message);
    
    if (fileInfo.isEmpty()) {
        QMessageBox::critical(this, tr("Error"),
            tr("Failed to extract file transfer details."));
        return;
    }
    
    QString filename = fileInfo["filename"].toString();
    QString sizeStr = fileInfo["size"].toString();
    
    QMessageBox::information(this, tr("File Transfer"),
        tr("Received file transfer request:\nFile: %1\nSize: %2\n\n"
           "File transfer is not implemented in this version.")
        .arg(filename)
        .arg(formatByteSize(sizeStr.toULongLong())));
}

void MainWindow::handleChallengeMessage(const MessageProtocol::Message &message)
{
    QString challenge = messageProtocol->extractChallenge(message);
    
    if (challenge.isEmpty()) {
        QMessageBox::critical(this, tr("Error"),
            tr("Failed to extract challenge."));
        return;
    }
    
    QMessageBox::information(this, tr("Challenge Received"),
        tr("Received challenge: %1\n\n"
           "Challenge-response functionality is not fully implemented in this version.")
        .arg(challenge));
}

void MainWindow::handleCodePhraseMessage(const MessageProtocol::Message &message)
{
    QString codePhrase = messageProtocol->extractCodePhrase(message);
    
    if (codePhrase.isEmpty()) {
        QMessageBox::critical(this, tr("Error"),
            tr("Failed to extract code phrase."));
        return;
    }
    
    QMessageBox::information(this, tr("Code Phrase Received"),
        tr("Received code phrase: %1\n\n"
           "Code phrase functionality is not fully implemented in this version.")
        .arg(codePhrase));
}

// Signal handlers

void MainWindow::handleError(const QString &errorMessage)
{
    statusBar()->showMessage(tr("Error: %1").arg(errorMessage), 5000);
    qDebug() << "Error:" << errorMessage;
}

void MainWindow::handleKeyMaterialLow(double percentageRemaining)
{
    QMessageBox::warning(this, tr("Low Key Material"),
        tr("Your codebook is running low on key material. Only %1% remaining.")
        .arg(percentageRemaining * 100.0, 0, 'f', 1));
}

void MainWindow::handleEmergencyProtocol()
{
    QMessageBox::critical(this, tr("Emergency Protocol"),
        tr("Emergency destruction protocol has been executed. "
           "All key material has been wiped."));
}

void MainWindow::handleDuressDetected()
{
    QMessageBox::warning(this, tr("Duress Detected"),
        tr("This message contains duress indicators! "
           "The sender may be under duress."));
}

void MainWindow::handleChallengeReceived(const QString &challenge)
{
    bool ok;
    QString response = QInputDialog::getText(this, tr("Challenge Received"),
        tr("Challenge: %1\nPlease enter the response:").arg(challenge),
        QLineEdit::Normal, QString(), &ok);
    
    if (!ok || response.isEmpty()) {
        return;
    }
    
    // The actual response verification would go here
    QMessageBox::information(this, tr("Response Sent"),
        tr("Your response has been sent."));
}

void MainWindow::handleCodePhraseReceived(const QString &codePhrase)
{
    QMessageBox::information(this, tr("Code Phrase Received"),
        tr("Received code phrase: %1").arg(codePhrase));
}

void MainWindow::handleAuthenticationFailed(const QString &reason)
{
    QMessageBox::critical(this, tr("Authentication Failed"),
        tr("Authentication failed: %1").arg(reason));
}

void MainWindow::handleAuthenticationSuccessful()
{
    QMessageBox::information(this, tr("Authentication Successful"),
        tr("Authentication successful."));
}

void MainWindow::handleBiometricPrompt()
{
    // In a real implementation, this would use the OS biometric API
    bool ok;
    QString dummy = QInputDialog::getText(this, tr("Biometric Authentication"),
        tr("Biometric authentication required.\n\n"
           "This is a simulation. Enter any text to 'authenticate'."),
        QLineEdit::Normal, QString(), &ok);
    
    if (ok) {
        QMessageBox::information(this, tr("Biometric Authenticated"),
            tr("Biometric authentication successful."));
    } else {
        QMessageBox::critical(this, tr("Biometric Failed"),
            tr("Biometric authentication failed."));
    }
}

void MainWindow::handleHardwareTokenPrompt()
{
    // In a real implementation, this would interact with a hardware token
    bool ok;
    QString response = QInputDialog::getText(this, tr("Hardware Token"),
        tr("Please enter the code from your hardware token:"),
        QLineEdit::Normal, QString(), &ok);
    
    if (ok && !response.isEmpty()) {
        QMessageBox::information(this, tr("Hardware Token"),
            tr("Hardware token response accepted."));
    } else {
        QMessageBox::critical(this, tr("Hardware Token"),
            tr("Hardware token authentication failed."));
    }
}
