#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSettings>

#include "cypherbook.h"
#include "cryptoengine.h"
#include "messageprotocol.h"
#include "authentication.h"

namespace Ui {
class MainWindow;
}

/**
 * @brief The MainWindow class provides the main user interface for the OTP Messenger application.
 * 
 * This class coordinates between the UI components and the core classes that handle
 * the cryptographic operations, message formatting, and authentication. It manages
 * the cypher book files, handles user interactions, and provides feedback on operations.
 */
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the main window
     * @param parent The parent widget
     */
    explicit MainWindow(QWidget *parent = nullptr);
    
    /**
     * @brief Destroys the main window and clean up resources
     */
    ~MainWindow();

private slots:
    // File menu actions
    void on_actionNew_Cypher_Book_triggered();
    void on_actionOpen_Cypher_Book_triggered();
    void on_actionSave_Cypher_Book_triggered();
    void on_actionExit_triggered();
    
    // Message menu actions
    void on_actionSend_Message_triggered();
    void on_actionReceive_Message_triggered();
    void on_actionClear_Messages_triggered();
    
    // Settings menu actions
    void on_actionPreferences_triggered();
    void on_actionAuthentication_triggered();
    
    // Help menu actions
    void on_actionAbout_triggered();
    
    // Message tab buttons
    void on_pushButtonOpenCypherBook_clicked();
    void on_pushButtonNewCypherBook_clicked();
    void on_pushButtonSend_clicked();
    void on_pushButtonClear_clicked();
    void on_pushButtonPaste_clicked();
    void on_pushButtonClearReceive_clicked();
    void on_pushButtonDecrypt_clicked();
    void on_pushButtonAttach_clicked();
    void on_pushButtonChallenge_clicked();
    void on_pushButtonCodePhrase_clicked();
    void on_pushButtonLoadFromFile_clicked();
    
    // Signal handlers
    void handleError(const QString &errorMessage);
    void handleKeyMaterialLow(double percentageRemaining);
    void handleEmergencyProtocol();
    void handleDuressDetected();
    void handleChallengeReceived(const QString &challenge);
    void handleCodePhraseReceived(const QString &codePhrase);
    void handleAuthenticationFailed(const QString &reason);
    void handleAuthenticationSuccessful();
    void handleBiometricPrompt();
    void handleHardwareTokenPrompt();

private:
    Ui::MainWindow *ui;
    
    // Core components
    CypherBook *cypherBook;
    CryptoEngine *cryptoEngine;
    MessageProtocol *messageProtocol;
    Authentication *authentication;
    
    // State tracking
    QString cypherBookPath;
    bool cypherBookModified;
    
    /**
     * @brief Initialize core components
     */
    void initializeComponents();
    
    /**
     * @brief Setup signal/slot connections
     */
    void setupConnections();
    
    /**
     * @brief Load application settings
     */
    void loadSettings();
    
    /**
     * @brief Save application settings
     */
    void saveSettings();
    
    /**
     * @brief Prompt to save changes if needed
     * @return True if operation can continue, false if cancelled
     */
    bool maybeSave();
    
    /**
     * @brief Load a cypher book from file
     * @param path The path to the cypher book file
     * @return True if successful, false otherwise
     */
    bool loadCypherBook(const QString &path);
    
    /**
     * @brief Update status bar information
     */
    void updateStatusBar();
    
    /**
     * @brief Update the cypher book information display
     */
    void updateCypherBookInfo();
    
    /**
     * @brief Update the compartments table
     */
    void updateCompartmentsTable();
    
    /**
     * @brief Update the key material visualizer
     */
    void updateKeyMaterialVisualizer();
    
    /**
     * @brief Format byte size for display
     * @param bytes The number of bytes
     * @return A formatted string (e.g., "1.23 MB")
     */
    QString formatByteSize(quint64 bytes);
    
    /**
     * @brief Handle a file transfer message
     * @param message The parsed message
     */
    void handleFileTransferMessage(const MessageProtocol::Message &message);
    
    /**
     * @brief Handle a challenge message
     * @param message The parsed message
     */
    void handleChallengeMessage(const MessageProtocol::Message &message);
    
    /**
     * @brief Handle a code phrase message
     * @param message The parsed message
     */
    void handleCodePhraseMessage(const MessageProtocol::Message &message);
};

#endif // MAINWINDOW_H
