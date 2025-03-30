#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSettings>

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
    // File menu
    void on_actionNew_Cypher_Book_triggered();
    void on_actionOpen_Cypher_Book_triggered();
    void on_actionSave_Cypher_Book_triggered();
    void on_actionExit_triggered();
    
    // Message menu
    void on_actionSend_Message_triggered();
    void on_actionReceive_Message_triggered();
    
    // Settings menu
    void on_actionPreferences_triggered();
    void on_actionAuthentication_triggered();
    
    // Help menu
    void on_actionAbout_triggered();
    
    // Message handling
    void on_sendButton_clicked();
    void on_clearButton_clicked();

private:
    Ui::MainWindow *ui;
    QSettings settings;
    
    // Track cypher book state
    QString cypherBookPath;
    bool cypherBookModified;
    
    void setupConnections();
    void setupUI();
    void loadSettings();
    void saveSettings();
    
    bool maybeSave();
    bool loadCypherBook(const QString &path);
    bool saveCypherBook(const QString &path);
    
    void updateStatusBar();
};

#endif // MAINWINDOW_H
