#include <QApplication>
#include <QMessageBox>
#include "mainwindow.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    
    app.setApplicationName("OTP Messenger");
    app.setOrganizationName("OTP Messenger Project");
    app.setOrganizationDomain("github.com/MatejGomboc-Claude-MCP/otp-messenger");
    
    // Show disclaimer on first run
    QSettings settings;
    if (settings.value("firstRun", true).toBool()) {
        QMessageBox disclaimer;
        disclaimer.setWindowTitle("Disclaimer");
        disclaimer.setIcon(QMessageBox::Warning);
        disclaimer.setText("<b>OTP Messenger - Disclaimer</b>");
        disclaimer.setInformativeText(
            "This software is a hobby project provided for educational and research purposes only.\n\n"
            "The creators and contributors are not responsible for any misuse, damage, or illegal "
            "activities conducted using this software.\n\n"
            "By using this software, you acknowledge that:\n"
            "1. You will comply with all applicable laws and regulations.\n"
            "2. You accept full responsibility for your use of the software.\n"
            "3. The developers cannot guarantee perfect security or absence of bugs.\n\n"
            "This project is not intended for production use or in environments requiring high "
            "security assurance."
        );
        disclaimer.setStandardButtons(QMessageBox::Ok | QMessageBox::Cancel);
        
        int result = disclaimer.exec();
        if (result == QMessageBox::Cancel) {
            return 0;
        }
        
        settings.setValue("firstRun", false);
    }
    
    MainWindow mainWindow;
    mainWindow.show();
    
    return app.exec();
}
