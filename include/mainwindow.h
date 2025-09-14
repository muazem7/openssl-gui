#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "ui_mainwindow.h"

#include <QRegularExpression>

#include <QMainWindow>
#include <QMessageBox>
#include <QThread>
#include <QMutex>
#include <QTimer>
#include <QDebug>
#include <QInputDialog>
#include <QSignalMapper>
#include <QFileDialog>
#include <QDateTime>
#include <QLayout>
#include <QSettings>
#include <QDebug>

#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/pkcs12.h>
#include <openssl/ssl.h>


#include <iostream>

QT_BEGIN_NAMESPACE
namespace Ui
{
    class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:

    void on_btn_new_clicked();

    void on_convert_pfx_clicked();

    void on_toolButton_clicked();

    void on_toolButton_2_clicked();

    void on_toolButton_3_clicked();

    void on_toolButton_4_clicked();

private:
    Ui::MainWindow *ui;

    bool validatePasswords();
    bool validateCertificateName(const QString &name);
    std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)> generateKey();
    std::unique_ptr<X509_REQ, void (*)(X509_REQ *)> generateCSR(
        EVP_PKEY *rsa,
        const QString &cn,
        const QString &country,
        const QString &org,
        const QString &locality,
        const QString &state,
        const QString &unit,
        const QString &email,
        const QString &challengePassword);
    void saveCSRAndKey(X509_REQ *csr, EVP_PKEY *rsa, const QString &pemPassword, const QString &defaultName);

    bool validatePasswords(const QString &pass1, const QString &pass2);
    bool validatePKCSPassword(const QString &password);
    X509 *loadCertificate(const QString &filename);
    EVP_PKEY *loadPrivateKey(const QString &filename, const QString &password);
    bool createPKCS12File(X509 *cert, EVP_PKEY *pkey, const QString &pkcsPassword, const QString &outputFile);

    QDir lastDir;
};
#endif // MAINWINDOW_H
