#include "include/mainwindow.h"

QDir lastDir = QDir::current();

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow)
{
    QIcon icon(":/icons/lock.png");
    this->setWindowIcon(icon);
    ui->setupUi(this);
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
}

MainWindow::~MainWindow()
{
    delete ui;
}

/**
 * @brief Copies the key from the provided certificate request into a string
 *
 * @param csr Pointer to the certificate request structure
 * @param Skey Reference to the string where the key will be stored
 * @param maxlength Maximum number of characters to copy
 *
 * @note Example usage:
 * std::string buffer;
 * get_csr_PEM(csr.get(), buffer, 3000);
 */
int get_csr_PEM(X509_REQ *csr, std::string &Skey, size_t maxlength)
{

    BIO *mem = BIO_new(BIO_s_mem());
    BUF_MEM *bptr;
    if (!PEM_write_bio_X509_REQ(mem, csr))
    {
        BIO_free_all(mem);
        return 3;
    }

    BIO_get_mem_ptr(mem, &bptr);

    if (bptr->length == 0)
    {
        BIO_free_all(mem);
        return 1;
    }
    if (bptr->length >= maxlength)
    {
        BIO_free_all(mem);
        return 2;
    }

    Skey.reserve(bptr->length + 2);
    Skey.assign(bptr->data, bptr->length);
    Skey[bptr->length + 1] = '\0';
    BIO_free_all(mem);
    return 0;
}

void print_ssl_errors()
{

    unsigned long int errcode;
    char buff[300];
    while ((errcode = ERR_get_error()) != 0)
    {

        sprintf(buff, "Lib : %s, err : %s (%i/%i)\n",
                ERR_lib_error_string(errcode),
                ERR_reason_error_string((errcode)),
                ERR_GET_LIB(errcode),
                ERR_GET_REASON(errcode));

        qDebug() << buff;
    }
}

bool MainWindow::validatePasswords()
{
    const QString pem1 = this->ui->txt_pem_1->text();
    const QString pem2 = this->ui->txt_pem_2->text();
    if (pem1 != pem2)
    {
        QMessageBox::warning(this, tr("Error"), tr("PEM passwords do not match."));
        return false;
    }
    return true;
}

bool MainWindow::validateCertificateName(const QString &name)
{
    // Allow only letters, digits, space, dot, underscore, dash
    QRegularExpression allowedChars("^[A-Za-z0-9 ._\\-]+$");
    if (!allowedChars.match(name).hasMatch())
    {
        QMessageBox::warning(
            this,
            tr("Error"),
            tr("Certificate name contains invalid characters. Only letters, digits, spaces, '.', '_', and '-' are allowed."));
        return false;
    }
    return true;
}

std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)> MainWindow::generateKey()
{
    auto rsa = std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)>(EVP_RSA_gen(2048), EVP_PKEY_free);
    if (!rsa)
    {
        QMessageBox::warning(this, tr("Error"), tr("Failed to generate RSA key"));
        return std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY *)>(nullptr, EVP_PKEY_free);
    }
    return rsa;
}

std::unique_ptr<X509_REQ, void (*)(X509_REQ *)> MainWindow::generateCSR(
    EVP_PKEY *rsa,
    const QString &cn,
    const QString &country,
    const QString &org,
    const QString &locality,
    const QString &state,
    const QString &unit,
    const QString &email,
    const QString &challengePassword)
{
    auto csr = std::unique_ptr<X509_REQ, void (*)(X509_REQ *)>(X509_REQ_new(), X509_REQ_free);
    X509_REQ_set_version(csr.get(), 0);
    X509_REQ_set_pubkey(csr.get(), rsa);
    X509_NAME *name = X509_REQ_get_subject_name(csr.get());

    auto addEntry = [&](const char *field, const QString &value, const char *errorMessage = nullptr)
    {
        if (!value.isEmpty())
        {
            if (!X509_NAME_add_entry_by_txt(name, field, MBSTRING_ASC, reinterpret_cast<const unsigned char *>(value.toStdString().c_str()), -1, -1, 0))
            {
                QMessageBox::information(this, tr("Error"), tr(errorMessage));
                print_ssl_errors();
                return false;
            }
        }
        return true;
    };

    if (!addEntry("C", country, "Country must be 2 letters long") ||
        !addEntry("O", org, "Organization is required") ||
        !addEntry("CN", cn, "Common Name is required") ||
        !addEntry("L", locality, "Locality is required"))
        return std::unique_ptr<X509_REQ, void (*)(X509_REQ *)>(nullptr, X509_REQ_free);

    addEntry("ST", state, "State/Province");
    addEntry("OU", unit, "Organizational Unit");

    if (!email.isEmpty())
    {
        if (!X509_NAME_add_entry_by_NID(name, NID_Mail, MBSTRING_ASC, reinterpret_cast<const unsigned char *>(email.toStdString().c_str()), -1, -1, 0))
        {
            QMessageBox::information(this, tr("Error"), tr("E-mail"));
            print_ssl_errors();
            return std::unique_ptr<X509_REQ, void (*)(X509_REQ *)>(nullptr, X509_REQ_free);
        }
    }

    if (!challengePassword.isEmpty())
    {
        if (!X509_REQ_add1_attr_by_NID(csr.get(), NID_pkcs9_challengePassword, MBSTRING_ASC, reinterpret_cast<const unsigned char *>(challengePassword.toStdString().c_str()), -1))
        {
            QMessageBox::information(this, tr("Error"), tr("Challenge password"));
            print_ssl_errors();
            return std::unique_ptr<X509_REQ, void (*)(X509_REQ *)>(nullptr, X509_REQ_free);
        }
    }

    X509_REQ_sign(csr.get(), rsa, EVP_sha256());
    print_ssl_errors();

    return csr;
}

void MainWindow::saveCSRAndKey(X509_REQ *csr, EVP_PKEY *rsa, const QString &pemPassword, const QString &defaultName)
{
    QString filename = QFileDialog::getSaveFileName(this, tr("Save CSR/Key"), lastDir.absoluteFilePath(defaultName));
    if (filename.isEmpty())
        return;

    lastDir = QFileInfo(filename).absoluteDir();
    QString csrName = filename + ".csr";
    QString keyName = filename + ".key";

    auto certFile = std::unique_ptr<BIO, void (*)(BIO *)>(BIO_new_file(csrName.toStdString().c_str(), "wb"), BIO_free_all);
    auto keyFile = std::unique_ptr<BIO, void (*)(BIO *)>(BIO_new_file(keyName.toStdString().c_str(), "wb"), BIO_free_all);

    int keyRet = PEM_write_bio_PrivateKey(keyFile.get(), rsa,
                                          const_cast<EVP_CIPHER *>(EVP_get_cipherbyname("aes256")),
                                          nullptr, 0, PEM_def_callback,
                                          (void *)pemPassword.toStdString().c_str());
    print_ssl_errors();
    if (!keyRet)
    {
        QMessageBox::warning(this, tr("Error"), tr("Cannot write key file, check the key password"));
        return;
    }

    int csrRet = PEM_write_bio_X509_REQ(certFile.get(), csr);
    if (keyRet == 1 && csrRet == 1)
        QMessageBox::information(this, tr("Saved"), tr("CSR and key were saved"));
    else
        QMessageBox::information(this, tr("Error"), tr("Failed to save files"));
}

/**
 * @brief Creates a new Certificate Signing Request (CSR) using the specified entries.
 *
 * This function is triggered when the "New" button is clicked in the UI.
 * It gathers the required fields from the form and generates a CSR accordingly.
 */
void MainWindow::on_btn_new_clicked()
{

    if (!validatePasswords())
        return;

    QString certName = this->ui->txt_name->text();
    if (!validateCertificateName(certName))
        return;

    const QString country = this->ui->txt_country->text();
    const QString locality = this->ui->txt_locality->text();
    const QString state = this->ui->txt_state->text();
    const QString org = this->ui->txt_org->text();
    const QString unit = this->ui->txt_orgunit->text();
    const QString email = this->ui->txt_email->text();
    const QString pemPassword = this->ui->txt_pem_1->text();
    const QString challengePassword = this->ui->txt_challenge_pass->text();

    if (certName.isEmpty() || country.isEmpty() || locality.isEmpty() || org.isEmpty())
    {
        QMessageBox::warning(this, tr("Error"), tr("Please enter all mandatory fields marked with *"));
        return;
    }

    auto rsa = generateKey();
    if (!rsa)
        return;
    auto csr = generateCSR(rsa.get(), certName, country, org, locality, state, unit, email, challengePassword);
    if (!csr)
        return;

    saveCSRAndKey(csr.get(), rsa.get(), pemPassword, certName);
}

bool MainWindow::validatePasswords(const QString &pass1, const QString &pass2)
{
    if (pass1 != pass2)
    {
        QMessageBox::warning(this, tr("Error"), tr("PKCS#12 password entries do not match."));
        return false;
    }
    return true;
}

bool MainWindow::validatePKCSPassword(const QString &password)
{
    QRegularExpression allowedChars("^[A-Za-z0-9._\\-]+$");

    if (!allowedChars.match(password).hasMatch())
    {
        QMessageBox::warning(
            this,
            tr("Error"),
            tr("PKCS#12 password contains invalid characters. Only letters, digits, and the symbols '.', '_', '-' are allowed."));
        return false;
    }

    return true;
}
X509 *MainWindow::loadCertificate(const QString &filename)
{
    FILE *fp = fopen(filename.toStdString().c_str(), "r");
    if (!fp)
    {
        QMessageBox::warning(this, tr("Error"), tr("Cannot open certificate file."));
        return nullptr;
    }

    X509 *cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!cert)
    {
        QMessageBox::warning(this, tr("Error"), tr("Cannot read certificate file."));
        return nullptr;
    }

    return cert;
}

EVP_PKEY *MainWindow::loadPrivateKey(const QString &filename, const QString &password)
{
    FILE *fp = fopen(filename.toStdString().c_str(), "r");
    if (!fp)
    {
        QMessageBox::warning(this, tr("Error"), tr("Cannot open key file."));
        return nullptr;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, nullptr, PEM_def_callback, (void *)password.toStdString().c_str());
    fclose(fp);

    if (!pkey)
    {
        QMessageBox::warning(this, tr("Error"), tr("Cannot read key file. Make sure the key password is correct."));
        return nullptr;
    }

    return pkey;
}

bool MainWindow::createPKCS12File(X509 *cert, EVP_PKEY *pkey, const QString &pkcsPassword, const QString &outputFile)
{
    PKCS12 *p12 = PKCS12_create(pkcsPassword.toStdString().c_str(),
                                outputFile.toStdString().c_str(),
                                pkey, cert, nullptr, 0, 0, 0, 0, 0);
    if (!p12)
    {
        QMessageBox::warning(this, tr("Error"), tr("Failed to create PKCS#12 structure."));
        ERR_print_errors_fp(stderr);
        return false;
    }

    FILE *fp = fopen(outputFile.toStdString().c_str(), "wb");
    if (!fp)
    {
        QMessageBox::warning(this, tr("Error"), tr("Cannot open output file."));
        PKCS12_free(p12);
        ERR_print_errors_fp(stderr);
        return false;
    }

    i2d_PKCS12_fp(fp, p12);
    PKCS12_free(p12);
    fclose(fp);
    return true;
}

/**
 * @brief creates a PKCS12 file from a signed certificate (.cer/.crt) and a key (.key)
 */

void MainWindow::on_convert_pfx_clicked()
{

    if (!validatePasswords(ui->txt_pass_1->text(), ui->txt_pass_2->text()))
        return;

    if (!validatePKCSPassword(ui->txt_pass_1->text()))
        return;

    QString keyFile = QFileDialog::getOpenFileName(this, tr("Load Key"), "", tr("Key (*.key);;Any (*.*)"));
    if (keyFile.isEmpty())
        return;

    QString certFile = QFileDialog::getOpenFileName(this, tr("Load Certificate"), "", tr("Certificate (*.cer);;Any (*.*)"));
    if (certFile.isEmpty())
        return;

    QString pkcsPassword = ui->txt_pass_1->text();
    QString keyPassword = ui->txt_pass_key->text();

    X509 *cert = loadCertificate(certFile);
    if (!cert)
        return;

    EVP_PKEY *pkey = loadPrivateKey(keyFile, keyPassword);
    if (!pkey)
    {
        X509_free(cert);
        return;
    }

    QString pfxFile = QFileDialog::getSaveFileName(this, tr("Save PKCS#12"), "", tr("PKCS#12 (*.pfx);;Any (*.*)"));
    if (pfxFile.isEmpty())
    {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return;
    }

    if (!createPKCS12File(cert, pkey, pkcsPassword, pfxFile))
    {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return;
    }

    X509_free(cert);
    EVP_PKEY_free(pkey);
    QMessageBox::information(this, tr("Saved"), tr("PKCS#12 file saved successfully."));
}

/* -------------------- Tooltips -------------------- */

void MainWindow::on_toolButton_clicked()
{
    QMessageBox::information(this, tr("Note"), tr("Only necessary if a PEM password was set."));
}

void MainWindow::on_toolButton_2_clicked()
{
    QMessageBox::information(this, tr("Note"), tr("For Desigo CC, a password should be set."));
}

void MainWindow::on_toolButton_3_clicked()
{
    QMessageBox::information(this, tr("Note"), tr("Optional for the certification process."));
}

void MainWindow::on_toolButton_4_clicked()
{
    QMessageBox::information(this, tr("Note"), tr("Only letters, digits, spaces, '.', '_', and '-' are allowed."));
}