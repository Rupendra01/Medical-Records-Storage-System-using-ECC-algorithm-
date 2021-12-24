import sys
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog, QApplication, QWidget
from PyQt5.QtGui import QPixmap

import sqlite3


class WelcomeScreen(QDialog):
    def __init__(self):
        super(WelcomeScreen, self).__init__()
        loadUi("welcomescreen.ui",self)
        qpixmap = QPixmap('welcome1.png')
        self.label_3.setPixmap(qpixmap)
        self.login.clicked.connect(self.gotologin)
        self.create.clicked.connect(self.gotocreate)

    def gotologin(self):
        login = LoginScreen()
        widget.addWidget(login)
        widget.setCurrentIndex(widget.currentIndex()+1)

    def gotocreate(self):
        create = CreateAccScreen()
        widget.addWidget(create)
        widget.setCurrentIndex(widget.currentIndex() + 1)

class LoginScreen(QDialog):
    def __init__(self):
        super(LoginScreen, self).__init__()
        loadUi("login.ui",self)
        qpixmap = QPixmap('loginimage.jpg')
        self.label_5.setPixmap(qpixmap)
        self.passwordfield.setEchoMode(QtWidgets.QLineEdit.Password)
        self.login.clicked.connect(self.signinfunction)

    def signinfunction(self):
        user = self.emailfield.text()
        password = self.passwordfield.text()

        if len(user)==0 or len(password)==0:
            self.error.setText("Please fill in all inputs.")

        elif user!= 'cryptography' and password!='utopia':
            self.error.setText("Username or Password is in correct.")
        else:

            interface = PatientScreen()
            widget.addWidget(interface)
            widget.setCurrentIndex(widget.currentIndex() + 1)


class CreateAccScreen(QDialog):
    def __init__(self):
        super(CreateAccScreen, self).__init__()
        loadUi("createacc.ui",self)
        qpixmap = QPixmap('signupimage.jpg')
        self.label_6.setPixmap(qpixmap)
        self.passwordfield.setEchoMode(QtWidgets.QLineEdit.Password)
        self.confirmpasswordfield.setEchoMode(QtWidgets.QLineEdit.Password)
        self.signup.clicked.connect(self.signupfunction)

    def signupfunction(self):
        user = self.emailfield.text()
        password = self.passwordfield.text()
        confirmpassword = self.confirmpasswordfield.text()

        if len(user)==0 or len(password)==0 or len(confirmpassword)==0:
            self.error.setText("Please fill in all inputs.")

        elif password!=confirmpassword:
            self.error.setText("Passwords do not match.")
        else:
            interface = PatientScreen()
            widget.addWidget(interface)
            widget.setCurrentIndex(widget.currentIndex()+1)


class PatientScreen(QDialog):
    def __init__(self):
        super(PatientScreen, self).__init__()
        loadUi("interface_patient.ui",self)
        widget.setFixedHeight(881)
        widget.setFixedWidth(1231)
        #self.image.setPixmap(QPixmap('placeholder.png'))
        self.login.clicked.connect(self.patientfunction)
        self.login_2.clicked.connect(self.doctorfunction)

    def patientfunction(self):
        #print("abc")
        name = self.emailfield.text()
        age = self.passwordfield.text()
        phn = self.passwordfield_2.text()
        sex = self.passwordfield_3.text()
        appointment = self.passwordfield_4.text()
        problem = self.passwordfield_5.text()
        address = self.passwordfield_6.text()
        marital = self.passwordfield_7.text()
        new = self.passwordfield_8.text()

        from tinyec import registry
        from Crypto.Cipher import AES
        import hashlib, secrets, binascii

        def encrypt_AES_GCM(msg, secretKey):
            aesCipher = AES.new(secretKey, AES.MODE_GCM)
            ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
            return (ciphertext, aesCipher.nonce, authTag)

        def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
            aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
            plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
            return plaintext

        def ecc_point_to_256_bit_key(point):
            sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
            sha.update(int.to_bytes(point.y, 32, 'big'))
            return sha.digest()

        curve = registry.get_curve('brainpoolP256r1')

        def encrypt_ECC(msg, pubKey):
            ciphertextPrivKey = secrets.randbelow(curve.field.n)
            sharedECCKey = ciphertextPrivKey * pubKey
            secretKey = ecc_point_to_256_bit_key(sharedECCKey)
            ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
            ciphertextPubKey = ciphertextPrivKey * curve.g
            return (ciphertext, nonce, authTag, ciphertextPubKey)

        def decrypt_ECC(encryptedMsg, privKey):
            (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
            sharedECCKey = privKey * ciphertextPubKey
            secretKey = ecc_point_to_256_bit_key(sharedECCKey)
            plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
            return plaintext

        #msg = b'Text to be encrypted by ECC public key and '
        #print(type(msg))
        #print("second")
        msg = bytes(name + age + phn + sex + appointment + problem + address + marital + new, 'utf-8')
        #print("original msg:", msg)
        privKey = secrets.randbelow(curve.field.n)
        pubKey = privKey * curve.g

        encryptedMsg = encrypt_ECC(msg, pubKey)
        encryptedMsgObj = {
            'ciphertext': binascii.hexlify(encryptedMsg[0]),
            'nonce': binascii.hexlify(encryptedMsg[1]),
            'authTag': binascii.hexlify(encryptedMsg[2]),
            'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
        }
        #print("encrypted msg:", encryptedMsgObj)
        encryptedMsg1 = binascii.hexlify(encryptedMsg[0]).decode("utf-8")
        #print("encrypted msg", encryptedMsg1)



        decryptedMsg = decrypt_ECC(encryptedMsg, privKey)
        #print("decrypted msg:", decryptedMsg)
        decryptedMsg1 = decryptedMsg.decode("utf-8")
        #print("string", decryptedMsg1)

        conn = sqlite3.connect("medical_record.db")
        cur = conn.cursor()

        user_info = [encryptedMsg1, name, age, phn, sex, appointment, problem, address, marital, new]
        cur.execute('INSERT INTO login_info (encrypted_text, name,age, phn_number, sex, appiontment, problem, address, marital, new ) VALUES (?,?,?,?,?,?,?,?,?,?)', user_info)

        conn.commit()
        conn.close()

        conn = sqlite3.connect("instance_medical_record.db")
        cur = conn.cursor()

        user_info = [decryptedMsg1]
        cur.execute('INSERT INTO login1_info (decryptedmsg) VALUES (?)', user_info)

        conn.commit()
        conn.close()

        interface = encryptdecryptScreen()
        widget.addWidget(interface)
        widget.setCurrentIndex(widget.currentIndex() + 1)


    def doctorfunction(self):
        interface = DoctorScreen()
        widget.addWidget(interface)
        widget.setCurrentIndex(widget.currentIndex() + 1)


class DoctorScreen(QDialog):
    def __init__(self):
        super(DoctorScreen, self).__init__()
        loadUi("interface_doctor.ui",self)
        widget.setFixedHeight(881)
        widget.setFixedWidth(1231)
        #self.image.setPixmap(QPixmap('placeholder.png'))
        self.login.clicked.connect(self.doctorfunction)
        self.login_2.clicked.connect(self.skipfunction)

    def doctorfunction(self):
        name = self.emailfield.text()
        age = self.passwordfield.text()
        phn = self.passwordfield_2.text()
        sex = self.passwordfield_3.text()
        specialization = self.passwordfield_4.text()
        expirence = self.passwordfield_5.text()
        marital = self.passwordfield_6.text()
        address = self.passwordfield_7.text()

        from tinyec import registry
        from Crypto.Cipher import AES
        import hashlib, secrets, binascii

        def encrypt_AES_GCM(msg, secretKey):
            aesCipher = AES.new(secretKey, AES.MODE_GCM)
            ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
            return (ciphertext, aesCipher.nonce, authTag)

        def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
            aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
            plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
            return plaintext

        def ecc_point_to_256_bit_key(point):
            sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
            sha.update(int.to_bytes(point.y, 32, 'big'))
            return sha.digest()

        curve = registry.get_curve('brainpoolP256r1')

        def encrypt_ECC(msg, pubKey):
            ciphertextPrivKey = secrets.randbelow(curve.field.n)
            sharedECCKey = ciphertextPrivKey * pubKey
            secretKey = ecc_point_to_256_bit_key(sharedECCKey)
            ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
            ciphertextPubKey = ciphertextPrivKey * curve.g
            return (ciphertext, nonce, authTag, ciphertextPubKey)

        def decrypt_ECC(encryptedMsg, privKey):
            (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
            sharedECCKey = privKey * ciphertextPubKey
            secretKey = ecc_point_to_256_bit_key(sharedECCKey)
            plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
            return plaintext

        #msg = b'Text to be encrypted by ECC public key and '
        #print(type(msg))
        msg = bytes(name + age + phn + sex + specialization + expirence + marital + address, 'utf-8')
        #print("original msg:", msg)
        privKey = secrets.randbelow(curve.field.n)
        pubKey = privKey * curve.g

        encryptedMsg = encrypt_ECC(msg, pubKey)
        encryptedMsgObj = {
            'ciphertext': binascii.hexlify(encryptedMsg[0]),
            'nonce': binascii.hexlify(encryptedMsg[1]),
            'authTag': binascii.hexlify(encryptedMsg[2]),
            'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
        }
        #print("encrypted msg:", encryptedMsgObj)
        encryptedMsg1 = binascii.hexlify(encryptedMsg[0]).decode("utf-8")
        #print("encrypted msg", encryptedMsg1)

        decryptedMsg = decrypt_ECC(encryptedMsg, privKey)
        #print("decrypted msg:", decryptedMsg)
        decryptedMsg1 = decryptedMsg.decode("utf-8")
        #print("string", decryptedMsg1)


        conn = sqlite3.connect("medical_record_doctor.db")
        cur = conn.cursor()

        user_info = [encryptedMsg1, name, age, phn, sex, specialization, expirence, marital, address]
        cur.execute('INSERT INTO login_info (encrypted_text, name, age, phn_number, sex, specialization, expirence, marital, address) VALUES (?,?,?,?,?,?,?,?,?)', user_info)

        conn.commit()
        conn.close()

        conn = sqlite3.connect("instance_medical_record_doctor.db")
        cur = conn.cursor()

        user_info = [decryptedMsg1]
        cur.execute('INSERT INTO login1_info (decryptedmsg) VALUES (?)', user_info)

        conn.commit()
        conn.close()

        interface = encryptdecryptScreen()
        widget.addWidget(interface)
        widget.setCurrentIndex(widget.currentIndex() + 1)

    def skipfunction(self):
        interface = encryptdecryptScreen()
        widget.addWidget(interface)
        widget.setCurrentIndex(widget.currentIndex() + 1)



class encryptdecryptScreen(QDialog):
    def __init__(self):
        super(encryptdecryptScreen, self).__init__()
        loadUi("encryption_decryption.ui",self)
        widget.setFixedHeight(801)
        widget.setFixedWidth(1201)
        #self.image.setPixmap(QPixmap('placeholder.png'))
        self.login.clicked.connect(self.encryptfunction)
        self.create.clicked.connect(self.decryptfunction)
        self.create_2.clicked.connect(self.decryptfunction)


    def encryptfunction(self):
        interface = encrypttextScreen()
        widget.addWidget(interface)
        widget.setCurrentIndex(widget.currentIndex() + 1)

    def decryptfunction(self):
        interface = LoginScreen2()
        widget.addWidget(interface)
        widget.setCurrentIndex(widget.currentIndex() + 1)



class encrypttextScreen(QDialog):
    def __init__(self):
        super(encrypttextScreen, self).__init__()
        loadUi("encrypted_text.ui",self)
        widget.setFixedHeight(430)
        widget.setFixedWidth(964)
        #self.image.setPixmap(QPixmap('placeholder.png'))
        self.login_2.clicked.connect(self.interfacefunction)

    def interfacefunction(self):
        interface = PatientScreen()
        widget.addWidget(interface)
        widget.setCurrentIndex(widget.currentIndex() + 1)


class LoginScreen2(QDialog):
    def __init__(self):
        super(LoginScreen2, self).__init__()
        loadUi("login.ui",self)
        qpixmap = QPixmap('loginimage.jpg')
        self.label_5.setPixmap(qpixmap)
        self.passwordfield.setEchoMode(QtWidgets.QLineEdit.Password)
        self.login.clicked.connect(self.signinfunction)

    def signinfunction(self):
        user = self.emailfield.text()
        password = self.passwordfield.text()

        if len(user)==0 or len(password)==0:
            self.error.setText("Please fill in all inputs.")

        elif user!= 'cryptography' and password!='healthcare':
            self.error.setText("Username or Password is in correct.")
        else:

            interface = decrypttextScreen()
            widget.addWidget(interface)
            widget.setCurrentIndex(widget.currentIndex() + 1)

class decrypttextScreen(QDialog):
    def __init__(self):
        super(decrypttextScreen, self).__init__()
        loadUi("decrypted_text.ui",self)
        widget.setFixedHeight(491)
        widget.setFixedWidth(911)
        #self.image.setPixmap(QPixmap('placeholder.png'))
        self.login.clicked.connect(self.interfacefunction)

    def interfacefunction(self):
        interface = PatientScreen()
        widget.addWidget(interface)
        widget.setCurrentIndex(widget.currentIndex() + 1)

# main
app = QApplication(sys.argv)
welcome = WelcomeScreen()
widget = QtWidgets.QStackedWidget()
widget.addWidget(welcome)
widget.setFixedHeight(800)
widget.setFixedWidth(1200)
widget.show()
try:
    sys.exit(app.exec_())
except:
    print("Exiting")