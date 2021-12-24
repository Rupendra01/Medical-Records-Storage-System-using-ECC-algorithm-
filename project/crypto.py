import sys
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog, QApplication, QWidget
from PyQt5.QtGui import QPixmap

import sqlite3


class ECCScreen(QDialog):
    def __init__(self):
        super(ECCScreen, self).__init__()
        loadUi("welcomescreen1.ui",self)
        self.login.clicked.connect(self.gotologin)
        self.create.clicked.connect(self.gotocreate)

    def gotologin(self):
        # print("abc")
        message = self.emailfield.text()

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

        # msg = b'Text to be encrypted by ECC public key and '
        # print(type(msg))
        # print("second")
        msg = bytes(message, 'utf-8')
        # print("original msg:", msg)
        privKey = secrets.randbelow(curve.field.n)
        pubKey = privKey * curve.g

        encryptedMsg = encrypt_ECC(msg, pubKey)
        encryptedMsgObj = {
            'ciphertext': binascii.hexlify(encryptedMsg[0]),
            'nonce': binascii.hexlify(encryptedMsg[1]),
            'authTag': binascii.hexlify(encryptedMsg[2]),
            'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
        }
        # print("encrypted msg:", encryptedMsgObj)
        encryptedMsg1 = binascii.hexlify(encryptedMsg[0]).decode("utf-8")
        # print("encrypted msg", encryptedMsg1)

        decryptedMsg = decrypt_ECC(encryptedMsg, privKey)
        # print("decrypted msg:", decryptedMsg)
        decryptedMsg1 = decryptedMsg.decode("utf-8")
        # print("string", decryptedMsg1)
        self.emailfield_2.setText(encryptedMsg1)

    def gotocreate(self):
        # print("abc")
        message = self.emailfield.text()

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

        # msg = b'Text to be encrypted by ECC public key and '
        # print(type(msg))
        # print("second")
        msg = bytes(message, 'utf-8')
        # print("original msg:", msg)
        privKey = secrets.randbelow(curve.field.n)
        pubKey = privKey * curve.g

        encryptedMsg = encrypt_ECC(msg, pubKey)
        encryptedMsgObj = {
            'ciphertext': binascii.hexlify(encryptedMsg[0]),
            'nonce': binascii.hexlify(encryptedMsg[1]),
            'authTag': binascii.hexlify(encryptedMsg[2]),
            'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
        }
        # print("encrypted msg:", encryptedMsgObj)
        encryptedMsg1 = binascii.hexlify(encryptedMsg[0]).decode("utf-8")
        # print("encrypted msg", encryptedMsg1)

        decryptedMsg = decrypt_ECC(encryptedMsg, privKey)
        # print("decrypted msg:", decryptedMsg)
        decryptedMsg1 = decryptedMsg.decode("utf-8")
        # print("string", decryptedMsg1)
        self.emailfield_3.setText(decryptedMsg1)



# main
app = QApplication(sys.argv)
welcome = ECCScreen()
widget = QtWidgets.QStackedWidget()
widget.addWidget(welcome)
widget.setFixedHeight(870)
widget.setFixedWidth(1264)
widget.show()
try:
    sys.exit(app.exec_())
except:
    print("Exiting")