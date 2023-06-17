import base64
import os
import sys
import time

from PyQt5.QtWidgets import QMainWindow, QApplication, QFileDialog, QDialog, QTableWidgetItem, QPushButton, QHeaderView
from PyQt5 import QtWidgets
from src.gui.pyFiles.mainWindow import Ui_MainWindow
from src.gui.pyFiles.sendPrompt import Ui_Dialog
from src.gui.pyFiles.receivePrompt import Ui_ReceiveDialog
from src.impl.user import User
from src.impl.compression.compression import compress, decompress
from src.impl.conversion.conversion import decodeFromRadix64, encodeToRadix64


class SendPrompt(QDialog, Ui_Dialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.buttonBox.accepted.connect(self.buttonOK)
        self.buttonBox.rejected.connect(self.buttonCancel)

    def buttonOK(self):
        self.accept()

    def buttonCancel(self):
        self.reject()

class ReceivePrompt(QDialog, Ui_ReceiveDialog):
    def __init__(self, keyID, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.buttonBox.accepted.connect(self.buttonOK)
        self.buttonBox.rejected.connect(self.buttonCancel)
        self.receiveKeyIDLabel.setText(keyID)

    def buttonOK(self):
        self.accept()

    def buttonCancel(self):
        self.reject()


class Window(QMainWindow, Ui_MainWindow):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)


        self.generateButton.clicked.connect(self.generateKeysGUI)
        self.sendSignCheckBox.clicked.connect(self.signCheckBoxClicked)
        self.sendEncryptCheckBox.clicked.connect(self.encryptCheckBoxClicked)
        self.sendButton.clicked.connect(self.sendMessage)

        self.receiveBrowsePathInputText.clicked.connect(self.receiveBrowseClicked)

        self.importKeyTypePrivateRadioButton.clicked.connect(self.importKeyTypePrivateClicked)
        self.importKeyTypePublicRadioButton.clicked.connect(self.importKeyTypePublicClicked)
        self.importBrowseForPUButton.clicked.connect(self.importBrowsePUClicked)
        self.importBrowseForPRButton.clicked.connect(self.importBrowsePRClicked)
        self.importButton.clicked.connect(self.importKeys)

        # Disable fileds in send tab:
        self.sendSignPrivateIDInput.setDisabled(True)
        self.sendSignPrivateIDInput.setStyleSheet("QTextEdit { background-color: #a3a3a3; }")
        self.sendPrivateIDSignLabel.setStyleSheet("QLabel { color: #a3a3a3; }")

        self.sendAESRadioButton.setDisabled(True)
        self.send3DESRadioButton.setDisabled(True)
        self.sendEncryptPublicIDInputText.setDisabled(True)
        self.sendEncryptPublicIDInputText.setStyleSheet("QTextEdit { background-color: #a3a3a3; }")
        self.sendPublicIDEncryptLabel.setStyleSheet("QLabel { color: #a3a3a3; }")
        self.sendAESRadioButton.setStyleSheet("QRadioButton { color: #a3a3a3; }")
        self.send3DESRadioButton.setStyleSheet("QRadioButton { color: #a3a3a3; }")


        self.receiveButton.clicked.connect(self.receiveMessage)
        # Disable fields in import tab:
        self.importPathForPRInputText.setDisabled(True)
        self.importPathForPRInputText.setStyleSheet("QTextEdit { background-color: #a3a3a3; }")
        self.importPathForPRLabel.setStyleSheet("QLabel { color: #a3a3a3; }")
        self.importBrowseForPRButton.setDisabled(True)
        self.importBrowseForPRButton.setStyleSheet("QPushButton { background-color: #a3a3a3; }")

        self.generateErrorLabel.setStyleSheet("QLabel { color: red; }")
        self.sendErrorLabel.setStyleSheet("QLabel { color: red; }")

        header = self.privateKeyRingTable.horizontalHeader()
        header.resizeSection(0, 170)
        header.resizeSection(1, 170)
        header.resizeSection(4, 100)
        header.resizeSection(5, 100)

        self.user = User()

    def checkFields(self, forWhat):
        match forWhat:
            case "generateKeys":
                self.generateErrorLabel.setStyleSheet("QLabel { color: red; }")
                if self.generateNameInputText.toPlainText() == "":
                    self.generateErrorLabel.setText("Name is empty!")
                    return -1

                if self.generateEmailInputText.toPlainText() == "":
                    self.generateErrorLabel.setText("Email is empty!")
                    return -1

                if not (self.generateRSARadioButton.isChecked() or self.generateDSAElGamalRadioButton.isChecked()):
                    self.generateErrorLabel.setText("Algorithm is not selected!")
                    return -1

                if not (
                        self.generateKeySize1024RadioButton.isChecked() or self.generateKeysize2048RadioButton.isChecked()):
                    self.generateErrorLabel.setText("Key Size is not selected!")
                    return -1

                if self.generatePasswordInputText.toPlainText() == "":
                    self.generateErrorLabel.setText("Password is empty!")
                    return -1
                return 0

            case "send":
                self.sendErrorLabel.setStyleSheet("QLabel { color: red; }")
                if self.sendMessageInputText.toPlainText() == "":
                    self.sendErrorLabel.setText("Message is empty!")
                    return -1

                if self.sendSignCheckBox.isChecked():
                    if self.sendSignPrivateIDInput.toPlainText() == "":
                        self.sendErrorLabel.setText("Private ID for Signing is empty!")
                        return -1

                if self.sendEncryptCheckBox.isChecked():
                    if not (self.sendAESRadioButton.isChecked() or self.send3DESRadioButton.isChecked()):
                        self.sendErrorLabel.setText("Algorithm is not selected!")
                        return -1

                    if self.sendEncryptPublicIDInputText.toPlainText() == "":
                        self.sendErrorLabel.setText("Public ID for Encryption is empty!")
                        return -1
                if self.sendFilenameInputText.toPlainText() == "":
                    self.sendErrorLabel.setText("Filename is empty!")
                    return -1
                return 0
            case "receive":
                self.receivedMessageBox.setStyleSheet("color: red;")
                if self.receiveMessagePathInput.toPlainText() == "":
                    self.receivedMessageBox.setText("Message Path is empty!")
                    return -1

                path = self.receiveMessagePathInput.toPlainText()

                if not os.path.exists(path):
                    self.receivedMessageBox.setText("Message Path is invalid!")
                    return -1

                self.receivedMessageBox.setStyleSheet("color: black;")
                self.receivedMessageBox.setText("")
                return 0
            case "import":
                if self.importKeyTypePublicRadioButton.isChecked():
                    if self.importPathForPUInputText.toPlainText() == "":
                        self.importErrorLabel.setText("Path for Public Key is empty!")
                        return -1
                    path = self.importPathForPUInputText.toPlainText()
                    if not os.path.exists(path):
                        self.importErrorLabel.setText("Path for Public Key is invalid!")
                        return -1
                elif self.importKeyTypePrivateRadioButton.isChecked():
                    if self.importPathForPUInputText.toPlainText() == "":
                        self.importErrorLabel.setText("Path for Public Key is empty!")
                        return -1
                    PUpath = self.importPathForPUInputText.toPlainText()
                    if not os.path.exists(PUpath):
                        self.importErrorLabel.setText("Path for Public Key is invalid!")
                        return -1

                    if self.importPathForPRInputText.toPlainText() == "":
                        self.importErrorLabel.setText("Path for Private Key is empty!")
                        return -1
                    PRpath = self.importPathForPRInputText.toPlainText()
                    if not os.path.exists(PRpath):
                        self.importErrorLabel.setText("Path for Private Key is invalid!")
                        return -1
                else:
                    self.importErrorLabel.setText("Key Type is not selected!")
                    return -1
                return 0

    def generateKeysGUI(self):
        # Check all fields:
        if self.checkFields("generateKeys") == 0:
            self.generateErrorLabel.setText("Key Generated!")
            self.generateErrorLabel.setStyleSheet("QLabel { color: lightgreen; }")
            name = self.generateNameInputText.toPlainText()
            email = self.generateEmailInputText.toPlainText()
            algorithm = "RSA" if (self.generateRSARadioButton.isChecked()) else "DSA+ElGamal"
            keySize = 1024 if (self.generateKeySize1024RadioButton.isChecked()) else 2048
            password = self.generatePasswordInputText.toPlainText()
            signingKeyID, encyptionKeyID = self.user.generateKeys(name, email, algorithm, keySize, password)
            self.user.printKeys()
            self.addRowToPrivateKeyRingTable(signingKeyID, "Signing")
            self.addRowToPrivateKeyRingTable(encyptionKeyID, "Encryption")

    def sendMessage(self):
        if self.checkFields("send") == 0:
            message = self.sendMessageInputText.toPlainText()
            timestamp = time.time()
            filename = self.sendFilenameInputText.toPlainText()

            data = message + "~#~" + str(timestamp) + "~#~" + filename
            operations = "M"

            # Sign data if selected:
            if self.sendSignCheckBox.isChecked():
                # Open prompt for password:
                popup = SendPrompt()
                if popup.exec_() == QDialog.Accepted:
                    password = popup.passwordInputText.toPlainText()
                else:
                    self.sendErrorLabel.setText("Password not entered or not correct!")
                    return -1

                privateID = self.sendSignPrivateIDInput.toPlainText()
                signature = self.user.signData(data, int(privateID), password)
                operations = "S" + operations
                data = data + "~#~" + signature + "~#~" + "LEADING TWO OCTETS?" + "~#~" + privateID + "~#~" + str(timestamp)

            # Compress data if selected:
            if self.sendCompressCheckBox.isChecked():
                operations = "C" + operations
                data = compress(data)
                data = base64.b64encode(data).decode('utf-8')

            # Encrypt data if selected:
            if self.sendEncryptCheckBox.isChecked():
                publicID = self.sendEncryptPublicIDInputText.toPlainText()
                algorithm = "AES" if (self.sendAESRadioButton.isChecked()) else "3DES"
                encryptedData, encryptedSessionKey, publicKeyID = self.user.encryptData(data, int(publicID), algorithm)
                operations = "E" + operations
                data = encryptedData + "~#~" + encryptedSessionKey + "~#~" + publicKeyID + "~#~" + algorithm

            # Convert to Radix if selected:
            if self.sendRadixCheckBox.isChecked():
                operations = "R" + operations
                data = encodeToRadix64(data)

            # Save to file:
            frame = QFileDialog.getSaveFileName(self, 'Save File', 'C:\\Users\\Mladen\\Desktop\\TestZPFajlovi\\' + filename + '.txt', "Txt File (*.txt)")
            if (frame[0] == ""):
                self.sendErrorLabel.setText("Message not saved.")
            else:
                with open(frame[0], 'w') as f:
                    f.write(operations + "~#~" + data)
                self.sendErrorLabel.setText("Saved Message at:" + frame[0])
                self.sendErrorLabel.setStyleSheet("QLabel { color: lightgreen; }")


    def receiveMessage(self):
        if self.checkFields("receive") == 0:
            with open(self.receiveMessagePathInput.toPlainText(), 'r') as f:
                data = f.read()
            operations, data = data.split("~#~", 1)
            if "R" in operations:
                data = decodeFromRadix64(data)
            if "E" in operations:

                encryptedData, encryptedSessionKey, publicKeyID, algorithm = data.split("~#~")

                #Open prompt for password:
                receivePopup = ReceivePrompt(publicKeyID)
                if receivePopup.exec_() == QDialog.Accepted:
                    password = receivePopup.passwordInputText.toPlainText()
                else:
                    self.receivedMessageBox.setStyleSheet("color: red;")
                    self.receivedMessageBox.setText("Password not entered or not correct!")
                    return -1

                data = self.user.decryptData(encryptedData, encryptedSessionKey, publicKeyID, password, algorithm)

            if "C" in operations:
                data = decompress(base64.b64decode(data))
            if "S" in operations:

                message, timestamp, filename, signature, leadingTwoOctets, publicID, timestamp = data.split("~#~")
                publicKey = self.user.publicKeyring.getKey(int(publicID))

                toVerify = message + "~#~" + timestamp + "~#~" + filename

                if self.user.verifySignature(toVerify, signature, publicKey,
                                             self.user.privateKeyring.getKeyForSigning(int(publicID)).usedAlgorithm):
                    self.receivedMessageBox.setText("Message is verified!")
                else:
                    self.receivedMessageBox.setStyleSheet("color: red;")
                    self.receivedMessageBox.setText("Message is not verified!")
                data = message + "~#~" + timestamp + "~#~" + filename
            message, timestamp, filename = data.split("~#~")
            self.receivedMessageBox.setText(message)

    def importKeys(self):
        if self.checkFields("import") == 0:
            if self.importKeyTypePublicRadioButton.isChecked():
                path = self.importPathForPUInputText.toPlainText()
                publicKeyID = self.user.publicKeyring.importKey(path)
                self.addRowToPublicKeyRingTable(publicKeyID)

            else:
                pathPU = self.importPathForPUInputText.toPlainText()
                pathPR = self.importPathForPRInputText.toPlainText()
                publicKeyID = self.user.publicKeyring.importKey(pathPU)
                usage = "Signing" if self.importKeyUsageSignRadioButton.isChecked() else "Encryption"
                privateKeyID = self.user.privateKeyring.importKey(pathPU, pathPR, usage)

                self.addRowToPrivateKeyRingTable(privateKeyID, usage)
                self.addRowToPublicKeyRingTable(publicKeyID)
        self.user.printKeys()



    def addRowToPrivateKeyRingTable(self, keyID, usage):
        rowPosition = self.privateKeyRingTable.rowCount()
        self.privateKeyRingTable.insertRow(rowPosition)

        if usage == 'Signing' or usage == 's':
            privateKey = self.user.privateKeyring.getKeyForSigning(keyID)
        else:
            privateKey = self.user.privateKeyring.getKeyForEncryption(keyID)

        userID = privateKey.userID
        algorithm = privateKey.usedAlgorithm
        self.privateKeyRingTable.setItem(rowPosition, 0, QTableWidgetItem(str(keyID)))
        self.privateKeyRingTable.setItem(rowPosition, 1, QTableWidgetItem(str(userID)))
        self.privateKeyRingTable.setItem(rowPosition, 2, QTableWidgetItem(str(usage)))
        self.privateKeyRingTable.setItem(rowPosition, 3, QTableWidgetItem(str(algorithm)))

        buttonMore = QPushButton("More..")
        buttonMore.clicked.connect(lambda checked, id=keyID: self.handle_button_click(id))
        self.privateKeyRingTable.setCellWidget(rowPosition, 4, buttonMore)

        buttonDelete = QPushButton("Delete")
        buttonDelete.setStyleSheet("QPushButton { background-color: #b0a996; font: bold; }")
        buttonDelete.clicked.connect(lambda checked, id=keyID: self.deletePrivateKey(id))
        self.privateKeyRingTable.setCellWidget(rowPosition, 5, buttonDelete)


    def addRowToPublicKeyRingTable(self, keyID):
        rowPosition = self.publicKeyRingTable.rowCount()
        self.publicKeyRingTable.insertRow(rowPosition)

        publicKey = self.user.publicKeyring.getKey(keyID)
        userID = publicKey.userID
        algorithm = publicKey.usedAlgorithm
        self.publicKeyRingTable.setItem(rowPosition, 0, QTableWidgetItem(str(keyID)))
        self.publicKeyRingTable.setItem(rowPosition, 1, QTableWidgetItem(str(userID)))
        self.publicKeyRingTable.setItem(rowPosition, 2, QTableWidgetItem(str(algorithm)))

        buttonMore = QPushButton("More..")
        buttonMore.clicked.connect(lambda checked, id=keyID: self.handle_button_click(id))
        self.publicKeyRingTable.setCellWidget(rowPosition, 3, buttonMore)

        buttonDelete = QPushButton("Delete")
        buttonDelete.setStyleSheet("QPushButton { background-color: #b0a996; font: bold; }")
        buttonDelete.clicked.connect(lambda checked, id=keyID: self.deletePublicKey(id))
        self.publicKeyRingTable.setCellWidget(rowPosition, 4, buttonDelete)


    def handle_button_click(self, keyID):
        print("Button clicked, Row ", keyID)


    def deletePublicKey(self, keyID):
        rowCount = self.publicKeyRingTable.rowCount()
        for row in range(rowCount):
            if self.publicKeyRingTable.item(row, 0).text() == str(keyID):
                self.publicKeyRingTable.removeRow(row)
                #IMPLEMENTIRATI DELETE IZ PUBLIC KEYRINGA
                break

    def deletePrivateKey(self, keyID):
        rowCount = self.privateKeyRingTable.rowCount()
        for row in range(rowCount):
            if self.privateKeyRingTable.item(row, 0).text() == str(keyID):
                self.privateKeyRingTable.removeRow(row)
                #IMPLEMENTIRATI DELETE IZ PRIVATE KEYRINGA
                break

    def signCheckBoxClicked(self):
        if self.sendSignCheckBox.isChecked():
            self.sendSignPrivateIDInput.setDisabled(False)
            self.sendSignPrivateIDInput.setStyleSheet("")
            self.sendPrivateIDSignLabel.setStyleSheet("")
        else:
            self.sendSignPrivateIDInput.setDisabled(True)
            self.sendSignPrivateIDInput.setStyleSheet("QTextEdit { background-color: #a3a3a3; }")
            self.sendPrivateIDSignLabel.setStyleSheet("QLabel { color: #a3a3a3; }")

    def encryptCheckBoxClicked(self):
        if self.sendEncryptCheckBox.isChecked():
            self.sendAESRadioButton.setDisabled(False)
            self.send3DESRadioButton.setDisabled(False)
            self.sendEncryptPublicIDInputText.setDisabled(False)
            self.sendEncryptPublicIDInputText.setStyleSheet("")
            self.sendPublicIDEncryptLabel.setStyleSheet("")
            self.sendAESRadioButton.setStyleSheet("")
            self.send3DESRadioButton.setStyleSheet("")
        else:
            self.sendAESRadioButton.setDisabled(True)
            self.send3DESRadioButton.setDisabled(True)
            self.sendEncryptPublicIDInputText.setDisabled(True)
            self.sendEncryptPublicIDInputText.setStyleSheet("QTextEdit { background-color: #a3a3a3; }")
            self.sendPublicIDEncryptLabel.setStyleSheet("QLabel { color: #a3a3a3; }")
            self.sendAESRadioButton.setStyleSheet("QRadioButton { color: #a3a3a3; }")
            self.send3DESRadioButton.setStyleSheet("QRadioButton { color: #a3a3a3; }")

    def receiveBrowseClicked(self):
        frame = QFileDialog.getOpenFileName(self, 'Open Message to Read', 'C:\\Users\\Mladen\\Desktop\\TestZPFajlovi\\', "All files (*.*)")
        self.receiveMessagePathInput.setText(frame[0])

    def importBrowsePUClicked(self):
        frame = QFileDialog.getOpenFileName(self, 'Open Public Key PEM File', 'C:\\Users\\Mladen\\Desktop\\', "PEM Files (*.pem)")
        self.importPathForPUInputText.setText(frame[0])

    def importBrowsePRClicked(self):
        frame = QFileDialog.getOpenFileName(self, 'Open Private Key PEM File', 'C:\\Users\\Mladen\\Desktop\\', "PEM Files (*.pem)")
        self.importPathForPRInputText.setText(frame[0])

    def importKeyTypePrivateClicked(self):
        if self.importKeyTypePrivateRadioButton.isChecked():
            self.importPathForPRInputText.setDisabled(False)
            self.importPathForPRInputText.setStyleSheet("")
            self.importPathForPRLabel.setStyleSheet("")
            self.importBrowseForPRButton.setDisabled(False)
            self.importBrowseForPRButton.setStyleSheet("")
        else:
            self.importPathForPRInputText.setDisabled(True)
            self.importPathForPRInputText.setStyleSheet("QTextEdit { background-color: #a3a3a3; }")
            self.importPathForPRLabel.setStyleSheet("QLabel { color: #a3a3a3; }")
            self.importBrowseForPRButton.setDisabled(True)
            self.importBrowseForPRButton.setStyleSheet("QPushButton { background-color: #a3a3a3; }")

    def importKeyTypePublicClicked(self):
        if self.importKeyTypePublicRadioButton.isChecked():
            self.importPathForPRInputText.setDisabled(True)
            self.importPathForPRInputText.setStyleSheet("QTextEdit { background-color: #a3a3a3; }")
            self.importPathForPRLabel.setStyleSheet("QLabel { color: #a3a3a3; }")
            self.importBrowseForPRButton.setDisabled(True)
            self.importBrowseForPRButton.setStyleSheet("QPushButton { background-color: #a3a3a3; }")
        else:
            self.importPathForPRInputText.setDisabled(False)
            self.importPathForPRInputText.setStyleSheet("")
            self.importPathForPRLabel.setStyleSheet("")
            self.importBrowseForPRButton.setDisabled(False)
            self.importBrowseForPRButton.setStyleSheet("")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    mainWindow = Window()

    widget = QtWidgets.QStackedWidget()
    widget.addWidget(mainWindow)
    widget.show()
    widget.setFixedSize(780, 690)
    sys.exit(app.exec_())