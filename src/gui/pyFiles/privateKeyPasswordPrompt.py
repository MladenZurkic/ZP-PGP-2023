# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '.\uiFiles\privateKeyPasswordPrompt.ui'
#
# Created by: PyQt5 UI code generator 5.15.6
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_privateKeyPasswordPrompt(object):
    def setupUi(self, privateKeyPasswordPrompt):
        privateKeyPasswordPrompt.setObjectName("privateKeyPasswordPrompt")
        privateKeyPasswordPrompt.resize(400, 207)
        privateKeyPasswordPrompt.setStyleSheet("QPushButton {\n"
"    background-color: #dbd5c3;\n"
"}\n"
"QDialog { \n"
"   border: 1px solid black;\n"
"    background-color: #8d6535;\n"
"}\n"
"QTextEdit {\n"
"    background-color: #dbd5c3;\n"
"}")
        self.buttonBox = QtWidgets.QDialogButtonBox(privateKeyPasswordPrompt)
        self.buttonBox.setGeometry(QtCore.QRect(120, 170, 161, 23))
        self.buttonBox.setLayoutDirection(QtCore.Qt.RightToLeft)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.passwordInputText = QtWidgets.QTextEdit(privateKeyPasswordPrompt)
        self.passwordInputText.setGeometry(QtCore.QRect(90, 110, 221, 41))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(False)
        font.setItalic(False)
        font.setUnderline(False)
        font.setWeight(50)
        font.setKerning(True)
        self.passwordInputText.setFont(font)
        self.passwordInputText.setObjectName("passwordInputText")
        self.passwordLabel = QtWidgets.QLabel(privateKeyPasswordPrompt)
        self.passwordLabel.setGeometry(QtCore.QRect(0, 10, 401, 51))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(14)
        font.setBold(False)
        font.setItalic(False)
        font.setUnderline(False)
        font.setWeight(50)
        font.setKerning(True)
        self.passwordLabel.setFont(font)
        self.passwordLabel.setStyleSheet("QLabel {\n"
"    color: white;\n"
"}")
        self.passwordLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.passwordLabel.setObjectName("passwordLabel")
        self.privateKeyIDLabel = QtWidgets.QLabel(privateKeyPasswordPrompt)
        self.privateKeyIDLabel.setGeometry(QtCore.QRect(0, 70, 401, 31))
        font = QtGui.QFont()
        font.setFamily("Arial")
        font.setPointSize(12)
        self.privateKeyIDLabel.setFont(font)
        self.privateKeyIDLabel.setStyleSheet("QLabel {\n"
"    color: white;\n"
"}")
        self.privateKeyIDLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.privateKeyIDLabel.setObjectName("privateKeyIDLabel")

        self.retranslateUi(privateKeyPasswordPrompt)
        QtCore.QMetaObject.connectSlotsByName(privateKeyPasswordPrompt)

    def retranslateUi(self, privateKeyPasswordPrompt):
        _translate = QtCore.QCoreApplication.translate
        privateKeyPasswordPrompt.setWindowTitle(_translate("privateKeyPasswordPrompt", "Dialog"))
        self.passwordLabel.setText(_translate("privateKeyPasswordPrompt", "To View this Key\n"
"You Need to Enter Password:"))
        self.privateKeyIDLabel.setText(_translate("privateKeyPasswordPrompt", "placeholder"))
