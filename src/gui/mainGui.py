import sys

from PyQt5 import QtWidgets, QtGui
from PyQt5.QtWidgets import QMainWindow, QApplication
from src.gui.pyFiles.mainWindow import Ui_MainWindow

class Window(QMainWindow, Ui_MainWindow):


    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.pushButton.clicked.connect(self.testing)
        self.actionAbout.triggered.connect(self.testing)

    def testing(self):
        print("test")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    mainWindow = Window()

    widget = QtWidgets.QStackedWidget()
    widget.addWidget(mainWindow)
    widget.show()
    widget.setFixedSize(800, 500)
    sys.exit(app.exec_())