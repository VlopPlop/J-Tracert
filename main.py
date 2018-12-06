import resource_rc
import gui
import funcs
from PyQt5 import QtCore, QtGui, QtWidgets
from requests import get



    

def go():
    ui.listWidget.clear()
    funcs.enable_loading_overlay(ui.processingLabel)
    app.processEvents()
    global data
    data, timeouts = funcs.prepare_data(ui.ipInput.toPlainText())
    if data == None:
        funcs.disable_loading_overlay(ui.processingLabel)
        return

    for x in data:
        ui.listWidget.addItem(x[0].replace('IPv4: ', 'v4:') + ' ' + x[1].replace('Resolved: ', 'R:'))

    ui.timeoutsNumber.setText('Tracert timeouts: ' + str(timeouts))
    ui.hopsNumber.setText('Hops: ' + str(len(data)))
    funcs.disable_loading_overlay(ui.processingLabel)

def inspectHop(index):
    ui.infoText.setText('')
    map_img = QtGui.QPixmap()
    
    try:
        if data[index][2] != None:
            map_img.loadFromData(data[index][2])
        else:
            map_img = QtGui.QPixmap(':/map.png')
    except:
        map_img = QtGui.QPixmap(':/map.png')
        
    ui.mapImg.setPixmap(map_img)
    ui.infoText.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop)
    for x in [value for counter, value in enumerate(data[index]) if counter != 2]:
        ui.infoText.setText(ui.infoText.text() + str(x) + '\n')
        



import resource_rc

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = gui.Ui_MainWindow()
    ui.setupUi(MainWindow)
    ui.traceButton.clicked.connect(go)
    ui.listWidget.currentRowChanged.connect(inspectHop)
    funcs.disable_loading_overlay(ui.processingLabel)
    ui.publicAddrLabel.setText('Public IPv4: ' + funcs.get_own_address())
    ui.notice_2.setText('Status: ' + str(get("http://google.com").status_code))
    MainWindow.show()

    

    sys.exit(app.exec_())