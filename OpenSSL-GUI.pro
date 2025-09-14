QT       += core gui
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets


CONFIG += c++17

# ------------ Auto-detect sources ------------
SOURCES += $$files(src/*.cpp, true)
HEADERS += $$files(include/*.h, true)
FORMS   += $$files(ui/*.ui, true)
RESOURCES += $$files(resources/*.qrc, true)

# ------------ Default rules for deployment ------------
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

# ------------ Dependencies (OpenSSL) ------------
INCLUDEPATH += "D:/a/_temp/msys64/ucrt64/include"
DEPENDPATH  += "D:/a/_temp/msys64/ucrt64/include"
LIBS += -L"D:/a/_temp/msys64/ucrt64/lib" -lssl -lcrypto

# ------------ Output Directories ------------
debug {
    DESTDIR     = $$PWD/build/bin
    OBJECTS_DIR = $$PWD/build/obj
    MOC_DIR     = $$PWD/build/moc
    RCC_DIR     = $$PWD/build/rcc
    UI_DIR      = $$PWD/build/ui
}

release {
    DESTDIR     = $$PWD/release/bin
    OBJECTS_DIR = $$PWD/release/obj
    MOC_DIR     = $$PWD/release/moc
    RCC_DIR     = $$PWD/release/rcc
    UI_DIR      = $$PWD/release/ui
}