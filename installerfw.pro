CONFIG += ordered
TEMPLATE = subdirs
SUBDIRS += src tools
!macx:SUBDIRS += examples

test.target = test
test.depends = $(TARGET)
QMAKE_EXTRA_TARGETS += test
test.commands = (cd tests && $(QMAKE) && $(MAKE))

include (doc/doc.pri)
