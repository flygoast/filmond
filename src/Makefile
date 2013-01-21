DEBUG = -g -DDEBUG
CC = gcc
CFLAGS  = $(DEBUG)  -Wall
LIB 	= -L ../lib  -linotifytools -lpthread -lcurl -lcrypto -lssl -ljson
OO	= filmond.o log.o md5.o conf.o heap.o threadpool.o lock.o base64.o
TARGETS = filmond
VERS = version.h

all: $(VERS) $(TARGETS) $(BIN)

$(VERS):
	sh version.h.sh

$(TARGETS): $(OO)
	$(CC) $(CFLAGS) $(OO) -o $@ $(LIBDIR) $(LIB)

install:
	install $(TARGETS) ../bin/

.c.o:
	$(CC) $(CFLAGS) $< -c -o $@ $(INC) $(MYSQLCFLAGS)

clean:
	rm -f $(VERS)
	rm -f *.o
	rm -f $(TARGETS)
