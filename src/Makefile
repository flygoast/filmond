DEBUG = -g -DDEBUG
CC = gcc
CFLAGS  = $(DEBUG)  -Wall
LIB 	= -L ../lib  -linotifytools -lpthread -lcurl -lcrypto -lssl
OO	= filmond.o log.o md5.o conf.o dqueue.o threadpool.o lock.o
TARGETS = filmond

all: $(TARGETS) $(BIN)

$(TARGETS): $(OO)
	$(CC) $(CFLAGS) $(OO) -o $@ $(LIBDIR) $(LIB)

install:
	install $(TARGETS) ../bin/

.c.o:
	$(CC) $(CFLAGS) $< -c -o $@ $(INC) $(MYSQLCFLAGS)

clean:
	rm -f *.o
	rm -f $(TARGETS)
