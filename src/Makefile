DEBUG = -g -DDEBUG
CC = gcc
CFLAGS  = $(DEBUG)  -Wall
LIB 	=  -rdynamic -L ../lib  -linotifytools -lpthread -ldl
OO	= filmond.o log.o conf.o hash.o so.o vector.o lock.o heap.o threadpool.o \
	  base64.o md5.o
TARGETS = filmond
VERS = version.h
PLUGIN = plugin

all: $(VERS) $(TARGETS) $(PLUGIN)

$(VERS):
	sh version.h.sh

$(TARGETS): $(OO)
	$(CC) $(CFLAGS) $(OO) -o $@ $(LIBDIR) $(LIB)

.PHONY: $(PLUGIN)
$(PLUGIN): plugin/
	make -C plugin

install:
	install $(TARGETS) ../bin/
	make -C plugin install

.c.o:
	$(CC) $(CFLAGS) $< -c -o $@ $(INC) $(MYSQLCFLAGS)

clean:
	rm -f $(VERS)
	rm -f *.o
	rm -f $(TARGETS)
	make -C plugin clean
