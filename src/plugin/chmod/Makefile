CC = gcc
CFLAGS  = -fPIC -Wall -pipe -DDEBUG -g -D_GNU_SOURCE -D_REENTRANT
LDFLAGS = -Wl,-e,__chmod_plugin_main
LIB 	= -L ../../lib -ldl -lrt -rdynamic -ljson -lcurl -lcrypto -lssl
INC     = -I ../../
OO	= chmod.o
TARGETS = chmod.so

all: $(TARGETS)


$(TARGETS): $(OO)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OO) -shared -o $@ $(LIBDIR) $(LIB)

install:
	install $(TARGETS) ../../../bin/

.c.o:
	$(CC) $(CFLAGS) $< -c -o $@ $(INC)

clean:
	rm -f *.o
	rm -f $(TARGETS)
