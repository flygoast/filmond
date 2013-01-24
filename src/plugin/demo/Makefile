CC = gcc
CFLAGS  = -fPIC -Wall -pipe -DDEBUG -g -D_GNU_SOURCE -D_REENTRANT
LDFLAGS = -Wl,-e,__demo_plugin_main
LIB 	= -ldl -lrt -rdynamic
INC     = -I ../../
OO	= demo.o
TARGETS = demo.so

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
