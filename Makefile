
CC       = gcc
ECHO     = echo "going to compile for target $@"
PROG = decryptor.out
SHARED_FLAGS= -shared -fPIC -pthread

SRCS := $(subst ./,,$(shell find . -maxdepth 1 -name "*.c" ! -iname "decrypter.c"))
OBJECTS := $(patsubst %.c, %.out,$(SRCS))

all: $(SRCS) $(OBJECTS)

%.out: %.c
	$(CC) $< -nostartfiles  -lmta_crypt -lmta_rand -lcrypto -pthread -L`pwd` -o $@

clean:
	rm *.out *.log *.o