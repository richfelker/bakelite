SRCS = compats.c backup.c restore.c misccmds.c prune.c cull.c map.c flatmap.c localindex.c crypto.c store.c x25519.c sha3.c chacha20.c bloom.c binhex.c match.c main.c
OBJS = $(SRCS:.c=.o)

CFLAGS = -g -O3 -Wall
#CFLAGS = -O2 -Wall
#LDFLAGS = -static

all: config.h bakelite

config.h: configure
	./configure

bakelite: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f bakelite config.h $(OBJS)

$(OBJS):
