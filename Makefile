SRCS = main.c backup.c restore.c misccmds.c prune.c map.c crypto.c store.c x25519.c sha3.c chacha20.c bloom.c
OBJS = $(SRCS:.c=.o)

CFLAGS = -g -O2 -Wall
#CFLAGS = -O2 -Wall
#LDFLAGS = -static

all: bakelite

bakelite: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f bakelite $(OBJS)

$(OBJS):
