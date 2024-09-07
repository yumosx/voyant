.PHONY: all clean

HEADERS = include/*.h
SRCS = ut.c bpflib.c buffer.c ir.c syscall.c func.c lexer.c ast.c parser.c symtable.c annot.c
CFLAGS = -Wall -g
OBJS = $(SRCS:.c=.o)

%.o: %.c
	$(CC) $(CFLAGS) -Iinclude -c $< -o $@

all: $(OBJS)
	$(CC) -o voyant $(OBJS) $(LDFLAGS)

clean:
	rm -f $(OBJS) voyant
