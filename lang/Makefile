CFLAGS = -Wall -g

HEADERS = include/*.h

FRONT = lexer.c ast.c parser.c ut.c
SEMA  = annot.c func.c symtable.c
BACK  = bpflib.c buffer.c probe.c ir.c gen.c
SRCS  = $(FRONT) $(SEMA) $(BACK)

OBJS = $(SRCS:.c=.o)

TSRCS = $(FRONT) test.c
TOBJS = $(TSRCS:.c=.o)
TBINS = test.exe

%.o: %.c
	$(CC) $(CFLAGS) -Iinclude -c $< -o $@

all: $(OBJS)
	$(CC) -o voyant $(OBJS) $(LDFLAGS)

test: $(TOBJS)
	$(CC) -o $(TBINS) $(TOBJS) $(LDFLAGS)
	./$(TBINS)

ct:
	rm -f $(TOBJS) $(TBINS)

clean:
	rm -f $(OBJS) voyant

.PHONY: all clean test ct