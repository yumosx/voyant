.PHONY: all clean
HEADERS = lexer.h insn.h  ast.h parser.h dsl.h testbase.h
SRCS = lexer.c ast.c parser.c dsl.c compile_test.c

CFLAGS = -Wall -g

OBJS = $(SRCS:.c=.o)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

all: $(OBJS)
	$(CC) -o voyant $(OBJS) $(LDFLAGS)

clean:
	rm -f $(OBJS) voyant
