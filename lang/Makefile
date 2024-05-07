.PHONY: all clean
HEADERS = lexer.h insn.h tracepoint.h dsl.h testbase.h
SRCS = lexer.c dsl.c parse_test.c compile_test.c
CFLAGS = -Wall -g

OBJS = $(SRCS:.c=.o)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

all: $(OBJS)
	$(CC) -o program $(OBJS) $(LDFLAGS)

clean:
	rm -f $(OBJS) program
