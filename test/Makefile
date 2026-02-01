CFLAGS = -Wall -g -I../lang/include

HEADERS = ../lang/include/*.h

TEST_SRCS = test_lexer.c
LEXER_SRCS = ../lang/lexer.c ../lang/ut.c ../lang/test_framework.c

TEST_OBJS = $(TEST_SRCS:.c=.o)
LEXER_OBJS = $(LEXER_SRCS:.c=.o)
ALL_OBJS = $(TEST_OBJS) $(LEXER_OBJS)

TEST_BIN = test_lexer

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

../lang/%.o: ../lang/%.c
	$(CC) $(CFLAGS) -c $< -o $@

all: $(TEST_BIN)

test: $(TEST_BIN)
	./$(TEST_BIN)

$(TEST_BIN): $(ALL_OBJS)
	$(CC) -o $(TEST_BIN) $(ALL_OBJS) $(LDFLAGS)

clean:
	rm -f $(TEST_OBJS) $(LEXER_OBJS) $(TEST_BIN)

.PHONY: all test clean
