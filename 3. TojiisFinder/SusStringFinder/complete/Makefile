CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
SRC = src/main.c src/scanner.c src/signatures.c src/reporter.c
TARGET = SusStringFinder

.PHONY: all clean debug

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

debug: $(SRC)
	$(CC) $(CFLAGS) -fsanitize=address,undefined -g -o $(TARGET)_debug $(SRC)

clean:
	rm -f $(TARGET) $(TARGET)_debug
