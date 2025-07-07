CC = gcc
CFLAGS = -Wall -Wextra -pedantic -std=c11 -g
LDFLAGS = -lcrypto -lssl
SRC = src/main.c src/config.c src/router.c
OBJ = $(SRC:.c=.o)
TARGET = dist/nas-web  # Zmieniona ścieżka docelowa

all: create_dist $(TARGET)

create_dist:
	mkdir -p dist

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)
	rmdir dist 2>/dev/null || true

install: all
	cp $(TARGET) /usr/local/bin/nas-web

.PHONY: all clean create_dist install
