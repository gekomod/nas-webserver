CC = cc
CFLAGS = -Wall -Wextra -pedantic -std=c11 -g -DENABLE_PROFILING -D_POSIX_C_SOURCE=199309L
LDFLAGS = -lcrypto -lssl -lz
SRC = src/main.c src/config.c src/router.c src/error.c src/profiler.c
OBJ = $(SRC:.c=.o)
TARGET = dist/nas-web

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)
