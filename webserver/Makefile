CC = cc
CFLAGS = -Wall -Wextra -Wno-unused-parameter -O2 -pedantic -std=c11 -g -DENABLE_PROFILING -D_POSIX_C_SOURCE=199309L -D_GNU_SOURCE
LDFLAGS = -lcrypto -lssl -lz -lnghttp2 -lpthread -lcrypto 
SRC = src/main.c src/router.c src/config.c src/error.c src/profiler.c src/threadpool.c src/logging.c security/isolation.c security/monitoring.c
OBJ = $(SRC:.c=.o)
TARGET = dist/nas-web

# Benchmark variables
BENCHMARK_SRC = src/benchmark.c
BENCHMARK_TARGET = dist/benchmark
BENCHMARK_CFLAGS = -Wall -Wextra -O2 -pthread

all: $(TARGET) benchmark

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Benchmark build
benchmark: $(BENCHMARK_SRC)
	$(CC) $(BENCHMARK_CFLAGS) -o $(BENCHMARK_TARGET) $(BENCHMARK_SRC)

clean:
	rm -f $(OBJ) $(TARGET) $(BENCHMARK_TARGET)

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/nas-web
	mkdir -p /etc/nas-web
	cp config/nas-web.conf /etc/nas-web/
	mkdir -p /var/log/nas-web

run: $(TARGET)
	./$(TARGET)

bench: benchmark
	./$(BENCHMARK_TARGET)

load-test: benchmark
	./$(BENCHMARK_TARGET) 127.0.0.1 8080 50 200

test-endpoints: benchmark
	./$(BENCHMARK_TARGET) 127.0.0.1 8080 5 100

.PHONY: all clean install run bench load-test test-endpoints
