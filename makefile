CC = gcc
CFLAGS = -m32 -Wall -Wextra

TARGET = myELF
SRC = myELF.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f $(TARGET)
