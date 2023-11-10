CC=gcc
CFLAGS=-g -Wall 
LDFLAGS=
OBJS=client.o
TARGET=client
LIBS=-lncurses

all: $(TARGET) clean_object

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(LIBS)

client.o: client.c
	$(CC) $(CFLAGS) -c client.c -o client.o $(LDFLAGS) $(LIBS)

clean:
	rm -f *.o
	rm -f $(TARGET) $(TARGET)

clean_object:
	rm -f *.o
.PHONY: client clean clean_object
