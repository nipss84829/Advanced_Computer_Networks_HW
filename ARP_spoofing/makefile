
CC = gcc
CFLAGS = -Wall -g
LDFLAGS = 
TARGET = arp
OBJS = main.o arp.o


$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)


main.o: main.c arp.h
	$(CC) $(CFLAGS) -c main.c


arp.o: arp.c arp.h
	$(CC) $(CFLAGS) -c arp.c


clean:
	rm -f $(OBJS) $(TARGET)


run: $(TARGET)
	./$(TARGET)

