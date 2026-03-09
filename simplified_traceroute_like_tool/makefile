CC = gcc
CFLAGS = -Wall

all: prog

prog: hw4.o
	$(CC) -o prog hw4.o
	
# Let user can directly execute this program because socket needs more higher privilege
	sudo setcap cap_net_raw+ep prog 

hw4.o: hw4.c
	$(CC) $(CFLAGS) -c hw4.c

