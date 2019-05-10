TARGET = crypto
LIBS = -lm
CC = gcc
#CFLAGS = -g -std=c99 -Wall
CFLAGS = -std=c99 -Wall

.PHONY: default all clean

default: $(TARGET)

all: default

debug: CFLAGS = -g -DDEBUG -std=c99 -Wall
debug: $(TARGET)


# attention aux fichier .c qui trainent dans le répertoire
# si par exemple "crypto copy serveur.c" cela va générer
# des cibles "copy" puis "crypto" ... la misère !!!
OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -Wall $(LIBS) -o $@

clean:
	-rm -f *.o
	-rm -f $(TARGET)
	-rm -f data/*.cry
	-rm -f data/_*
