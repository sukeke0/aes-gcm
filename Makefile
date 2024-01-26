OBJS = aes128.o aes128gcm.o test.o

TARGET = test

CFLAGS = -std=c99 -O2 -Wunused-variable -fomit-frame-pointer -funroll-loops
LFLAGS = 

.SUFFIXES: .c .o

all: $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(CFLAGS) $(LFLAGS)

.c.o : $<
	$(CC) -c $(CFLAGS) $<

clean : 
	rm -f *.o $(OBJS) $(TARGET)

