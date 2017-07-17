CC=gcc
#OBJS=pcap.o
TARGET=hw0717
LIBS=-lpcap

all : $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) -o $(TARGET) $(TARGET).c $(LIBS)

clean :
	rm -f $(OBJS) $(TARGET)
