CC=gcc
OBJS=pcap.o
TARGET=pcap
LIBS=-lpcap

all : $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LIBS)

clean :
	rm -f $(OBJS) $(TARGET)
