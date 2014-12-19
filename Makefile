TARGET = myslowtrancapture

SRCS= local_addresses.cc my_slow_tran_capture.cc
OBJS= local_addresses.o my_slow_tran_capture.o

DEST= /usr/local/bin
CXX= g++
CXXFLAGS= -Wall -O3 `mysql_config --cflags`
LFLAGS= -Wall -O3
LIBS= -lpcap -lboost_regex -lmysqlclient

debug: LFLAGS= -g -DDEBUG
debug: CXXFLAGS= -g -DDEBUG `mysql_config --cflags`
debug: release

release: clean
release: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(LFLAGS) $(OBJS) $(LIBS) -o $(TARGET) `mysql_config --libs`

$(TARGET).o: $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS)

clean:
	rm -f *.o $(TARGET)

install: $(TARGET)
	install -s $(TARGET) $(DEST)

