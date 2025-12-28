# Простой Makefile с переменными
TARGET = hash_programm
CXX = g++
CXXFLAGS = -std=c++11 -Wall
LIBS = -lcrypto++ -lpthread

all: $(TARGET)

$(TARGET): hash_programm.cpp
	$(CXX) $(CXXFLAGS) hash_programm.cpp -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET)
