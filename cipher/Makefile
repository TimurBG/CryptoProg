# Простой Makefile с переменными
TARGET = cipher_programm
CXX = g++
CXXFLAGS = -std=c++11 -Wall
LIBS = -lcrypto++ -lpthread

all: $(TARGET)

$(TARGET): cipher_programm.cpp
	$(CXX) $(CXXFLAGS) cipher_programm.cpp -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET)
