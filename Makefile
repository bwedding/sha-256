objects = sha256.o
CC = c++ -std=c++20 -o sha256

sha256.o : sha256.cpp
	$(CC) sha256.cpp
clean : 
	-rm -f sha256

