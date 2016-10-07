proj2: main.o VigenereCipher.o HashTable.o
	g++ -g -std=c++11 main.o VigenereCipher.o HashTable.o -o proj2

main.o: main.cpp
	g++ -g -std=c++11 -c main.cpp

VigenereCipher.o: VigenereCipher.h VigenereCipher.cpp
	g++ -g -std=c++11 -c VigenereCipher.cpp

HashTable.o: HashTable.h HashTable.cpp
	g++ -g -std=c++11 -c HashTable.cpp

ifdef SystemRoot
    RM = del /Q
    FixPath = $(subst /,\,$1)
else
    ifeq ($(shell uname), Linux)
        RM = rm -f
        FixPath = $1
        EXEC = ./
    endif
endif

clean:
	$(RM) *.o *.exe proj2

build:
	make
	$(exec)proj2