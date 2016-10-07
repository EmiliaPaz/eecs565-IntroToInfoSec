proj1: main.o VigenereCipher.o
	g++ -g -std=c++11 main.o VigenereCipher.o -o proj1

main.o: main.cpp
	g++ -g -std=c++11 -c main.cpp

VigenereCipher.o: VigenereCipher.h VigenereCipher.cpp
	g++ -g -std=c++11 -c VigenereCipher.cpp

ifdef SystemRoot
    RM = del /Q
    FixPath = $(subst /,\,$1)
else
    ifeq ($(shell uname), Linux)
        RM = rm -f
        FixPath = $1
    endif
endif

clean:
	$(RM) *.o *.exe proj1