//*****************************************************************************
//
//		Author: Jay Offerdahl
//		Class:	EECS 565 (Intro. to Information Security)
//		Class:	Tues. 9:30a - 10:45a
//		Proj #:	2
//
//*****************************************************************************

#include <iostream>
#include <string>
#include <fstream>
#include "VigenereCipher.h"
#include "HashTable.h"
#include "Timer.cpp"

void fillTable(int, HashTable*&);

int main()
{
	//*************************************************************************
	// Declare all necessary variables
	VigenereCipher* cipher = new VigenereCipher();
	HashTable* table = nullptr;
	Timer* timer = new Timer();
	Timer* totalTimer = new Timer();

	std::string str1, str2, key;
	double duration;
	//*************************************************************************


	//*************************************************************************
	// Brute force cracking & timing Tests
	totalTimer->start();

	std::cout << "\n\nTest #1: Key length of 2, first word length of 6\n";
	key = "AA";
	fillTable(6, table);
	timer->start();

	// key length = 2; firstWordLength = 6
	// "MSOKKJCOSXOEEKDTOSLGFWCMCHSUSGX"
	for(key.at(0) = 'A'; key.at(0) < 91; key.at(0)++) {
		for(key.at(1) = 'A'; key.at(1) < 91; key.at(1)++) {
			str1 = cipher->decrypt("MSOKKJ", key);
			if(table->find(str1))
				std::cout << "Possible key: " << key << " --> output: " << 
				cipher->decrypt("MSOKKJCOSXOEEKDTOSLGFWCMCHSUSGX", key) << "\n";
		}
	}

	duration = timer->stop();
	std::cout << "\nTime elapsed for #1: ";
	timer->printTime(duration);

	std::cout << "\n\nTest #2: Key length of 3, first word length of 7\n";
	key = "AAA";
	fillTable(7, table);
	timer->start();

	// keyLength=3; firstWordLength = 7
	// "OOPCULNWFRCFQAQJGPNARMEYUODYOUNRGWORQEPVARCEPBBSCEQYEARAJUYGWWYACYWBPRNEJBMDTEAEYCCFJNENSGWAQRTSJTGXNRQRMDGFEEPHSJRGFCFMACCB"
	for(key.at(0) = 'A'; key.at(0) < 91; key.at(0)++) {
		for(key.at(1) = 'A'; key.at(1) < 91; key.at(1)++) {
			for(key.at(2) = 'A'; key.at(2) < 91; key.at(2)++) {
				str1 = cipher->decrypt("OOPCULN", key);
				if(table->find(str1))
					std::cout << "Possible key: " << key << " --> output: " << 
					cipher->decrypt("OOPCULNWFRCFQAQJGPNARMEYUODYOUNRGWORQEPVARCEPBBSCEQYEARAJUYGWWYACYWBPRNEJBMDTEAEYCCFJNENSGWAQRTSJTGXNRQRMDGFEEPHSJRGFCFMACCB", key) << "\n";
			}
		}
	}

	duration = timer->stop();
	std::cout << "\nTime elapsed for #2: ";
	timer->printTime(duration);

	std::cout << "\n\nTest #3: Key length of 4, first word length of 10\n";
	key = "AAAA";
	fillTable(10, table);
	timer->start();

	// keyLength=4; firstWordLength = 10
	// "MTZHZEOQKASVBDOWMWMKMNYIIHVWPEXJA"
	for(key.at(0) = 'A'; key.at(0) < 91; key.at(0)++) {
		for(key.at(1) = 'A'; key.at(1) < 91; key.at(1)++) {
			for(key.at(2) = 'A'; key.at(2) < 91; key.at(2)++) {
				for(key.at(3) = 'A'; key.at(3) < 91; key.at(3)++) {
					str1 = cipher->decrypt("MTZHZEOQKA", key);
					if(table->find(str1))
						std::cout << "Possible key: " << key << " --> output: " << 
						cipher->decrypt("MTZHZEOQKASVBDOWMWMKMNYIIHVWPEXJA", key) << "\n";
				}
			}
		}
	}

	duration = timer->stop();
	std::cout << "\nTime elapsed for #3: ";
	timer->printTime(duration);

	std::cout << "\n\nTest #4: Key length of 5, first word length of 11\n";
	key = "AAAAA";
	fillTable(11, table);
	timer->start();

	// keyLength=5; firstWordLength = 11
	// "HUETNMIXVTMQWZTQMMZUNZXNSSBLNSJVSJQDLKR"
	for(key.at(0) = 'A'; key.at(0) < 91; key.at(0)++) {
		for(key.at(1) = 'A'; key.at(1) < 91; key.at(1)++) {
			for(key.at(2) = 'A'; key.at(2) < 91; key.at(2)++) {
				for(key.at(3) = 'A'; key.at(3) < 91; key.at(3)++) {
					for(key.at(4) = 'A'; key.at(4) < 91; key.at(4)++) {
						str1 = cipher->decrypt("HUETNMIXVTM", key);
						if(table->find(str1))
							std::cout << "Possible key: " << key << " --> output: " << 
							cipher->decrypt("HUETNMIXVTMQWZTQMMZUNZXNSSBLNSJVSJQDLKR", key) << "\n";
					}
				}
			}
		}
	}

	duration = timer->stop();
	std::cout << "\nTime elapsed for #4: ";
	timer->printTime(duration);
	
	std::cout << "\n\nTest #5: Key length of 6, first word length of 9\n";
	key = "AAAAAA";
	fillTable(9, table);
	timer->start();

	// keyLength=6; firstWordLength = 9
	// "LDWMEKPOPSWNOAVBIDHIPCEWAETYRVOAUPSINOVDIEDHCDSELHCCPVHRPOHZUSERSFS"
	for(key.at(0) = 'A'; key.at(0) < 91; key.at(0)++) {
		for(key.at(1) = 'A'; key.at(1) < 91; key.at(1)++) {
			for(key.at(2) = 'A'; key.at(2) < 91; key.at(2)++) {
				for(key.at(3) = 'A'; key.at(3) < 91; key.at(3)++) {
					for(key.at(4) = 'A'; key.at(4) < 91; key.at(4)++) {
						for(key.at(5) = 'A'; key.at(5) < 91; key.at(5)++) {
							str1 = cipher->decrypt("LDWMEKPOP", key);
							if(table->find(str1))
								std::cout << "Possible key: " << key << " --> output: " << 
								cipher->decrypt("LDWMEKPOPSWNOAVBIDHIPCEWAETYRVOAUPSINOVDIEDHCDSELHCCPVHRPOHZUSERSFS", key) << "\n";
						}
					}
				}
			}
		}
	}

	duration = timer->stop();
	std::cout << "\nTime elapsed for #5: ";
	timer->printTime(duration);

	std::cout << "\n\nTest #6: Key length of 7, first word length of 13\n";
	key = "AAAAAAA";
	fillTable(13, table);
	timer->start();

	// keyLength=7; firstWordLength = 13
	// "VVVLZWWPBWHZDKBTXLDCGOTGTGRWAQWZSDHEMXLBELUMO"
	for(key.at(0) = 'A'; key.at(0) < 91; key.at(0)++) {
		for(key.at(1) = 'A'; key.at(1) < 91; key.at(1)++) {
			for(key.at(2) = 'A'; key.at(2) < 91; key.at(2)++) {
				for(key.at(3) = 'A'; key.at(3) < 91; key.at(3)++) {
					for(key.at(4) = 'A'; key.at(4) < 91; key.at(4)++) {
						for(key.at(5) = 'A'; key.at(5) < 91; key.at(5)++) {
							for(key.at(6) = 'A'; key.at(6) < 91; key.at(6)++) {
								str1 = cipher->decrypt("VVVLZWWPBWHZD", key);
								if(table->find(str1))
									std::cout << "Possible key: " << key << " --> output: " << 
									cipher->decrypt("VVVLZWWPBWHZDKBTXLDCGOTGTGRWAQWZSDHEMXLBELUMO", key) << "\n";
							}
						}
					}
				}
			}
		}
	}

	duration = timer->stop();
	std::cout << "\nTime elapsed for #6: ";
	timer->printTime(duration);
	std::cout << "\n\n";

	duration = totalTimer->stop();
	std::cout << "\nEntire program length: ";
	totalTimer->printTime(duration);
	std::cout << "\n\n";

	//*************************************************************************

	// Exit when user wants to
	while(true) {
		std::cout << "Press enter to exit...\n";
		getline(std::cin, str1);

		delete cipher;
		delete table;
		return 0;
	}
}

// Return a hashtable with words that are only as long as the specified length
void fillTable(int wordLen, HashTable*& table) {
	std::string temp;

	if(table != nullptr)
		delete table;

	table = new HashTable();

	std::ifstream file;
	file.open("dict.txt");

	// Load the dictionary into a hash table
	while(file >> temp) {
		if(temp.length() == wordLen)
			table->insert(temp);
	}

	file.close();
}
//*************************************************************************