//***********************************************
//
//	Author: Jay Offerdahl
//	Class:	EECS 565 (Intro. to Info. Security)
//	Lab:	Tues. 9:30a - 10:45a
//	Proj #: 1
//
//***********************************************

#include <iostream>
#include <string>
#include "VigenereCipher.h"

int main(int argc, char** argv)
{
	// User workflow
	bool cont = true;
	int temp;
	std::string tempString;

	VigenereCipher* cipher = new VigenereCipher();

	while(cont) {
		std::cout << "Options: \n" << "1. Encrypt Text\n" << "2. Decrypt Text\n" 
			<< "3. Change Key\n" << "4. Quit\n\n" << "Choice: ";

		std::cin >> temp;
		std::cout << std::endl;

		std::cin.ignore(10000, '\n');

		switch(temp) {
			// Encrypt Text
			case 1: {
				std::cout << "Enter text to encrypt: ";
				getline(std::cin, tempString);
				std::cout << "Encrypted text: " << cipher->encrypt(tempString) << "\n\n";
				break;
			}
			// Decrypt Text
			case 2: {
				std::cout << "Enter text to decrypt: ";
				getline(std::cin, tempString);
				std::cout << "Decrypted text: " << cipher->decrypt(tempString) << "\n\n";
				break;
			}
			// Change Key
			case 3: {
				std::cout << "Are you sure you want to change the key?\nAny previously encrypted text"
					<< " will be unable to be decoded by this program. (y/n)\n" << "Choice: ";
				std::cin >> tempString;

				if(tempString == "y" || tempString == "Y") {
					std::cin.ignore(10000, '\n');
					std::cout << "\nEnter new key: ";
					getline(std::cin, tempString);
					cipher->setKey(tempString);

					std::cout << "The key has been successfully changed.\n\n";
				}
				break;
			}
			// Quit
			case 4: {
				cont = false;
				break;
			}
			default: {
				std::cout << "Invalid input, please try again.\n\n";
				break;
			}
		}
	}
	return 0;
}