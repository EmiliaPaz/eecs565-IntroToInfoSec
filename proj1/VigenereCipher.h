//***********************************************
//
//	Author: Jay Offerdahl
//	Class:	EECS 565 (Intro. to Info. Security)
//	Lab:	Tues. 9:30a - 10:45a
//	Proj #: 1
//
//***********************************************

#ifndef V_CIPHER_H
#define V_CIPHER_H

#include <string>

class VigenereCipher
{
public:
	// Create a vigenere cipher object which prompts for key
	VigenereCipher();

	// Create a vigenere cipher with input key
	VigenereCipher(std::string);

	// Sets the key of the vigenere cipher to the input string
	void setKey(std::string);

	// Encrypts the input string using the privately stored key
	std::string encrypt(std::string);

	// Decrypts the input string using the privately stored key
	std::string decrypt(std::string);

	// Removes all spaces from the text
	std::string normalizeString(std::string);

private:
	// Private string to hold the secret key to encode with
	std::string m_key;
};

#endif
