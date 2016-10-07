//*****************************************************************************
//
//		Author: Jay Offerdahl
//		Class:	EECS 565 (Intro. to Information Security)
//		Class:	Tues. 9:30a - 10:45a
//		Proj #:	2
//
//*****************************************************************************

#ifndef V_CIPHER_H
#define V_CIPHER_H

#include <string>

class VigenereCipher
{
public:
	// Create a vigenere cipher object which prompts for key
	VigenereCipher();

	// Encrypts the input string using the input secret key
	// @param plaintext - the string to be encrypted
	// @param key - the string to encrypt the plaintext with
	// @return the encrypted string
	std::string encrypt(std::string, std::string);

	// Decrypts the input string using the input secret key
	// @param plaintext - the string to be decrypted
	// @param key - the string to decrypt the plaintext with
	// @return the decrypted stri
	std::string decrypt(std::string, std::string);

	// Removes all whitespace from the input string & converts to uppercase
	// @pre - the input string has only A-Z or a-z characters
	// @param input - the string to be normalized
	// @return the normalized string
	std::string normalizeString(std::string);
};

#endif
