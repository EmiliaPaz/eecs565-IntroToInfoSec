//*****************************************************************************
//
//		Author: Jay Offerdahl
//		Class:	EECS 565 (Intro. to Information Security)
//		Class:	Tues. 9:30a - 10:45a
//		Proj #:	2
//
//*****************************************************************************

#include <iostream>
#include <algorithm>
#include "VigenereCipher.h"

// Create a vigenere cipher object
VigenereCipher::VigenereCipher() {}

// Encrypts the input string using the input secret key
// @param plaintext - the string to be encrypted
// @param key - the string to encrypt the plaintext with
// @return the encrypted string
std::string VigenereCipher::encrypt(std::string plaintext, std::string key) {
	// Loop through the input, encrypting each character
	for(int i = 0, keyCounter = 0; i < plaintext.length(); i++) {
		plaintext.at(i) = (plaintext.at(i) + key.at(keyCounter) - 130) % 26 + 65;

		// Switch back to the front of the key, if applicable
		keyCounter = keyCounter == key.length() - 1 ? 0 : keyCounter + 1;
	}
	return plaintext;
}

// Decrypts the input string using the input secret key
// @param plaintext - the string to be decrypted
// @param key - the string to decrypt the plaintext with
// @return the decrypted string
std::string VigenereCipher::decrypt(std::string ciphertext, std::string key) {
	char tempChar;

	// Loop through the input, encrypting each character
	for(int i = 0, keyCounter = 0; i < ciphertext.length(); i++) {
		tempChar = ciphertext.at(i) - key.at(keyCounter);
		ciphertext.at(i) = tempChar < 0 ? tempChar + 91 : tempChar + 65;

		// Switch back to the front of the key, if applicable
		keyCounter = keyCounter == key.length() - 1 ? 0 : keyCounter + 1;
	}
	return ciphertext;
}

// Removes all whitespace from the input string & converts to uppercase
// @pre - the input string has only A-Z or a-z characters
// @param input - the string to be normalized
// @return the normalized string
std::string VigenereCipher::normalizeString(std::string input) {
	std::string temp = input;

	temp.erase(remove_if(temp.begin(), temp.end(), isspace), temp.end());

	// Make everything lowercase
	for(int i = 0; i < temp.length(); i++) {
		// If the character is uppercase, make it lowercase
		if(temp.at(i) >= 97 && temp.at(i) <= 122)	
			temp.at(i) -= 32;
	}
	return temp;
}