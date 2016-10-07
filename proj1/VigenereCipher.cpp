//***********************************************
//
//	Author: Jay Offerdahl
//	Class:	EECS 565 (Intro. to Info. Security)
//	Lab:	Tues. 9:30a - 10:45a
//	Proj #: 1
//
//***********************************************

#include <iostream>
#include <algorithm>
#include "VigenereCipher.h"

// Create a vigenere cipher object which prompts for key
VigenereCipher::VigenereCipher() {
	std::string input;

	std::cout << "Please enter a secret key for this cipher: ";
	getline(std::cin, input);

	setKey(input);
	std::cout << "\nKey set. Please remember this value.\n";
}

// Create a vigenere cipher with input key
VigenereCipher::VigenereCipher(std::string key) {
	setKey(key);
}

// Sets the key of the vigenere cipher to the input string
void VigenereCipher::setKey(std::string key) {
	m_key = normalizeString(key);
}

// Encrypts the input string using the privately stored key
// Returns the newly encrypted string
std::string VigenereCipher::encrypt(std::string plaintext) {
	std::string normalized = normalizeString(plaintext);

	std::string key = m_key;
	int keyLen = m_key.length(), keyCounter = 0;

	// Loop through the input, encrypting each character
	for(int i = 0; i < normalized.length(); i++) {
		normalized.at(i) = ((normalized.at(i) - 97) + (key.at(keyCounter) - 97) % 26) % 26 + 97;

		// Switch back to the front of the key, if applicable
		keyCounter = keyCounter == m_key.length() - 1 ? 0 : keyCounter + 1;
	}
	return normalized;
}

// Decrypts the input string using the privately stored key
// Returns the decrypted input
std::string VigenereCipher::decrypt(std::string ciphertext) {
	std::string normalized = normalizeString(ciphertext);

	std::string key = m_key;
	char tempChar;
	int keyLen = m_key.length(), keyCounter = 0;

	// Loop through the input, encrypting each character
	for(int i = 0; i < normalized.length(); i++) {
		tempChar = normalized.at(i) - key.at(keyCounter);

		// Account for wrapping around the alphabet
		// % operator was unable to perform this...further investigation required
		if(tempChar < 0) {
			tempChar += 26;
		}
		normalized.at(i) = (tempChar % 26) + 97;

		// Switch back to the front of the key, if applicable
		keyCounter = keyCounter == m_key.length() - 1 ? 0 : keyCounter + 1;
	}
	return normalized;
}

// Removes all whitespace from the input string
// Assumes the input string is value (alphabetic characters)
std::string VigenereCipher::normalizeString(std::string input) {
	std::string temp = input;

	temp.erase(remove_if(temp.begin(), temp.end(), isspace), temp.end());

	// Make everything lowercase
	for(int i = 0; i < temp.length(); i++) {
		// If the character is uppercase, make it lowercase
		if(temp.at(i) >= 65 && temp.at(i) <= 90) {	
			temp.at(i) += 32;
		}
	}
	return temp;
}