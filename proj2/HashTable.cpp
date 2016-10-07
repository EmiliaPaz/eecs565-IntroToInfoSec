//*****************************************************************************
//
//		Author: Jay Offerdahl
//		Class:	EECS 565 (Intro. to Information Security)
//		Class:	Tues. 9:30a - 10:45a
//		Proj #:	2
//
//*****************************************************************************

#include <iostream>
#include "HashTable.h"

// Create a hashtable object & initializes all table addresses to "*" (empty)
HashTable::HashTable() {
	for(int i = 0; i < tableSize; i++) {
		table[i] = new entry;
		table[i]->word = "*";
		table[i]->next = nullptr;
	}
}

// Compute the hash of an input string
// @note - The code could be shortened here, but I'm looking for performance 
// so storing variables in memory instead of calculating them a lot is a boost
// @param key - the input key to compute the hash of
// @return - the integer location of where the key could/should be
int HashTable::hash(std::string key) {
	int hash = 0;
	int size = key.length();
	char temp;

	for(int i = 0; i < size; i++) {
		temp = key.at(i);
		hash += temp * temp;
	}

	return hash;
}

// Insert a word into the hash table
// @param word - the string to be inserted
void HashTable::insert(std::string word) {
	int index = hash(word);

	entry* temp = table[index];

	// Set up the new entry
	entry* add = new entry;
	add->word = word;
	add->next = nullptr;

	while(temp->next != nullptr)
		temp = temp->next;

	temp->next = add;
}

// Print out the hash table (testing)
// @note - This prints out in order, of the table, so the words will be
// scrambled beyond any meaningful pattern.
void HashTable::print() {
	entry* temp;

	for(int i = 0; i < tableSize; i++) {
		temp = table[i];

		while(temp != nullptr) {
			std::cout << temp->word << "\n";
			temp = temp->next;
		}
	}
}

// Determines whether or not the key exists in the table
// @param key - the input string to look for in the table
// @return - true if the key is found in an entry in the table
bool HashTable::find(std::string key) {
	int index = hash(key);

	entry* temp = table[index];

	while(temp != nullptr) {
		if(temp->word == key)
			return true;

		temp = temp->next;
	}
	return false;
}                                                                   