//*****************************************************************************
//
//		Author: Jay Offerdahl
//		Class:	EECS 565 (Intro. to Information Security)
//		Class:	Tues. 9:30a - 10:45a
//		Proj #:	2
//
//*****************************************************************************

#ifndef HASHTABLE_H
#define HASHTABLE_H

#include <string>

class HashTable
{
public:
	// Create a hashtable object & initializes all table addresses to "*" (empty)
	HashTable();

	// Compute the hash of an input string
	// @note - The code could be shortened here, but I'm looking for performance
	// so storing variables in memory instead of computing them a lot is a boost
	// @param key - the input key to compute the hash of
	// @return - the integer location of where the key could/should be
	int hash(std::string);

	// Insert a word into the hash table
	// @param word - the string to be inserted
	void insert(std::string);

	// Print out the hash table (testing)
	// @note - This prints out in order, of the table, so the words will be
	// scrambled beyond any meaningful pattern.
	void print();

	// Determines whether or not the key exists in the table
	// @param key - the input string to look for in the table
	// @return - true if the key is found in an entry in the table
	bool find(std::string);

private:
	// Size of the dictionary we're storing
	static const size_t tableSize = 165620;

	// Struct to hold the dictionary entries (basically a node)s
	struct entry {
		std::string word;
		entry* next;
	};

	// The actual array for the hash table
	entry* table[tableSize];
};

#endif
