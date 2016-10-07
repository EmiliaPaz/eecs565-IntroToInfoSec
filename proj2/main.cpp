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
#include <vector>
#include "VigenereCipher.h"
#include "HashTable.h"
#include "Timer.cpp"

void fillTable(int, HashTable*&);
void crack(std::string, int, int);
double crackTime = 0;

int main()
{
	std::cout << "*****************************************************************************\n\n";
	std::cout << "                               IamAHacker.exe\n\n";
	std::cout << "*****************************************************************************\n";
	Timer* timer = new Timer();
	std::cout << "Starting whole program timer...\n";
	std::cout << "*****************************************************************************\n";
	timer->start();

	// Crack each given ciphertext
	crack("MSOKKJCOSXOEEKDTOSLGFWCMCHSUSGX", 2, 6);
	crack("OOPCULNWFRCFQAQJGPNARMEYUODYOUNRGWORQEPVARCEPBBSCEQYEARAJUYGWWYACYWBPRNEJBMDTEAEYCCFJNENSGWAQRTSJTGXNRQRMDGFEEPHSJRGFCFMACCB", 3, 7);
	crack("MTZHZEOQKASVBDOWMWMKMNYIIHVWPEXJA", 4, 10);
	crack("HUETNMIXVTMQWZTQMMZUNZXNSSBLNSJVSJQDLKR", 5, 11);
	crack("LDWMEKPOPSWNOAVBIDHIPCEWAETYRVOAUPSINOVDIEDHCDSELHCCPVHRPOHZUSERSFS", 6, 9);
	crack("VVVLZWWPBWHZDKBTXLDCGOTGTGRWAQWZSDHEMXLBELUMO", 7, 13);

	double duration = timer->stop();
	std::cout << "*****************************************************************************\n";
	std::cout << "Total cracking time: ";
	timer->printTime(crackTime);
	std::cout << "*****************************************************************************\n";
	std::cout << "Entire program length: ";
	timer->printTime(duration);
	std::cout << "*****************************************************************************\n\n";

	// Exit when user wants to
	while(true) {
		std::string temp;
		std::cout << "Press enter to exit...";
		getline(std::cin, temp);
		return 0;
	}
}

//*****************************************************************************
// Generate a hash table with words of input length, as well as all their 
// permutations --> used with cracking algorithm
void fillTable(int wordLen, HashTable*& table) {
	std::string input, temp;
	table = new HashTable();
	
	// Open the file
	std::ifstream file;
	file.open("dict.txt");

	// Load the dictionary into a hash table
	while(file >> input) {
		if(input.length() == wordLen) {
			// Insert all prefixes of the string, including the string itself
			for(int i = 0; i <= input.length(); i++) {
				temp = input.substr(0, i);
				if(!table->find(temp))
					table->insert(temp);
			}
		}
	}
	file.close();
}
//*****************************************************************************

//*****************************************************************************
// Cracks the cipher text given input key length, first word length, and
// input ciphertext by finding valid keys then decrypting
void crack(std::string ciphertext, int keyLen, int firstWordLen) {
	// Declare all necessary variables
	VigenereCipher* cipher = new VigenereCipher();
	std::vector<std::string> keyList;
	Timer* timer = new Timer();
	std::string word = "A", temp;
	HashTable* table;

	// Fills the hash table with all words of length firstWordLen and 
	// all of their permutations
	fillTable(firstWordLen, table);

	std::cout << "Testing key length: " << keyLen 
			  << ", and first word length: " << firstWordLen << "\n";

	timer->start();

	// Start valid keys as the first letters of the alphabet 
	for(char i = 65; i < 91; i++) {
		word = i;
		keyList.push_back(word);
	}

	// Find valid keys based on the keys in the list
	for(int index = 0; index < keyList.size(); index++) {
		word = ciphertext.substr(0, keyList[index].length());
		// If the decrypted text matches a string in the dictionary (including prefixes)
		if(table->find(cipher->decrypt(word, keyList[index]))) {
			// If the key can still be appended to
			if(keyList[index].length() < keyLen) {
				// Append A - Z on the key and only add them if they produce promising output
				for(char j = 65; j <= 90; j++) {
					temp = keyList[index] + j;
					if(table->find(cipher->decrypt(ciphertext.substr(0, temp.length()), temp)))
						keyList.push_back(temp);
				}	
			}
		}
		// If the key wasn't a match, remove it from the keyList
		else {
			keyList.erase(keyList.begin() + index);
			index--;
		}
	}

	// Decrypt each valid key found
	for(int i = 0; i < keyList.size(); i++) {
		// If the decrypted first word matches a word in the dictionary
		if(table->find(cipher->decrypt(ciphertext.substr(0, firstWordLen), keyList[i]))) {
			std::cout << "Possible key: " << keyList[i] << " --> output: " 
					  << cipher->decrypt(ciphertext, keyList[i]) << "\n";
		}
	}

	double duration = timer->stop();
	crackTime += duration;
	std::cout << "\nTime elapsed: ";
	timer->printTime(duration);
	std::cout << "\n";

	// Clean up memory
	delete cipher;
	delete table;
	delete timer;
}
//*****************************************************************************

/*
_________ .__          .__          __                .__                   ________              .__    .___                                  
\_   ___ \|  |_________|__| _______/  |_  ____ ______ |  |__   ___________  \______ \ _____ ___  _|__| __| _/                                  
/    \  \/|  |  \_  __ \  |/  ___/\   __\/  _ \\____ \|  |  \_/ __ \_  __ \  |    |  \\__  \\  \/ /  |/ __ |                                   
\     \___|   Y  \  | \/  |\___ \  |  | (  <_> )  |_> >   Y  \  ___/|  | \/  |    `   \/ __ \\   /|  / /_/ |                                   
 \______  /___|  /__|  |__/____  > |__|  \____/|   __/|___|  /\___  >__|    /_______  (____  /\_/ |__\____ |                                   
        \/     \/              \/              |__|        \/     \/                \/     \/             \/                                   
  _________                    .__           .__   __                                                                                          
 /   _____/ ____ _____    _____|  |__   ____ |  |_/  |_________                                                                                
 \_____  \_/ __ \\__  \  /  ___/  |  \ /  _ \|  |\   __\___   /                                                                                
 /        \  ___/ / __ \_\___ \|   Y  (  <_> )  |_|  |  /    /                                                                                 
/_______  /\___  >____  /____  >___|  /\____/|____/__| /_____ \ /\                                                                             
        \/     \/     \/     \/     \/                       \/ )/                                                                             
                                                                                                                                               
                                                                                                                                               
                                                                                                                                               
                                                                                                                                               
                                                                                                                                               
                                                                                                                                               
___________.__                   __                             _____                __          __   .__                                      
\__    ___/|  |__ _____    ____ |  | __  ___.__. ____  __ __  _/ ____\___________  _/  |______  |  | _|__| ____    ____                        
  |    |   |  |  \\__  \  /    \|  |/ / <   |  |/  _ \|  |  \ \   __\/  _ \_  __ \ \   __\__  \ |  |/ /  |/    \  / ___\                       
  |    |   |   Y  \/ __ \|   |  \    <   \___  (  <_> )  |  /  |  | (  <_> )  | \/  |  |  / __ \|    <|  |   |  \/ /_/  >                      
  |____|   |___|  (____  /___|  /__|_ \  / ____|\____/|____/   |__|  \____/|__|     |__| (____  /__|_ \__|___|  /\___  /                       
                \/     \/     \/     \/  \/                                                   \/     \/       \//_____/                        
  __  .__               __  .__                   __                                     .___         __  .__    .__                           
_/  |_|  |__   ____   _/  |_|__| _____   ____   _/  |_  ____      ________________     __| _/____   _/  |_|  |__ |__| ______                   
\   __\  |  \_/ __ \  \   __\  |/     \_/ __ \  \   __\/  _ \    / ___\_  __ \__  \   / __ |/ __ \  \   __\  |  \|  |/  ___/                   
 |  | |   Y  \  ___/   |  | |  |  Y Y  \  ___/   |  | (  <_> )  / /_/  >  | \// __ \_/ /_/ \  ___/   |  | |   Y  \  |\___ \                    
 |__| |___|  /\___  >  |__| |__|__|_|  /\___  >  |__|  \____/   \___  /|__|  (____  /\____ |\___  >  |__| |___|  /__/____  >                   
           \/     \/                 \/     \/                 /_____/            \/      \/    \/             \/        \/                    
                     .__                                     __      .___                      .__       .___                                  
_____    ______ _____|__| ____   ____   _____   ____   _____/  |_    |   | __  _  ______  __ __|  |    __| _/                                  
\__  \  /  ___//  ___/  |/ ___\ /    \ /     \_/ __ \ /    \   __\   |   | \ \/ \/ /  _ \|  |  \  |   / __ |                                   
 / __ \_\___ \ \___ \|  / /_/  >   |  \  Y Y  \  ___/|   |  \  |     |   |  \     (  <_> )  |  /  |__/ /_/ |                                   
(____  /____  >____  >__\___  /|___|  /__|_|  /\___  >___|  /__| /\  |___|   \/\_/ \____/|____/|____/\____ |                                   
     \/     \/     \/  /_____/      \/      \/     \/     \/     \/                                       \/                                   
.__  .__ __              __             __  .__                   __                             _____                                         
|  | |__|  | __ ____   _/  |_  ____   _/  |_|  |__ _____    ____ |  | __  ___.__. ____  __ __  _/ ____\___________                             
|  | |  |  |/ // __ \  \   __\/  _ \  \   __\  |  \\__  \  /    \|  |/ / <   |  |/  _ \|  |  \ \   __\/  _ \_  __ \                            
|  |_|  |    <\  ___/   |  | (  <_> )  |  | |   Y  \/ __ \|   |  \    <   \___  (  <_> )  |  /  |  | (  <_> )  | \/                            
|____/__|__|_ \\___  >  |__|  \____/   |__| |___|  (____  /___|  /__|_ \  / ____|\____/|____/   |__|  \____/|__|                               
             \/    \/                            \/     \/     \/     \/  \/                                                                   
  __  .__                 .___.__                                  .__                                        .__                              
_/  |_|  |__   ____     __| _/|__| ______ ____  __ __  ______ _____|__| ____   ____   ______ __  _  __ ____   |  |__ _____ ___  __ ____        
\   __\  |  \_/ __ \   / __ | |  |/  ___// ___\|  |  \/  ___//  ___/  |/  _ \ /    \ /  ___/ \ \/ \/ // __ \  |  |  \\__  \\  \/ // __ \       
 |  | |   Y  \  ___/  / /_/ | |  |\___ \\  \___|  |  /\___ \ \___ \|  (  <_> )   |  \\___ \   \     /\  ___/  |   Y  \/ __ \\   /\  ___/       
 |__| |___|  /\___  > \____ | |__/____  >\___  >____//____  >____  >__|\____/|___|  /____  >   \/\_/  \___  > |___|  (____  /\_/  \___  >      
           \/     \/       \/         \/     \/           \/     \/               \/     \/               \/       \/     \/          \/       
.__                .___       _____  .__                    .___                                                    __                         
|  |__ _____     __| _/      /  _  \ |  |   __________      |   |   ____   _______  __ ___________     ____   _____/  |_                       
|  |  \\__  \   / __ |      /  /_\  \|  |  /  ___/  _ \     |   |  /    \_/ __ \  \/ // __ \_  __ \   / ___\ /  _ \   __\                      
|   Y  \/ __ \_/ /_/ |     /    |    \  |__\___ (  <_> )    |   | |   |  \  ___/\   /\  ___/|  | \/  / /_/  >  <_> )  |                        
|___|  (____  /\____ | /\  \____|__  /____/____  >____/ /\  |___| |___|  /\___  >\_/  \___  >__|     \___  / \____/|__|                        
     \/     \/      \/ \/          \/          \/       )/             \/     \/          \/        /_____/                                    
                                      __           __    .__                                        .__            .__  __                     
  _____ ___.__. _______  ____   ____ |  | __ _____/  |_  |  |   ____ _____     ____  __ __   ____   |__| _______  _|__|/  |_  ____             
 /     <   |  | \_  __ \/  _ \_/ ___\|  |/ // __ \   __\ |  | _/ __ \\__  \   / ___\|  |  \_/ __ \  |  |/    \  \/ /  \   __\/ __ \            
|  Y Y  \___  |  |  | \(  <_> )  \___|    <\  ___/|  |   |  |_\  ___/ / __ \_/ /_/  >  |  /\  ___/  |  |   |  \   /|  ||  | \  ___/            
|__|_|  / ____|  |__|   \____/ \___  >__|_ \\___  >__|   |____/\___  >____  /\___  /|____/  \___  > |__|___|  /\_/ |__||__|  \___  > /\        
      \/\/                         \/     \/    \/                 \/     \//_____/             \/          \/                   \/  )/        
        .__            __            .__                    _________                                                                          
__  _  _|  |__ _____ _/  |_     ____ |__|__  __ ____   _____\_____   \                                                                         
\ \/ \/ /  |  \\__  \\   __\   / ___\|  \  \/ // __ \ /  ___/  /   __/                                                                         
 \     /|   Y  \/ __ \|  |    / /_/  >  |\   /\  ___/ \___ \  |   |                                                                            
  \/\_/ |___|  (____  /__|    \___  /|__| \_/  \___  >____  > |___|                                                                            
             \/     \/       /_____/               \/     \/  <___>                                                                            
                                                                                                                                               
                                                                                                                                               
                                                                                                                                               
                                                                                                                                               
                                                                                                                                               
                                                                                                                                               
     ____.              /\/\____  .__                          ________ ________           .__               __                _________._./\/\
    |    |____  ___.__. )/)/_   | |  |__   ____  __ _________  \_____  \\_____  \    _____ |__| ____  __ ___/  |_  ____   _____\_____   \ |)/)/
    |    \__  \<   |  |     |   | |  |  \ /  _ \|  |  \_  __ \  /  ____/ /  ____/   /     \|  |/    \|  |  \   __\/ __ \ /  ___/  /   __/ |    
/\__|    |/ __ \\___  |     |   | |   Y  (  <_> )  |  /|  | \/ /       \/       \  |  Y Y  \  |   |  \  |  /|  | \  ___/ \___ \  |   |   \|    
\________(____  / ____|     |___| |___|  /\____/|____/ |__|    \_______ \_______ \ |__|_|  /__|___|  /____/ |__|  \___  >____  > |___|   __    
              \/\/                     \/                              \/       \/       \/        \/                 \/     \/  <___>   \/    
________   _____  _____                .___      .__    .__                                                                                    
\_____  \_/ ____\/ ____\___________  __| _/____  |  |__ |  |                                                                                   
 /   |   \   __\\   __\/ __ \_  __ \/ __ |\__  \ |  |  \|  |                                                                                   
/    |    \  |   |  | \  ___/|  | \/ /_/ | / __ \|   Y  \  |__                                                                                 
\_______  /__|   |__|  \___  >__|  \____ |(____  /___|  /____/                                                                                 
        \/                 \/           \/     \/     \/                 
*/   