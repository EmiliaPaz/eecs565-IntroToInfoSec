import sys
import csv
import itertools
import time
import string

#Just because it made adding the Blackboard words easier.
class EncryptedWord(object):
    def __init__(self, text, key, firstWord):
        self.text = str(text)
        self.key = int(key)
        self.firstWord = int(firstWord)

#Does the exact same thing as the Encrypt function, except you subtract
# the values to remove the encryption
def Decrypt(text, key):
    decrypted = ""
    for n in range(0, len(text), 1):
        decrypted += chr((((ord(text[n])-97)-((ord(key[n%len(key)]))-97))% 26) +97)
    return decrypted.upper()

def crack(firstWordLength, keyLength, cipherText):
    #Initalizations
    plaintext = ""
    possibleFirstWords = {}
    possibleKeys = dict.fromkeys(string.ascii_uppercase, 1)
    firstRun = True
    
    #Gets the encrypted first word
    cryptFirstWord = cipherText[:int(firstWordLength)]

    #Opens the given dictionary
    dictionaryFile = open('dict.txt', 'r')

    #Gets all possible first words
    for line in dictionaryFile:
        if len(line.rstrip()) == firstWordLength:
            possibleFirstWords[line.rstrip()]=1

    #Start the timing clock
    start = time.clock()

    #Run through this function until the key length has been met
    for i in range(keyLength):
        tempKeys={}
        possibleNKeys = {}

        #Gets only the amount of letters needed from possible first words
        #and puts it in a hash table
        for currWord in possibleFirstWords:
            possibleNKeys[currWord[:i+1]] = 1

        #If we are running this for the first time, we already have keys
        #of length 1 in the possibleNKeys hash table
        if firstRun:

            #Go through every possible key, which is just the alphabet at this point
            for key in possibleKeys.keys():

                #Try to decrypt the first letter of the encrypted word against
                #the current letter. If a possible first word starts with that
                #letter, then add the key to a temporary hash table 
                if Decrypt(cryptFirstWord[i], key) in possibleNKeys:
                    tempKeys[key] = 1

            #Don't come back to this area of the function
            firstRun = False
            
        else:

            #We already have all the possible first letters of the key
            for key in possibleKeys.keys():

                #We need to try every possible second, third, fourth, etc.
                #letter in addition to those possible first letters.
                #If the combination matches, add it to the possible keys table
                for c in string.ascii_uppercase:
                    if Decrypt(cryptFirstWord[:i+1], key+c) in possibleNKeys:
                        tempKeys[key+c]=1
        #update the possible keys table for the next round or for the cracking
        possibleKeys = tempKeys

    #Getting to this point means that we have found all possible keys of the given length
    for currKey in possibleKeys.keys():

        #Decrypt the first word using one of the keys in the table
        decrypted = Decrypt(cryptFirstWord, currKey)

        #If the decrypted word is in the list of possible first words, output
        #the information to the user
        if decrypted in possibleFirstWords:
            print("Key: " + currKey)
            print("Decrypted Text: " + Decrypt(cipherText, currKey))

    #End the timing
    fintime = time.clock()-start

    #Write how long it took to decrypt
    print("It took " + str(fintime) + " seconds to decrypt")
    

def main():

    print("****************************")
    print("* Starting   the   Cracker *")
    print("****************************\n")

    #Find out what the user wants to do
    choice = input("Would you like to use your own (T)ext or the ones from (B)lackboard?")

    #If they choose to put their own encrypted text in, go here
    if choice.upper() == "T":
        
        #Gets all parameters from the user
        cipherText = input('Please input the encrypted text: ')
        keyLength = int(input('Please input the key length: '))
        firstWordLength = int(input('Please input the length of the first word: '))

        #Crack the text the user input
        crack(firstWordLength, keyLength, cipherText)

    #If they choose to run using the text from Blackboard, go here
    elif choice.upper() == "B":

        #Telling the user what we are doing.
        print("\nUsing the encrypted text from Blackboard...\n")

        #All the information from Blackboard, plus one of my own
        encryptedFromBlackboard = []
        encryptedFromBlackboard.append(EncryptedWord("MSOKKJCOSXOEEKDTOSLGFWCMCHSUSGX", 2, 6))
        encryptedFromBlackboard.append(EncryptedWord("OOPCULNWFRCFQAQJGPNARMEYUODYOUNRGWORQEPVARCEPBBSCEQYEARAJUYGWWYACYWBPRNEJBMDTEAEYCCFJNENSGWAQRTSJTGXNRQRMDGFEEPHSJRGFCFMACCB", 3, 7))
        encryptedFromBlackboard.append(EncryptedWord("MTZHZEOQKASVBDOWMWMKMNYIIHVWPEXJA", 4, 10))
        encryptedFromBlackboard.append(EncryptedWord("HUETNMIXVTMQWZTQMMZUNZXNSSBLNSJVSJQDLKR", 5, 11))
        encryptedFromBlackboard.append(EncryptedWord("LDWMEKPOPSWNOAVBIDHIPCEWAETYRVOAUPSINOVDIEDHCDSELHCCPVHRPOHZUSERSFS", 6, 9))
        encryptedFromBlackboard.append(EncryptedWord("VVVLZWWPBWHZDKBTXLDCGOTGTGRWAQWZSDHEMXLBELUMO", 7, 13))
        encryptedFromBlackboard.append(EncryptedWord("qynlrahxvfucwgeyewdwtgknrmgnhpremwslxkcumumsuw".upper(), 12, 14))

        #Loop through every item and run the cracking function on it
        for item in encryptedFromBlackboard:
            if item.key == 12:
                print("I added this one in because my numbers looked odd since key length 6 has a longer time than key length 7.")
                print("The correct key is JAYHAWKERSRU\n")
            print("Cracking key length: " + str(item.key))
            crack(item.firstWord, item.key, item.text)
            print("-----------")
        

#Runs everything
if __name__ == '__main__':
    main()
