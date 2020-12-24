"""

Uses Fork to Connect to Multiple Clients
Uses AES (ECB Mode) for Encryption/Decryption

Reference: Computer Networking: A Top Down Approach Chapter 2
Pycryptodome docs: https://pycryptodome.readthedocs.io/en/latest/

Author: Sharon Lee
"""

import socket
import sys
import os
import os.path
from os import path
import json
import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

"""
	This function, client() establishes an encryption
	environment & a socket used to communicate with server. 
	Parameters: None
	Returns: None
"""
def client():

	#Server Information
	serverName = input('Enter the server IP or name: ')
	serverPort = 13000
	
	#Client socket: uses IPv4 & TCP protocols
	try:
		clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	except socket.error as e:
		print('Error in creating client socket: ', e)
		sys.exit(1)
	
	try:
		#Client connect with server
		clientSocket.connect((serverName, serverPort))
		
		welcome = clientSocket.recv(2048).decode('ascii')
		username = input(welcome + "\nUsername: ")
		password = input("Password: ")
		loginInfo = "" + username + "\n" + password
		
		#encryption with server public key (AES)
		loginInfoEnc = encryptWithPublic(loginInfo)
		
		clientSocket.send(loginInfoEnc)
		
		#verification 
		verificationMsg = clientSocket.recv(2048)
		
		verificationMessage = ""
		try:
			verificationMessage = verificationMsg.decode('ascii')
		except:
			pass
		
		if (verificationMessage == "\nLogin failed.\nPlease try again later."):
			print(verificationMessage)
			clientSocket.close() 
			return

		key = decryptSymKey(username, verificationMsg)
		symKeyToFile(key)
		
		#Set up encryption environment
		cipherBlock = setUpAES(key)
		confirm = "OK"
		confirmEnc = encryptMsg(cipherBlock, confirm)
		clientSocket.send(confirmEnc)
		
		menu = clientSocket.recv(2048)
		menuDec = decryption(cipherBlock, menu)
		
		choice = input(menuDec)
		choiceEnc = encryptMsg(cipherBlock, choice)
		clientSocket.send(choiceEnc)
		
		while (choice != "2"):
		
			if (choice == "1"):
				uploadMenu = clientSocket.recv(2048)
				uploadMenuDec = decryption(cipherBlock, uploadMenu)
				
				uploadChoice = input(uploadMenuDec)
				uploadChoiceEnc = encryptMsg(cipherBlock, uploadChoice)
				clientSocket.send(uploadChoiceEnc)
					
				while (uploadChoice != "3"):
					if (uploadChoice == "1"):
						
						#Obtain file info
						fileInfo = sendFileInfo(clientSocket, cipherBlock)
						
						#Extract file info
						div = fileInfo.find('\n')
						fname = fileInfo[:div]; size = fileInfo[div+1:]
						
						if fname.endswith('png') == True:
							#Use extracted file info to send file contents
							sendFileContents(cipherBlock, clientSocket, fname, size)
							print('Upload process completed')
						else:
							print('Not an image file.')
						
					elif (uploadChoice == "4"):
						clientSocket.close()
						return 
						
					else:
						uploadChoice = input(uploadMenuDec)
						uploadChoiceEnc = encryptMsg(cipherBlock, uploadChoice)
						clientSocket.send(uploadChoiceEnc)
						
					uploadChoice = input(uploadMenuDec)
					uploadChoiceEnc = encryptMsg(cipherBlock, uploadChoice)
					clientSocket.send(uploadChoiceEnc)
			else:
				choice = input(menuDec)
				choiceEnc = encryptMsg(cipherBlock, choice)
				clientSocket.send(choiceEnc)
			
			choice = input(menuDec)
			choiceEnc = encryptMsg(cipherBlock, choice)
			clientSocket.send(choiceEnc)
			
		clientSocket.close() 
		return


		
	except socket.error as e:
		print('Error occurred: ', e)
		clientSocket.close()
		sys.exit(1)
	
	except Exception as inst:
		print('Error with', inst)
	
		
#####################################################################################################
#Functions
#####################################################################################################

#prep for AES encryption
"""
	This function, setUpCrypto(), generates an
	encryption key and cipher block.
	Parameters: fname - string
	Returns: (Key, cipherBlock) - tuple
"""
def setUpAES(key):
	#Generate cipher block
	cipherBlock = genBlock(key)
	return cipherBlock

"""
	This function, genBlock(), generates & returns
	a cipher block in ECB mode under AES.
	Parameters: key - bytes
	Returns: block - AES cipher object
"""
def genBlock(key):
	return AES.new(key, AES.MODE_ECB)




#=========================================================================================================#
# FILE - FUNCTIONS
#=========================================================================================================#

"""
	This function, checkDir(), gets size of 
	an existing file in the same directory.
	Parameters: 
	Returns: 
	
"""
def checkDir(fname):
	size = 0
	#If file-to-be-uploaded exists in directory, get file size
	
	if path.exists(fname) == True: 
		size = os.path.getsize(fname)
	else:
		print('File doesn\'t exist.')
	
	return size


"""
	This function, sendFileInfo(), sends & receives
	messages from the server.
	Parameters: clientSocket - socket
	Returns: reply - str
	
"""
def sendFileInfo(clientSocket, cipherBlock):
	reply = ''

	#Receive item from server that prompts user input
	prompt = clientSocket.recv(2048)
	promptDec = decryption(cipherBlock, prompt)
	fname = input(promptDec)
	
	#Obtain file size & format response
	size = checkDir(fname)
	reply += fname + '\n' + str(size)
	replyEnc = encryptMsg(cipherBlock, reply)
	
	#Sends user input to server
	clientSocket.send(replyEnc)

	return reply

"""
	This function, sendFileContents(), sends
	file contents while it's not entirely sent.
	Parameters: 
	Returns: None
	
"""
def sendFileContents(cipherBlock, clientSocket, fname, fileSize):
	
	#Assign buffer size for transferring
	bufferSize = 2048

	#When OK is received, initiate transfer
	ok = clientSocket.recv(2048)
	okDec = decryption(cipherBlock, ok)
	
	print(okDec)
	
	if 'OK' in okDec:
	
		with open(fname, "rb") as f:
			
			#Continue to read file in binary, send to server
			while True:
				
				fileContents = f.read(bufferSize)
				if not fileContents:
					break
				else:
					fileContentsEnc = encryptData(cipherBlock, fileContents)
					clientSocket.send(fileContentsEnc)
		f.close()
	
	return None


###################################################################################################
#RSA Encryption/Decryption Functions
###################################################################################################

def fileHandler(fname):
	keyFile = open(fname, "rb")
	content = keyFile.read()
	return content
	
def getPubKey():
	pubKey = fileHandler("server_public.pem")
	return pubKey
	
def encryptWithPublic(message):
	pubkey = RSA.import_key(getPubKey())
	cipher_rsa_en = PKCS1_OAEP.new(pubkey)
	enc_dat = cipher_rsa_en.encrypt(message.encode('ascii'))
	return enc_dat

######################################################
def symKeyToFile(SymKey):
	keyFile = open("server_symKey.pem", "wb")
	keyFile.write(SymKey)
	keyFile.close()
	
	
#before 
def decryptSymKey(clientName, key):
	private_key = fileHandler(clientName + "_private.pem")
	private_key = RSA.import_key(private_key)
	cipher_rsa = PKCS1_OAEP.new(private_key)
	session_key = cipher_rsa.decrypt(key)
	
	return session_key



###################################################################################################
#AES Encryption/Decryption Functions
###################################################################################################


"""
	This function, encryptMsg(), encodes,
	pads (up to 256 bits), encrypts and
	returns a message.
	Parameters: cipherBlock - AES cipher object, msg - str
	Returns: cipherText - 
"""
def encryptMsg(cipherBlock, msg):
	cipherText = cipherBlock.encrypt(pad(msg.encode('ascii'),32)) #Note 32: key len/divisible by is 256
	#print('Cipher text/encrypted message: ', cipherText)
	return cipherText

"""
	This function, encryptMsg(), encodes,
	pads (up to 256 bits), encrypts and
	returns a message.
	Parameters: cipherBlock - AES cipher object, msg - str
	Returns: cipherText - 
"""
def encryptData(cipherBlock, data):
	cipherText = cipherBlock.encrypt(pad(data, 32)) #Note 32: key len/divisible by is 256
	#print('Cipher text/encrypted message: ', cipherText)
	return cipherText



"""
	This function, decryption(), decrypts and
	decodes a message by removing padding.
	Parameters: cipherBlock - cipher AES, encryptMsg - 
	Returns: decodedMsg - str
"""
def decryption(cipherBlock, encryptMsg):
	pMsg = decryptMsg(cipherBlock, encryptMsg)
	decodedMsg = removePadding(pMsg)
	return decodedMsg

"""
	This function, decryptMsg(), decrypts a message.
	Parameters: cipherBlock - AES cipher object, encryptMsg - 
	Returns: paddedMsg - ascii 
"""
def decryptMsg(cipherBlock, encryptMsg):
	paddedMsg = cipherBlock.decrypt(encryptMsg)
	return paddedMsg

"""
	This function, removePadding(), removes padding
	around a decrypted message.
	Parameters: paddedMsg - ascii
	Returns: message - str
"""
def removePadding(paddedMsg):
	encodedMsg = unpad(paddedMsg, 32) #Note 32: key len/divisible by is 256
	return encodedMsg.decode('ascii')



###################################################################################################
#Message Exchange Function
###################################################################################################

"""
	This function, msgExchanger(), receives the server's
	message, decrypts their message and places it into
	a prompt for the user. Then user's response is 
	encrypted and sent to the server.
	Parameters: cipherBlock - AES cipher object, clientSocket - socket, promptAddOn - str
	Returns: clientResponse - str
"""
def msgExhanger(cipherBlock, clientSocket, promptAddOn):
	#Receive message from server & decrypt it
	message = clientSocket.recv(2048)
	originalMsg = decryption(cipherBlock, message)
	
	#Respond to message prompt, encrypt response & send it back to server
	response = input(originalMsg + promptAddOn)
	responseEncrypted = encryptMsg(cipherBlock, response)
	clientSocket.send(responseEncrypted)
	
	return response
	
#---------
client()





