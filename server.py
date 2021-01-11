"""
Uses Fork to Connect to Multiple Clients
Uses AES (ECB Mode) for Encryption/Decryption

Reference: Computer Networking: A Top Down Approach Chapter 2
Pycryptodome docs: https://pycryptodome.readthedocs.io/en/latest/

Author: Sharon Lee
"""
from PIL import Image
import io
import key_generator
import socket
import sys
import os
import os.path
from os import path
import shutil
import json
import datetime
from datetime import date 
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

"""
	This function, server() establishes an encryption environment &
	the sockets used to communicate with connecting clients. 
	Uses fork to connect with multiple clients while a
	server connection is active.
	Parameters: None
	Returns: None
"""
def server():

	#Server port
	serverPort = 13000
	
	#Server sockets: uses IPv4 and TCP protocols
	try:
		serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	except socket.error as e:
		print('Error in creating server socket: ', e)
		sys.exit(1)
	
	#Associate port# 13000 to server socket
	try:
		serverSocket.bind(('', serverPort))
	except socket.error as e:
		print('Error in binding server socket: ', e)
		sys.exit(1)
	
	print('The server is ready to accept connections.')
	
	#Server is only available to connect to one client at a time in its queue
	serverSocket.listen(5)
	
	while 1:

		try:

			#Server accepts ONE client connection
			connectionSocket, addr = serverSocket.accept()
			pid = os.fork() #Process ID 
			
			#If it's a client-child process
			if pid == 0:
				#Close duplicate reference from child 
				serverSocket.close() #ie. server still references socket server
				
				##############################################################
				#Communication Exchange
				
				#Server sends welcome to client & receives their name
				welcome  = 'Welcome to the Image Repository\n\nPlease enter your login. '
				connectionSocket.send(welcome.encode('ascii'))
				loginInfoEnc = connectionSocket.recv(2048)
				loginInfoDec = decryptionPubic(loginInfoEnc)

				try:
					clientKeysInfo = verifyClient(loginInfoDec)
					[sessionKey, encSymmKey, clientName] = clientKeysInfo
				except:
					sessionKey = False
				
				
				if (sessionKey == False):
					verificationMessage = "\nLogin failed.\nPlease try again later."
					connectionSocket.send(verificationMessage.encode('ascii'))
					connectionSocket.close() 
					return

				connectionSocket.send(encSymmKey)
				clientConfirmation = connectionSocket.recv(2048)
				cipherBlock = setUpAES(sessionKey)
				clientConfirmedDec = decryptionInit(cipherBlock, clientConfirmation)
				
				
				mainMenu = "\nMAIN MENU\nPlease choose from below options:\n1) Upload Image(s)\n2) Exit Repository\n"
				mainMenuEnc = encryption(cipherBlock, mainMenu)
				
				uploadMenu = "\nUPLOAD MENU\n1) Upload an image\n2) Upload many images\n3) Main Menu\n4) Exit Repository\n"
				uploadMenuEnc = encryption(cipherBlock, uploadMenu)
				
				connectionSocket.send(mainMenuEnc)
				
				clientChoice = connectionSocket.recv(2048)
				clientChoiceDec = decryptionUser(clientName, cipherBlock, clientChoice) 
				
				while (clientChoiceDec != "2"):
		
					if (clientChoiceDec == "1"):
						connectionSocket.send(uploadMenuEnc)
						clientUploadChoice = connectionSocket.recv(2048)
						clientUploadChoiceDec = decryptionUser(clientName, cipherBlock, clientUploadChoice)
						
						while (clientUploadChoiceDec != "3"):
							if (clientUploadChoiceDec == "1"):
								
								fnRequest = "Enter filename: "
								fileInfo = fileInfoReceiver(clientName, cipherBlock, connectionSocket, fnRequest)
							elif (clientUploadChoiceDec == "4"):
								connectionSocket.close() 
								return 
								
							else:
								clientUploadChoice = connectionSocket.recv(2048)
								clientUploadChoiceDec = decryptionUser(clientName, cipherBlock, clientUploadChoice)
								
							clientUploadChoice = connectionSocket.recv(2048)
							clientUploadChoiceDec = decryptionUser(clientName, cipherBlock, clientUploadChoice)
							
					else:
						clientChoice = connectionSocket.recv(2048)
						clientChoiceDec = decryptionUser(clientName, cipherBlock, clientChoice)
					
					clientChoice = connectionSocket.recv(2048)
					clientChoiceDec = decryptionUser(clientName, cipherBlock, clientChoice)
					
				connectionSocket.close() 
				return
				

			#Else, server/parent closes duplicate reference to connection socket
			connectionSocket.close() #ie. client-child process still has ref to conn socket
		
		except socket.error as e:
			print('Error occurred: ', e)
			serverSocket.close()
			sys.exit(1)
			
		except Exception as inst:
			print('Error with', inst)


#=========================================================================================================#
# LOGIN - FUNCTIONS
#=========================================================================================================#

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



def verifyClient(loginInfo):
	username = loginInfo.split('\n')[0]
	password = loginInfo.split('\n')[1]

	with open('user_pass.json') as file:
		data = json.load(file)
	if username in data and data[username] == password:
		sessionKey, encSymmKey = encryptSymKey(username)
		clientKeysInfo = [sessionKey, encSymmKey, username]
		return clientKeysInfo
	else:
		return False


#=========================================================================================================#
# FILE - FUNCTIONS
#=========================================================================================================#
"""
	This function, fileInfoReceiver(), sends & receives
	file info from the client.
	Parameters: connSocket - socket, msg - str
	Returns: fileInfo - list
	
"""
def fileInfoReceiver(user, cipherBlock, connSocket, msg):
	#Ask client for file name, get file info
	data = msgExchanger(msg, cipherBlock, connSocket)
	
	#Extract filename & size
	div = data.find('\n'); fname = data[:div]; fsize = data[div+1:]
	
	#Create confirmation of request
	ok = 'OK ' + fsize
	
	if fname.endswith('.png') == True or fname.endswith('.jpeg') or fname.endswith('.jpg') or fname.endswith('.gif'):
	
		#Receive & upload receiving file, obtain time of upload
		uploadTime = fileContentsReceiver(cipherBlock, connSocket, fname, fsize, ok)
	
		#Insert file into associated client folder
		path = os.getcwd() 
		filePath = path + "/" + fname
		newFilePath = path + "/" + user + "/" + fname
		os.rename(filePath, newFilePath)
	
		#Collect file info to update metadata file
		fileInfo = [fname, fsize, uploadTime]
		return fileInfo
	
	fileInfo = [fname, fsize, "Not Uploaded."]
	return fileInfo


"""
	This function, fileContentsReceiver() handles
	file content transfer between server and
	client programs.
	Parameters: connSocket - socket, fname - str, fsize - str, request - str
	Returns: dateTime - datetime
	
"""
def fileContentsReceiver(cipherBlock, connSocket, fname, fsize, request):
	#Send OK+size confirmation to client, initiate file exchange
	requestEnc = encryption(cipherBlock, request)
	connSocket.send(requestEnc)

	#Size for receiving file portions
	bufferSize = 2048
	
	#Create a new file in server directory
	newFname = fname 
	newFile = open(newFname, "w"); newFile.close()
	
	#Receive first file BATCH as response to OK message
	fileContents = connSocket.recv(bufferSize)
	#fileContentsDec = decryptData(cipherBlock, fileContents)
	fileWrite(newFname, fileContents)
	
	#Continue to receive remaining file contents
	while True:
		
		fileContents = connSocket.recv(bufferSize)
		#decrypt fileContents
		#fileContentsDec = decryptData(cipherBlock, fileContents)
		
		#Track size of received batch for handling
		contentSize = len(fileContents)

		if contentSize == bufferSize:
			fileAppend(newFname, fileContents)
				
		#Handle the last batch of the file  
		if contentSize < bufferSize:
			fileAppend(newFname, fileContents)
			break
			
	#Get date/time when entire file received/written in server	
	dateTime = datetime.now()
	return dateTime

"""
	This function, fileWrite() writes data
	to a file.
	Parameters: newFname - str, dataReceived - str
	Returns: None
	
"""
def fileWrite(newFname, dataReceived):
	with open(newFname, "wb") as nf:
		nf.write(dataReceived)
	nf.close()
	return None
	
"""
	This function, fileAppend() appends data
	to a file.
	Parameters: newFname - str, dataReceived - str
	Returns: None
	
"""
def fileAppend(newFname, dataReceived):
	with open(newFname, "ab") as nf:
		nf.write(dataReceived)
	nf.close()
	return None



###################################################################################################
#Encryption/Decryption functions
###################################################################################################

def fileHandler(fname):
	keyFile = open(fname, "rb")
	content = keyFile.read()
	return content

def getPubKey():
	pubKey = fileHandler("server_public.pem")
	return pubKey

def getPrivKey():
	privKey = fileHandler("server_private.pem")
	return privKey

def decryptionPubic(encryptedMessage):
	privkey = RSA.import_key(getPrivKey())
	cipher_rsa_dec = PKCS1_OAEP.new(privkey)
	dec_data = cipher_rsa_dec.decrypt(encryptedMessage)
	return dec_data.decode('ascii')


#########################################################
#use client public RSA key to encrypt generated AES key
#Reference: https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-rsa

def generateSessionKey():
	keyLen = 256
	session_key = get_random_bytes(int(keyLen/8))
	return session_key

def getClientPubKey(clientName):
	path = os.getcwd()
	newPath = path + "/" + clientName + "/"
	
	try:
		shutil.copyfile(newPath + "/" + clientName + "_public.pem", path + "/" + clientName + "_public.pem")
	except:
		print("File cannot be copied or doesn't exist.")
	
	pubClientKey = fileHandler(clientName + "_public.pem")
	
	
	try:
		os.remove(clientName + "_public.pem")
	except:
		print("File cannot be removed or doesn't exist.")
	
	
	return pubClientKey


def encryptionPubicClient(session_key, clientName):
	pubkey = RSA.import_key(getClientPubKey(clientName))
	cipher_rsa_en = PKCS1_OAEP.new(pubkey)
	enc_session_key = cipher_rsa_en.encrypt(session_key)
	return enc_session_key


def encryptSymKey(clientName):
	cipher = generateSessionKey()
	encSymKey = encryptionPubicClient(cipher, clientName)
	return (cipher, encSymKey)






"""
	This function, encryption(), encodes,
	pads (up to 256 bits), encrypts and
	returns a message.
	Parameters: cipherBlock - AES cipher object, msg - str
	Returns: cipherText - 
"""
def encryption(cipherBlock, msg):
	cipherText = cipherBlock.encrypt(pad(msg.encode('ascii'),32)) #Note 32: key len/divisible by is 256
	return cipherText

"""
	This function, decryptionInit(), prints messages
	before and after decryption. Used initially to 
	determine the client's user name.
	Parameters: cipherBlock - cipher AES, encryptMsg - 
	Returns: decodedMsg - str
"""
def decryptionInit(cipherBlock, encryptMsg):
	print('Encrypted message received: ', encryptMsg)
	pMsg       = decryptMsg(cipherBlock, encryptMsg)
	decodedMsg = removePadding(pMsg)
	print('Decrypted message received: ', decodedMsg)
	return decodedMsg

"""
	This function, decryptionUser(), prints messages
	before and after decryption. Used once 
	a client is identified.
	Parameters: user - str, cipherBlock - cipher AES, encryptMsg - 
	Returns: decodedMsg - str
"""
def decryptionUser(user, cipherBlock, encryptMsg):
	print('Encrypted message from', user + ':', encryptMsg)
	pMsg       = decryptMsg(cipherBlock, encryptMsg)
	decodedMsg = removePadding(pMsg)
	print('Decrypted message from', user + ':', decodedMsg)
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
	message    = encodedMsg.decode('ascii')
	return message



def decryptData(cipherBlock, encryptedData):
	data = unpad(cipherBlock.decrypt(encryptedData), 32)
	data = io.BytesIO(base64.b64decode(data))
	return data
'''
	paddedData = cipherBlock.decrypt(encryptedData)
	print(paddedData, '\n\n')
	data = unpad(paddedData, 32) #Note 32: key len/divisible by is 256
	print(data)
	return data
	'''
	
###################################################################################################
#Message Exchange Functions
###################################################################################################

"""
	This function, promptSender(), sends & receives
	messages to/from a client.
	Parameters: connSocket - socket, msg - str
	Returns: receipt - str
	
"""
def promptSender(connSocket, msg):
	#Server sends a message to the client
	connSocket.send(msg.encode('ascii'))
	
	#Server receives a response from client
	receipt = connSocket.recv(2048).decode('ascii')
	
	return receipt


"""
	This function, msgExchanger(), encrypts a message
	and sends it to a client. Then it receives the client's
	response, decrypts their message and returns it.
	This is used when a client identity is unknown.
	Parameters: message - str, cipherBlock - AES cipher object, connectionSocket - socket
	Returns: clientResponse - str
"""
def msgExchanger(message, cipherBlock, connectionSocket):
	#Server encrypts and sends message to a client
	messageEncrypted = encryption(cipherBlock, message)
	connectionSocket.send(messageEncrypted)
	
	#Receive client's response and decrypts it
	clientResponseEncrypted = connectionSocket.recv(2048)
	clientResponse = decryptionInit(cipherBlock, clientResponseEncrypted)
	
	return clientResponse

"""
	This function, msgExchangerUser(), encrypts a message
	and sends it to a client. Then it receives the client's
	response, decrypts their message and returns it.
	This function is used when a client identity is KNOWN.
	Parameters: user - str, message - str, cipherBlock - AES cipher object, connectionSocket - socket
	Returns: clientResponse - str
"""
def msgExchangerUser(user, message, cipherBlock, connectionSocket):
	#Server encrypts and sends message to a KNOWN client
	messageEncrypted = encryption(cipherBlock, message)
	connectionSocket.send(messageEncrypted)
	
	#Receive client's response and decrypts it
	clientResponseEncrypted = connectionSocket.recv(2048)
	clientResponse = decryptionUser(user, cipherBlock, clientResponseEncrypted)
	
	return clientResponse



#---------
server()




