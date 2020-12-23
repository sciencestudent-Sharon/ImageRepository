#----------------------------------
# Name:
# Program: Server.py
# CMPT361 Fall Project


import socket
import sys
import os 
import random
import json
import time

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

def server():
	SAVE_PATH = ("/home/sharon/Documents/")
	#SAVE_PATH = ("/home/kali/Desktop/")

	#Server port
	serverPort = 13000
	MENU = "Select the operation:\n\t1) Create and send an email\n\t2) Display the inbox list\n\t3) Display the email contents\n\t4) Terminate the connection\nChoice: "

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
				clientInfo = connectionSocket.recv(2048)
				
				#decrypt client info
				decClientInfo = decryptionPubic(clientInfo)
				
				#check if client info valid
				info_split = decClientInfo.split('\n')
				userName = info_split[0]
				userPassword = info_split[1]				
				valid = checkClient(userName,userPassword) #validity variable
				
				if valid == True:
					#generate symm key here
					#send symm key to client here
					symmKey = encryptSymKey(userName)
					connectionSocket.send(symmKey)
					
					print("Connection Accepted and Symmetric Key Generated for client:")

				else:
					invalidMessage = "Invalid username or password"
					
					connectionSocket.send(invalidMessage.encode('ascii'))
					print("The received client information: " + "is invalid (Connection Terminated).")
					connectionSocket.close()
					return

				
				#receive client OK
				clientConfirm = connectionSocket.recv(2048).decode('ascii')
				print(clientConfirm)
				#decrypt confirmation here
				

				#connectionSocket.send(menu.encode('ascii'))
				
				
				#userChoice = connectionSocket.recv(2048).decode('ascii')
				userChoice = "0"
				
				#decrypt userchoice here

				
				connectionSocket.send(MENU.encode('ascii'))

				userChoice = connectionSocket.recv(2048).decode('ascii')

				while (userChoice != "4"):
				
					if userChoice == "1":
						connectionSocket.send("Send the email".encode('ascii'))
						receiveEmail(connectionSocket, SAVE_PATH)
						

					elif userChoice == "2":
						connectionSocket.send("2".encode('ascii'))
						viewInbox(connectionSocket, SAVE_PATH)
						
					elif userChoice == "3":
						connectionSocket.send("3".encode('ascii'))
						viewEmail(connectionSocket, SAVE_PATH)
						
					else:
						connectionSocket.send(MENU.encode('ascii'))
						
					userChoice = connectionSocket.recv(2048).decode('ascii')
				
				
				terminateMessage = "4"
				#encrypt terminateMessage here 
				connectionSocket.send(terminateMessage.encode('ascii'))
				print("Connection terminated")
				connectionSocket.close()

				##############################################################
				return
				
			#Else, server/parent closes duplicate reference to connection socket
			connectionSocket.close() #ie. client-child process still has ref to conn socket
		
		except socket.error as e:
			print('Error occurred: ', e)
			serverSocket.close()
			sys.exit(1)
	
		except Exception as inst:
			print("Error with", inst)

		#except:
			#print('Goodbye')
			#serverSocket.close()
			#sys.exit(0)



###########################################################
#menu Functions
###########################################################

def receiveEmail(connectionSocket, SAVE_PATH):
	emailFrom = connectionSocket.recv(2048).decode('ascii')
	connectionSocket.send("Send to: ".encode('ascii'))
	emailTo = connectionSocket.recv(2048).decode('ascii')
	connectionSocket.send("Title: ".encode('ascii'))
	emailTitle = connectionSocket.recv(2048).decode('ascii')
	connectionSocket.send("Message: ".encode('ascii'))
	emailMessage = connectionSocket.recv(2048).decode('ascii')
	emailLength = str(len(emailMessage))
	emailTime = "12:00"
	email = "From: " + emailFrom + "\nTo: " + emailTo + "\nTime and Date: " + emailTime + "\nTitle: " + emailTitle + "\nContent length: " + emailLength + "\nContent: " + emailMessage

	connectionSocket.send("TERMINATE".encode('ascii'))

	emailToList = emailTo.split(";")

	for e in emailToList :

		path = SAVE_PATH + e + "/"
		name = os.path.join(path, emailTitle + ".txt")
		file1 = open(name, "w")
		file1.write(email)
		file1.close()

	print("An email from " + emailFrom + " is sent to " + emailTo + ", has a content length " + emailLength + ".")

	
def viewInbox(connectionSocket, SAVE_PATH):
	username = connectionSocket.recv(2048).decode('ascii')
	path = SAVE_PATH + username + "/"
	clientMail = os.listdir(path)
	index = 1
	for mail in clientMail:
		with open(path + mail, 'r') as file1:
			for line in file1:
				if line.split(":")[0] == "From":
					Sender = line.split(": ")[1].rstrip()
				if line.split(":")[0] == "Time and Date":
					timeSent = line.split(": ")[1].rstrip()
				if line.split(":")[0] == "Title":
					title = line.split(": ")[1].rstrip()
					
		mailIndex = str(index)
		email = mailIndex + "\t" + Sender + "\t" + timeSent + "\t" + title
		connectionSocket.send(email.encode('ascii'))
		time.sleep(0.0001)
		index += 1
		
	connectionSocket.send("TERMINATE".encode('ascii'))

def viewEmail(connectionSocket, SAVE_PATH):
	username = connectionSocket.recv(2048).decode('ascii')
	path = SAVE_PATH + username + "/"
	clientMail = os.listdir(path)
	connectionSocket.send("Enter the email index you wish to view: ".encode('ascii'))
	index = connectionSocket.recv(2048).decode('ascii')
	file1 = open(path + clientMail[int(index) -1], 'r')
	for line in file1:
		connectionSocket.send(line.rstrip().encode('ascii'))
		time.sleep(0.0001)
	connectionSocket.send("TERMINATE".encode('ascii'))
	
	
	
###########################################################
#encryption/decryption Functions
###########################################################
def checkClient(name, password):
	with open('user_pass.json') as file:
		data = json.load(file)
	if name in data and data[name] == password:
		return True
	else:
		return False
		
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
	pubClientKey = fileHandler(clientName + "_public.pem")
	return pubClientKey


def encryptionPubicClient(clientName, cipher):
	pubkey = RSA.import_key(getClientPubKey(clientName))
	cipher_rsa_en = PKCS1_OAEP.new(pubkey)
	session_key = generateSessionKey()
	enc_session_key = cipher_rsa_en.encrypt(session_key)
	return enc_session_key


def encryptSymKey(clientName):
	cipher = generateSessionKey()
	encSymKey = encryptionPubicClient(clientName, cipher)
	return encSymKey






#---------
server()

