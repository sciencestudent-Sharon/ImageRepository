#----------------------------------
# Name:
# Program: Client.py
# CMPT361 Fall Project



import socket
import sys
import socket
import os 
import json
import time

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

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
		
		clientInfo = ""
		username = input("Enter your username: ")
		password = input("Enter your password: ")
		clientInfo += username + '\n' + password

		clientInfo = encryptWithPublic(clientInfo)

		#here, encryption with server public key on clientinfo
		#send client info
		clientSocket.send(clientInfo)
		
		
		message = clientSocket.recv(2048)
		#print(message)
		 #<----- REMOVE
		new_message = ""
		
		try:
			new_message = message.decode('ascii')
		except:
			pass
		
		if new_message == "Invalid username or password":
			print("Invalid username or password\nTerminating.")
			clientSocket.close()
			
		else:
			#decrypt message here
			#store key here
			#encrypt symmetric key here
			
			key = decryptSymKey(username, message)
			fileSymKey(username, key)
			confirm = "OK"
			clientSocket.send(confirm.encode('ascii'))
		
		
		#menu = clientSocket.recv(2048).decode('ascii')
		#decrypt menu message here
		#choice = input(menu)	
			
		#encrypt choice here
		#clientSocket.send(choice.encode('ascii'))	
			
		#userNameRequest = clientSocket.recv(2048).decode('ascii')
		#reply = input(userNameRequest)

		
		received = clientSocket.recv(2048).decode('ascii')

		choice = "0"
		while (received != "4"):
	
			if received == "Send the email":
				choice = sendEmail(clientSocket, username)
				clientSocket.send(choice.encode('ascii'))

			elif received == "2":
				choice = viewInbox(clientSocket, username)
				clientSocket.send(choice.encode('ascii'))

			elif received == "3":
				choice = viewEmail(clientSocket, username)
				clientSocket.send(choice.encode('ascii'))

			else:
				choice = input(received)
				clientSocket.send(choice.encode('ascii'))
				
			
			#encrypt choice here
			received = clientSocket.recv(2048).decode('ascii')
			
			
		
		serverTerminate = clientSocket.recv(2048).decode('ascii')
		#decrypt serverTerminate here using sym_key
		print("The connection is terminated with the server.")
		clientSocket.close() 
		
	except socket.error as e:
		print('Error occurred: ', e)
		clientSocket.close()
		sys.exit(1)



###########################################################
#Functions
###########################################################

def sendEmail(clientSocket, username):
	choice = username
	clientSocket.send(choice.encode('ascii'))
	message = clientSocket.recv(2048).decode('ascii')
	while message != "TERMINATE":
		choice = input(message)
		clientSocket.send(choice.encode('ascii'))
		message = clientSocket.recv(2048).decode('ascii')
		
	print("The message is sent to the server")
	print()
	return "0"

def viewInbox(clientSocket, username):
	print("Index\tFrom\tDateTime\t\tTitle")
	choice = username
	clientSocket.send(choice.encode('ascii'))
	message = clientSocket.recv(2048).decode('ascii')
	while message != "TERMINATE":
		print(message)
		message = clientSocket.recv(2048).decode('ascii')
	print()
	return "0"

def viewEmail(clientSocket, username):
	choice = username
	clientSocket.send(choice.encode('ascii'))
	message = clientSocket.recv(2048).decode('ascii')
	choice = input(message)
	clientSocket.send(choice.encode('ascii'))
	print()
	message = clientSocket.recv(2048).decode('ascii')
	while message != "TERMINATE":
		print(message)
		message = clientSocket.recv(2048).decode('ascii')
	print()
	return "0"

###########################################################
#encryption/decryption Functions
###########################################################
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
def fileSymKey(clientName, SymKey):
	keyFile = open(clientName + "_symKey.pem", "wb")
	keyFile.write(SymKey)
	keyFile.close()
	
	
#before 
def decryptSymKey(clientName, key):
	private_key = fileHandler(clientName + "_private.pem")
	private_key = RSA.import_key(private_key)
	cipher_rsa = PKCS1_OAEP.new(private_key)
	session_key = cipher_rsa.decrypt(key)
	
	return session_key



#------
client()
