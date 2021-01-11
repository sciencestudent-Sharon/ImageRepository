
import json
import os
import shutil
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

def pubKeyGenerator(key):
	public_key = key.publickey().export_key()
	return public_key

def privKeyGenerator(key):
	private_key = key.export_key()
	return private_key
	
def pubkeyToFile(key, fname):
	newFile = open(fname, "wb")
	pubKey = pubKeyGenerator(key)
	newFile.write(pubKey)
	newFile.close()
	return pubKey
	

def privkeyToFile(key, fname):
	newFile = open(fname, "wb")
	privKey = privKeyGenerator(key)
	newFile.write(privKey)
	newFile.close()
	return privKey

def checkKeyFile(fname):
	f = open(fname, "rb")
	content = f.read()
	return content

def collectClients():
	#Collect existing users from stored user_pass.json file
	clientList = []
	with open('user_pass.json') as file:
		data = json.load(file)
	for username in data:
		clientList.append(username)
	
	return clientList

def showKeys():
	
	clientList = collectClients()
	
	#Generate public & private keys, place them into files for future use	
	key = RSA.generate(2048)
	pubkeyToFile(key, "server_public.pem")
	privkeyToFile(key, "server_private.pem")
	
	#Get current working directory path
	path = os.getcwd()
	
	#For each user in client list, create folder
	for client in clientList:
		newPath = path + "/" + client + "/"
		fnPubKey = "" + client + "_public.pem"
		fnPrivKey = "" + client + "_private.pem"
		pubkeyToFile(key, fnPubKey)
		privkeyToFile(key, fnPrivKey)
		
		try:
			os.mkdir(newPath)
		except OSError:
			#print("Creating directory failed: ", OSError)
			pass
		else:
			pass
		
		os.rename(path + "/" + fnPrivKey, newPath + "/" + fnPrivKey)
		os.rename(path + "/" + fnPubKey, newPath + "/" + fnPubKey)
		
		#shutil.copyfile(path + "/server_public.pem", newPath + "/server_public.pem")
		
		#for testing: copy client1 & client2 keys to Client folder
		if client == "client1" or client == "client2":
			shutil.copyfile(path + "/server_public.pem", path + "/Client" + "/server_public.pem")
			shutil.copyfile(newPath + "/" + fnPrivKey, path + "/Client/" + fnPrivKey)	




		
#------
showKeys()









