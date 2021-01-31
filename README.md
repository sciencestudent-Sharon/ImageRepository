# Image Repository

**Version 1.0.0**

Description: Image repository using socket programming – where different multiple clients can upload an image to their account folder following authentication using login verification as well as AES & RSA encryption and decryption methods.

Motivation: To supplement a job application. To combine concepts from a Fall 2020 course that I really enjoyed and wanted to practice more in.

References: https://pycryptodome.readthedocs.io/en/latest/src/introduction.html

### Features
- Image of any size can be uploaded.
- Images are uploaded to separate accounts.
- Server allows connection with multiple clients & tracks inputs from unique clients.

### Caveats/Limitations
- While messages between server and client are encrypted, images were not able to be encrypted & decrypted in this set-up. 
- AES Encryption is completed in ECB_Mode (not recommended due to security weaknesses).

## Usage

1. python3 server.py
2. python3 client.py

### server.py & Directory
Directory containing server.py represents the directory system existing on the server side.
Of note, this directory contains key_generator.py and user_pass.json files.
- key_generator.py: contains methods to generates RSA keys. 
- user_pass.json: contains 5 paired client username and passwords. 

Running server.py generates: 
> The server is ready to accept connections.
- Client folders for all clients present in the user_pass.json file.
- All associated client private & public RSA keys & moves them into their client's folders.
- Server private & public RSA keys.
- Copies and moves server public RSA key to Client folder.
- Copies and moves client1 and client2 private RSA keys for testing.

### Client
Client folder contains client.py and represents any connecting client.
This folder also contains sample images to upload.
Running client.py generates:

1. A prompt for server IP/name
> Enter the server IP or name: *localhost*

2. Prompts for username & password 
> Welcome to the Image Repository
> Please enter your login. 
> Username: *client1*
> Password: *password1* 

3. Main Menu 
> MAIN MENU
> Please choose from below options:
> 1) Upload Image
> 2) Exit Repository

4. Upload Menu
> UPLOAD MENU
> 1) Upload an image
> 2) Main Menu
> 3) Exit Repository

5. Upload an image 
> Enter filename: *cat.png*
> OK 663451
> Upload process completed.


## License & Copyright
Licensed under the [GNU General Public License v3.0](LICENSE) (C) Sharon Lee
