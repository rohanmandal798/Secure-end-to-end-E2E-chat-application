# Secure E2E Chat Application

This is a secure end-to-end (E2E) encrypted chat application using Python, sockets, and cryptography.

## Features
- Encrypted messages using Fernet encryption
- SSL/TLS for secure client-server communication
- GUI for better user experience

## Installation
1. Clone the repository:

   git clone https://github.com/your-username/secure-chat-app.git

## Install dependencies
pip install -r requirements.txt

## Run the Server
python server.py

## Run the Client
- python client.py
- python client1.py

## Option (You can geneate you own cert)
1. openssl genpkey -algorithm RSA -out private_key_pkcs1.pem -pkeyopt rsa_keygen_bits:2048
2. openssl rsa -pubout -in private_key_pkcs1.pem -out server_public.pem


