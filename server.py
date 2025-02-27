import socket
import threading
import ssl
from cryptography.fernet import Fernet

# Generate a Fernet key (You should save and share this key securely)
key = Fernet.generate_key()  
cipher_suite = Fernet(key)

# Choose a port
PORT = 5000
SERVER = "127.0.0.1"  # Localhost for local communication
ADDRESS = (SERVER, PORT)
FORMAT = "utf-8"

# List of connected clients
clients, names = [], []

# Create a new socket for the server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Create an SSL context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="server.crt", keyfile="server.key")

# Bind the server to the specified address
server.bind(ADDRESS)

# Function to start the chat
def startChat():
    print(f"Server is running on {SERVER}")
    server.listen()
    
    while True:
        # Accept new connections
        conn, addr = server.accept()
        conn = context.wrap_socket(conn, server_side=True)  # Wrap the connection with SSL
        conn.send(key)  # Send the encryption key to the client
        conn.send("NAME".encode(FORMAT))
        
        # Receive the client's name
        name = conn.recv(1024).decode(FORMAT)
        
        names.append(name)
        clients.append(conn)
        
        print(f"{name} has joined the chat!")
        
        broadcastMessage(f"{name} has joined the chat!".encode(FORMAT))
        
        conn.send('Connection successful!'.encode(FORMAT))
        
        # Start a new thread for handling messages from this client
        thread = threading.Thread(target=handle, args=(conn, addr))
        thread.start()
        
        print(f"Active connections: {threading.activeCount() - 1}")

# Function to handle incoming messages from clients
def handle(conn, addr):
    print(f"New connection: {addr}")
    connected = True
    
    while connected:
        try:
            # Receive the encrypted message
            message = conn.recv(1024)
            if message:
                # Decrypt the message using the Fernet key
                decrypted_message = cipher_suite.decrypt(message).decode(FORMAT)
                print(f"Received: {decrypted_message}")
                
                # Broadcast the decrypted message to all clients
                broadcastMessage(decrypted_message.encode(FORMAT))
        except Exception as e:
            print(f"Connection lost: {addr} - {e}")
            clients.remove(conn)
            conn.close()
            break

# Function to broadcast messages to all clients
def broadcastMessage(message):
    for client in clients:
        client.send(message)

# Start the chat server
startChat()
