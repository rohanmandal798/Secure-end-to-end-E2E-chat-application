import unittest
import socket
import threading
import time

# Server setup for testing
PORT = 5000
SERVER = "127.0.0.1"
ADDRESS = (SERVER, PORT)
FORMAT = "utf-8"

# Function to start the server for testing
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDRESS)
    server.listen(5)
    print(f"Server listening on {SERVER}:{PORT}")

    while True:
        client_socket, client_address = server.accept()
        print(f"Connected with {client_address}")
        client_socket.close()
        break

    server.close()

# Client setup for testing
def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect(ADDRESS)
        print(f"Connected to server at {SERVER}:{PORT}")
        client.close()
        return True
    except ConnectionRefusedError:
        print(f"Connection failed to {SERVER}:{PORT}")
        return False

# Unit test class to test connection
class TestConnection(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """ Start server in a separate thread before running tests """
        server_thread = threading.Thread(target=start_server)
        server_thread.daemon = True  # Ensure server stops when main program ends
        server_thread.start()
        time.sleep(1)  # Wait a bit to ensure the server starts up

    def test_connection(self):
        """ Test if the client can connect to the server """
        result = start_client()
        self.assertTrue(result, "Client should be able to connect to the server.")
    
if __name__ == "__main__":
    unittest.main()
