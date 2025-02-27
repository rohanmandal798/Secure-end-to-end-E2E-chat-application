import socket
import threading
import ssl
from cryptography.fernet import Fernet
from tkinter import *
from tkinter import messagebox
import base64
import hashlib

# Server details
PORT = 5000
SERVER = "127.0.0.1"  # Localhost to connect to the local server
ADDRESS = (SERVER, PORT)
FORMAT = "utf-8"

# Create a new socket and connect to the server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Create an SSL context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname = False  # For testing, do not verify the server's hostname
context.verify_mode = ssl.CERT_NONE  # For testing, do not verify the server's certificate

# Wrap the socket with SSL
client = context.wrap_socket(client)

client.connect(ADDRESS)

# Receive the encryption key from the server
key = client.recv(1024)
cipher_suite = Fernet(key)

# Base64 encryption and decryption functions
def encrypt_base64(message, password):
    if not password:
        raise ValueError("Password cannot be empty")
    if not message:
        raise ValueError("Message cannot be empty")

    # Create a hashed password
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    # Encrypt message by appending the hashed password
    encrypted_message = base64.b64encode((message + hashed_password).encode("ascii")).decode("ascii")
    
    return encrypted_message

def decrypt_base64(encrypted_message, password):
    if not password:
        raise ValueError("Password cannot be empty")
    if not encrypted_message:
        raise ValueError("Encrypted message cannot be empty")

    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    try:
        # Decode the message
        decoded_message = base64.b64decode(encrypted_message).decode("ascii")

        # Check if the message ends with the hashed password
        if decoded_message.endswith(hashed_password):
            decrypted_message = decoded_message[:-len(hashed_password)]  # Remove the hashed password
        else:
            raise ValueError("Incorrect password, decryption failed.")
        
        return decrypted_message
    except Exception as e:
        raise ValueError(f"Error in decryption: {str(e)}")


# GUI class for the chat
class GUI:
    def __init__(self):
        self.Window = Tk()
        self.Window.withdraw()
        
        # Login window
        self.login = Toplevel()
        self.login.title("Login")
        self.login.resizable(width=False, height=False)
        self.login.configure(width=400, height=300)
        
        # Login prompt
        self.pls = Label(self.login, text="Please login to continue", justify=CENTER, font="Helvetica 14 bold")
        self.pls.place(relheight=0.15, relx=0.2, rely=0.07)
        
        # Name label and entry
        self.labelName = Label(self.login, text="Name: ", font="Helvetica 12")
        self.labelName.place(relheight=0.2, relx=0.1, rely=0.2)
        
        self.entryName = Entry(self.login, font="Helvetica 14")
        self.entryName.place(relwidth=0.4, relheight=0.12, relx=0.35, rely=0.2)
        self.entryName.focus()
        
        # Continue button
        self.go = Button(self.login, text="CONTINUE", font="Helvetica 14 bold", command=lambda: self.goAhead(self.entryName.get()))
        self.go.place(relx=0.4, rely=0.55)
        
        self.Window.mainloop()

    def goAhead(self, name):
        self.login.destroy()
        self.layout(name)
        
        # Start thread to receive messages
        rcv = threading.Thread(target=self.receive)
        rcv.start()

        # Open encryption/decryption popup on successful connection
        self.open_encryption_decryption_popup()

    def layout(self, name):
        self.name = name
        self.Window.deiconify()
        self.Window.title("CHATROOM")
        self.Window.resizable(width=False, height=False)
        self.Window.configure(width=470, height=550, bg="#17202A")
        
        # Header and message area
        self.labelHead = Label(self.Window, bg="#17202A", fg="#EAECEE", text=self.name, font="Helvetica 13 bold", pady=5)
        self.labelHead.place(relwidth=1)
        
        self.textCons = Text(self.Window, width=20, height=2, bg="#17202A", fg="#EAECEE", font="Helvetica 14", padx=5, pady=5)
        self.textCons.place(relheight=0.745, relwidth=1, rely=0.08)
        
        self.labelBottom = Label(self.Window, bg="#ABB2B9", height=80)
        self.labelBottom.place(relwidth=1, rely=0.825)
        
        self.entryMsg = Entry(self.labelBottom, bg="#2C3E50", fg="#EAECEE", font="Helvetica 13")
        self.entryMsg.place(relwidth=0.74, relheight=0.06, rely=0.008, relx=0.011)
        
        self.entryMsg.focus()
        
        # Send button
        self.buttonMsg = Button(self.labelBottom, text="Send", font="Helvetica 10 bold", width=20, bg="#ABB2B9", command=lambda: self.sendButton(self.entryMsg.get()))
        self.buttonMsg.place(relx=0.77, rely=0.008, relheight=0.06, relwidth=0.22)
        
        self.textCons.config(cursor="arrow")
        scrollbar = Scrollbar(self.textCons)
        scrollbar.place(relheight=1, relx=0.974)
        scrollbar.config(command=self.textCons.yview)
        
        self.textCons.config(state=DISABLED)

    def sendButton(self, msg):
        self.textCons.config(state=DISABLED)
        self.msg = msg
        self.entryMsg.delete(0, END)
        snd = threading.Thread(target=self.sendMessage)
        snd.start()

    def receive(self):
        while True:
            try:
                message = client.recv(1024).decode(FORMAT)
                if message == 'NAME':
                    client.send(self.name.encode(FORMAT))
                else:
                    self.textCons.config(state=NORMAL)
                    self.textCons.insert(END, message + "\n\n")
                    self.textCons.config(state=DISABLED)
                    self.textCons.see(END)
            except Exception as e:
                print(f"An error occurred: {e}")
                client.close()
                break

    def sendMessage(self):
        self.textCons.config(state=DISABLED)
        while True:
            message = f"{self.name}: {self.msg}"
            encrypted_message = cipher_suite.encrypt(message.encode(FORMAT))  # Encrypt message
            client.send(encrypted_message)  # Send encrypted message
            break

    def open_encryption_decryption_popup(self):
        # Create encryption/decryption popup window
        self.popup = Toplevel(self.Window)
        self.popup.title("Text Encryption/Decryption")
        self.popup.geometry("400x300")
        self.popup.configure(bg="#00bd56")
        
        self.encrypt_label = Label(self.popup, text="Encryption", bg="#00bd56", font="Helvetica 14", fg="white")
        self.encrypt_label.place(x=10, y=10)
        
        self.text_to_encrypt = Text(self.popup, height=4, width=40)
        self.text_to_encrypt.place(x=10, y=40)
        
        self.password_label = Label(self.popup, text="Password:", bg="#00bd56", font="Helvetica 10", fg="white")
        self.password_label.place(x=10, y=150)
        
        self.password_entry = Entry(self.popup, width=30)
        self.password_entry.place(x=70, y=150)
        
        self.encrypted_output = Text(self.popup, height=4, width=40)
        self.encrypted_output.place(x=10, y=180)
        
        self.encrypt_button = Button(self.popup, text="Encrypt", bg="#17202A", fg="white", command=self.encrypt_text)
        self.encrypt_button.place(x=10, y=240)
        
        self.decrypt_button = Button(self.popup, text="Decrypt", bg="#17202A", fg="white", command=self.decrypt_text)
        self.decrypt_button.place(x=100, y=240)

    def encrypt_text(self):
        message = self.text_to_encrypt.get(1.0, END).strip()
        password = self.password_entry.get()
        if message and password:
            encrypted_message = encrypt_base64(message, password)
            self.encrypted_output.delete(1.0, END)
            self.encrypted_output.insert(END, encrypted_message)
        else:
            messagebox.showerror("Error", "Message or Password cannot be empty")

    def decrypt_text(self):
        encrypted_message = self.encrypted_output.get(1.0, END).strip()
        password = self.password_entry.get()
        if encrypted_message and password:
            try:
                decrypted_message = decrypt_base64(encrypted_message, password)
                self.encrypted_output.delete(1.0, END)
                self.encrypted_output.insert(END, decrypted_message)
            except ValueError as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showerror("Error", "Encrypted Message or Password cannot be empty")


# Create and run the GUI
g = GUI()
