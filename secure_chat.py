import os # Make sure to import 'os' at the top of your file
import tkinter as tk
from tkinter import simpledialog, scrolledtext, messagebox
import socket
import threading
import json
import base64

# Cryptography libraries
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa

# --- CryptoManager Class ---
# This class handles all cryptographic operations: key generation, encryption, etc.
class CryptoManager:
    def __init__(self):
        # RSA keys for signing Diffie-Hellman public keys
        self.rsa_private_key = None
        self.rsa_public_key = None
        self.peer_rsa_public_key = None

        # Diffie-Hellman parameters and keys for establishing the shared secret
        self.dh_parameters = None
        self.dh_private_key = None
        self.dh_public_key = None
        self.peer_dh_public_key = None

        # The final shared secret key for AES encryption
        self.shared_aes_key = None

        # Generate initial keys
        self.generate_rsa_keys()
        self.generate_dh_parameters()
        self.generate_dh_keys()

    def generate_rsa_keys(self):
        """Generates a new RSA public/private key pair for signing."""
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.rsa_public_key = self.rsa_private_key.public_key()
        print("RSA keys generated.")

   

    def generate_dh_parameters(self):
        """Generates Diffie-Hellman group parameters using the cryptography library."""
        self.dh_parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        print("DH parameters generated.")

    def generate_dh_keys(self):
        """Generates DH private and public keys from the parameters."""
        if self.dh_parameters:
            self.dh_private_key = self.dh_parameters.generate_private_key()
            self.dh_public_key = self.dh_private_key.public_key()
            print("DH keys generated.")

    def sign_data(self, data):
        """Signs data with the RSA private key."""
        return self.rsa_private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def verify_signature(self, signature, data):
        """Verifies a signature using the peer's RSA public key."""
        try:
            self.peer_rsa_public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False

    def generate_shared_secret(self):
        """Generates the shared secret using the peer's DH public key."""
        if self.dh_private_key and self.peer_dh_public_key:
            shared_key_material = self.dh_private_key.exchange(self.peer_dh_public_key)
            
            # Derive a 256-bit key using HKDF
            self.shared_aes_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32, # 32 bytes = 256 bits
                salt=None,
                info=b'handshake_data',
                backend=default_backend()
            ).derive(shared_key_material)
            print("Shared AES key derived successfully.")
        else:
            print("Cannot generate shared secret: DH keys missing.")

    # In CryptoManager class:
    def encrypt_message(self, plaintext):
        """Encrypts a message using AES-GCM with a random nonce."""
        if self.shared_aes_key:
            aesgcm = AESGCM(self.shared_aes_key)
            nonce = os.urandom(12)  # Generate a new 12-byte random nonce
            ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
            # Prepend the nonce to the ciphertext before encoding
            return base64.b64encode(nonce + ciphertext).decode('utf-8')
        return plaintext

    def decrypt_message(self, ciphertext_b64):
        """Decrypts a message using AES-GCM, extracting the nonce first."""
        if self.shared_aes_key:
            try:
                # Decode and separate the nonce from the actual ciphertext
                decoded_data = base64.b64decode(ciphertext_b64)
                nonce = decoded_data[:12]
                ciphertext = decoded_data[12:]
                
                aesgcm = AESGCM(self.shared_aes_key)
                plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                return plaintext.decode('utf-8')
            except Exception as e:
                print(f"Decryption failed: {e}")
                return "--- DECRYPTION FAILED ---"
        return ciphertext_b64
    # --- Helper functions for serialization ---
def serialize_key(key):
        """Serializes a public key to PEM format, encoded in base64."""
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(pem).decode('utf-8')

def deserialize_key(pem_b64):
        """Deserializes a base64 PEM public key (works for both RSA and DH)."""
        pem = base64.b64decode(pem_b64)
        return serialization.load_pem_public_key(pem, backend=default_backend())

# --- ChatApp Class ---
# This class manages the GUI and the main application logic.
class ChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat")
        self.crypto = CryptoManager()
        self.client_socket = None
        self.is_secure = False # Flag to track if the session is encrypted

        # --- GUI Setup ---
        self.chat_area = scrolledtext.ScrolledText(root, state='disabled', wrap=tk.WORD)
        self.chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.msg_entry = tk.Entry(root, width=70)
        self.msg_entry.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.X, expand=True)
        self.msg_entry.bind("<Return>", self.send_message)

        self.send_button = tk.Button(root, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.LEFT, padx=10, pady=10)
        
        self.secure_button = tk.Button(root, text="Go Secure", command=self.initiate_secure_session)
        self.secure_button.pack(side=tk.RIGHT, padx=10, pady=10)

        # Prompt for connection type
        self.setup_connection()

    def setup_connection(self):
        """Asks the user to be a server or client."""
        # Simple dialog to choose role
        role = simpledialog.askstring("Role", "Enter 'server' to wait for a connection, or 'client' to connect.", parent=self.root)
        if role and role.lower() == 'server':
            self.start_server()
        elif role and role.lower() == 'client':
            self.start_client()
        else:
            self.root.destroy()

    def start_server(self):
        """Initializes the server to listen for a client connection."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Get local IP to display
        host_ip = socket.gethostbyname(socket.gethostname())
        server_socket.bind((host_ip, 12345))
        server_socket.listen(1)
        self.display_message(f"--- Server started at {host_ip}:12345. Waiting for a client... ---")
        
        # Accept connections in a separate thread to not block the GUI
        threading.Thread(target=self.accept_connection, args=(server_socket,), daemon=True).start()

    def accept_connection(self, server_socket):
        """Thread target to accept a client connection."""
        try:
            self.client_socket, addr = server_socket.accept()
            self.display_message(f"--- Client connected from {addr} ---")
            # Start listening for messages from the client
            threading.Thread(target=self.receive_message, daemon=True).start()
        except Exception as e:
            self.display_message(f"--- Server error: {e} ---")

    def start_client(self):
        """Initializes the client to connect to a server."""
        server_ip = simpledialog.askstring("Server IP", "Enter the server's IP address:", parent=self.root)
        if not server_ip:
            self.root.destroy()
            return
            
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client_socket.connect((server_ip, 12345))
            self.display_message(f"--- Connected to server at {server_ip} ---")
            # Start listening for messages from the server
            threading.Thread(target=self.receive_message, daemon=True).start()
        except Exception as e:
            self.display_message(f"--- Connection failed: {e} ---")
            self.client_socket = None

    def display_message(self, message):
        """Displays a message in the chat area."""
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, message + '\n')
        self.chat_area.config(state='disabled')
        self.chat_area.yview(tk.END)

    def send_message(self, event=None):
        """Handles sending a message."""
        message_text = self.msg_entry.get()
        if not message_text or not self.client_socket:
            return

        self.display_message(f"You: {message_text}")
        
        # Encrypt if the session is secure
        if self.is_secure:
            payload = self.crypto.encrypt_message(message_text)
            message_type = "secure_msg"
        else:
            payload = message_text
            message_type = "plaintext_msg"
            
        # Construct JSON message
        message = json.dumps({"type": message_type, "payload": payload})
        
        try:
            self.client_socket.sendall(message.encode('utf-8') + b'\n')
        except Exception as e:
            self.display_message(f"--- Send failed: {e} ---")
            
        self.msg_entry.delete(0, tk.END)

    def receive_message(self):
        """Handles receiving messages in a loop."""
        buffer = ""
        while True:
            try:
                data = self.client_socket.recv(4096)
                if not data:
                    self.display_message("--- Peer disconnected. ---")
                    self.client_socket.close()
                    self.client_socket = None
                    break
                
                buffer += data.decode('utf-8')
                
                # Process messages separated by newlines
                while '\n' in buffer:
                    message_str, buffer = buffer.split('\n', 1)
                    if message_str:
                        message = json.loads(message_str)
                        self.handle_protocol_message(message)

            except (ConnectionResetError, BrokenPipeError):
                self.display_message("--- Connection lost. ---")
                if self.client_socket:
                    self.client_socket.close()
                self.client_socket = None
                break
            except json.JSONDecodeError:
                print(f"Received malformed JSON: {message_str}")
            except Exception as e:
                print(f"Receiving error: {e}")
                break

    def handle_protocol_message(self, msg):
        """Processes incoming messages based on their type."""
        msg_type = msg.get("type")
        payload = msg.get("payload")

        if msg_type == "plaintext_msg":
            self.display_message(f"Peer: {payload}")

        elif msg_type == "secure_msg":
            decrypted_msg = self.crypto.decrypt_message(payload)
            self.display_message(f"Peer (Encrypted): {decrypted_msg}")
        
        # --- Key Exchange Protocol Steps ---
        elif msg_type == "key_exchange_init":
            self.display_message("--- Peer initiated secure key exchange. ---")
            self.handle_key_exchange_init(payload)

        elif msg_type == "key_exchange_ack":
            self.display_message("--- Peer acknowledged key exchange. ---")
            self.handle_key_exchange_ack(payload)

        else:
            self.display_message(f"--- Received unknown message type: {msg_type} ---")

    def initiate_secure_session(self):
        """Starts the key exchange protocol (Step 1)."""
        if not self.client_socket:
            messagebox.showerror("Error", "Not connected to a peer.")
            return

        self.display_message("--- You initiated secure key exchange. ---")
        self.secure_button.config(state='disabled', text="Securing...")
        
        # Serialize DH public key and sign it
        dh_public_key_pem = serialize_key(self.crypto.dh_public_key)
        signature = self.crypto.sign_data(dh_public_key_pem.encode('utf-8'))
        
        payload = {
            "rsa_pub_key": serialize_key(self.crypto.rsa_public_key),
            "dh_pub_key": dh_public_key_pem,
            "signature": base64.b64encode(signature).decode('utf-8')
        }
        
        message = json.dumps({"type": "key_exchange_init", "payload": payload})
        self.client_socket.sendall(message.encode('utf-8') + b'\n')

    def handle_key_exchange_init(self, payload):
        """Handles receiving the initial key exchange message (Step 2)."""
        try:
            # Deserialize peer's keys and signature
            self.crypto.peer_rsa_public_key = deserialize_key(payload['rsa_pub_key'])
            peer_dh_pub_key_pem = payload['dh_pub_key']
            signature = base64.b64decode(payload['signature'])

            # Verify the signature of the DH key
            if self.crypto.verify_signature(signature, peer_dh_pub_key_pem.encode('utf-8')):
                self.display_message("--- Peer's signature is valid. ---")
                self.crypto.peer_dh_public_key = deserialize_key(peer_dh_pub_key_pem)
                
                # --- START OF THE FIX ---
                # Adopt the peer's DH parameters to ensure compatibility.
                # This is the crucial step to fix the "Error computing shared key".
                self.display_message("--- Adopting peer's DH parameters. ---")
                peer_params = self.crypto.peer_dh_public_key.parameters()
                self.crypto.dh_private_key = peer_params.generate_private_key()
                self.crypto.dh_public_key = self.crypto.dh_private_key.public_key()
                # --- END OF THE FIX ---

                # Now, respond with our own signed DH key (ACK)
                self.send_key_exchange_ack()
                
                # Finally, generate the shared secret
                self.crypto.generate_shared_secret()
                self.is_secure = True
                self.display_message("--- Secure session established! Messages are now encrypted. ---")
                self.secure_button.config(text="Secure")

            else:
                self.display_message("--- WARNING: Peer's signature is INVALID. Aborting secure session. ---")

        except Exception as e:
            self.display_message(f"--- Key exchange failed: {e} ---")
    def send_key_exchange_ack(self):
        """Sends the acknowledgment and own keys back to the initiator (Step 3)."""
        dh_public_key_pem = serialize_key(self.crypto.dh_public_key)
        signature = self.crypto.sign_data(dh_public_key_pem.encode('utf-8'))
        
        payload = {
            "rsa_pub_key": serialize_key(self.crypto.rsa_public_key),
            "dh_pub_key": dh_public_key_pem,
            "signature": base64.b64encode(signature).decode('utf-8')
        }
        
        message = json.dumps({"type": "key_exchange_ack", "payload": payload})
        self.client_socket.sendall(message.encode('utf-8') + b'\n')
        self.display_message("--- Sent acknowledgment and keys to peer. ---")

    def handle_key_exchange_ack(self, payload):
        """Handles the final acknowledgment from the peer (Step 4)."""
        try:
            self.crypto.peer_rsa_public_key = deserialize_key(payload['rsa_pub_key'])
            peer_dh_pub_key_pem = payload['dh_pub_key']
            signature = base64.b64decode(payload['signature'])

            if self.crypto.verify_signature(signature, peer_dh_pub_key_pem.encode('utf-8')):
                self.display_message("--- Peer's acknowledgment signature is valid. ---")
                self.crypto.peer_dh_public_key = deserialize_key(peer_dh_pub_key_pem)
                
                # Generate the shared secret
                self.crypto.generate_shared_secret()
                self.is_secure = True
                self.display_message("--- Secure session established! Messages are now encrypted. ---")
                self.secure_button.config(text="Secure")

            else:
                self.display_message("--- WARNING: Peer's ACK signature is INVALID. Aborting. ---")

        except Exception as e:
            self.display_message(f"--- Finalizing key exchange failed: {e} ---")


# --- Main Execution ---
if __name__ == "__main__":
    root = tk.Tk()
    app = ChatApp(root)
    root.mainloop()

