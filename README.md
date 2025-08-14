# Secure Chat Application (Python/Tkinter)

This repository contains a secure, two-party chat application developed for the CSE722 course project. The application establishes a direct TCP connection between two clients and uses a cryptographic handshake to enable end-to-end encrypted communication.

## Features

* **Direct Client-to-Client Chat:** Establishes a direct TCP connection between two users on a local network.

* **Secure Key Exchange:** Utilizes a **Diffie-Hellman (DH)** key exchange to agree upon a shared secret. The authenticity of the exchange is guaranteed by signing the DH public keys with **RSA-2048** digital signatures.

* **End-to-End Encryption:** All messages sent after the secure handshake are encrypted using **AES-256-GCM**, which provides confidentiality, integrity, and authenticity.

## Prerequisites

Before running the application, ensure you have the following installed:

* **Python 3.x**

* The **`cryptography`** library. You can install it via pip:

pip install cryptography

## How to Run

To use the application, you will need two computers connected to the same local network.

#### **1. On the First Computer (The "Server"):**

This computer will act as the listener, waiting for the other user to connect.

1. **Find its Local IP Address:**

 * On Windows, open Command Prompt and type `ipconfig`.

 * On macOS or Linux, open a terminal and type `ip addr`.

 * Note the "IPv4 Address" (e.g., `192.168.1.10`).

2. **Run the Application:**

 * Navigate to the project directory in your terminal.

 * Execute the script:

   ```
   python secure_chat.py
   ```

 * When the first dialog box appears, type `server` and press Enter. The application window will open and display a message indicating it is waiting for a connection.

#### **2. On the Second Computer (The "Client"):**

This computer will initiate the connection.

1. **Run the Application:**

 * Navigate to the project directory in your terminal.

 * Execute the script:

   ```
   python secure_chat.py
   ```

 * When the first dialog box appears, type `client` and press Enter.

2. **Enter the Server's IP:**

 * A second dialog box will appear. Type the IP address of the **first computer** that you noted earlier.

 * Press Enter.

The two clients should now be connected. You can begin by sending unencrypted messages. To enable encryption, click the **"Go Secure"** button on either client's window to initiate the secure handshake.

## Cryptographic Protocol Overview

The application follows a three-phase protocol:

1. **Unencrypted Connection:** A standard TCP socket is established for initial communication.

2. **Secure Handshake:** When initiated, the clients perform an authenticated Diffie-Hellman exchange. RSA signatures are used to verify the authenticity of the DH public keys, preventing Man-in-the-Middle (MitM) attacks. The clients agree on a shared secret without ever transmitting it over the network.

3. **Encrypted Communication:** The derived shared secret is used as a key for AES-256-GCM, which encrypts all subsequent messages, ensuring confidentiality and integrity.
