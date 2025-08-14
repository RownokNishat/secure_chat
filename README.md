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
