# AES_128_Encryption_Python
📌 Encryption Project — Caesar Cipher + AES (GUI)

Python Cryptography Projects

Project Description:

This project contains three main encryption programs that demonstrate the difference between classical and modern cryptography.

1. Caesar Cipher

A simple classical cipher that works by shifting letters in the alphabet by a certain number of positions.
It is mainly used for understanding the basic idea of encryption and substitution methods.

3. AES-128 From Scratch

A modern and secure encryption algorithm implemented from scratch for educational purposes.
This program demonstrates the internal workings of AES including key expansion, SubBytes, ShiftRows, MixColumns, and AddRoundKey.

4. AES GUI (Tkinter + PyCryptodome)
   
A modern and secure AES encryption program with a graphical user interface.
It allows users to encrypt and decrypt text using AES in multiple modes:

- ECB (Electronic Codebook)
- CBC (Cipher Block Chaining)
- CFB (Cipher Feedback)
- OFB (Output Feedback)
  
The GUI uses Tkinter for interface design and PyCryptodome for AES encryption.
Passwords are hashed using SHA-256 to create secure encryption keys.

What This Project Demonstrates:

- The difference between classical encryption (Caesar) and modern secure encryption (AES).
- Understanding how substitution works vs. how block ciphers and modes of operation work.
- How to build a simple GUI for encryption.
- How to apply hashing for secure key generation.
- How to use Python libraries for cryptography securely and efficiently.

Why This Is Important:

- Caesar Cipher teaches the basics of encryption logic.
- AES from scratch shows the internal mechanics of block ciphers.
- AES GUI demonstrates practical and secure implementation of encryption using existing libraries.
- Combines coding, cryptography, GUI design, and security concepts.
- Excellent for learning, presenting, and practical encryption examples.

Files Included:

- caesar_cipher.py: Implementation of Caesar encryption/decryption.
- aes_128.py: AES-128 implementation from scratch for educational purposes.
- aes_gui.py: GUI application for AES encryption/decryption using Python libraries.
- README.txt: Project description and documentation.

Caesar Cipher:

Overview:

A classical substitution cipher that shifts letters by a specified number of steps.

How to use:

1. Run the script.
2. Choose whether to encrypt or decrypt.
3. Enter your text and the shift number.
4. The program outputs the encrypted or decrypted text.

Learning Points:

- Understand the basics of encryption and substitution.
- Learn how simple algorithms can transform text securely (for educational purposes).

AES-128 From Scratch:

Overview:

A full AES-128 implementation demonstrating internal AES operations, including Key Expansion, SubBytes & ShiftRows, MixColumns & AddRoundKey, and PKCS7 Padding.

How to use:

1. Run the script.
2. Enter your message.
3. The program encrypts the message and shows it in hexadecimal format.
4. Then it decrypts the message and prints the original text.

Learning Points:

- Learn AES internal mechanics and round transformations.
- Understand how block ciphers work and how data is securely transformed.
- Educational version; for real applications, use libraries like PyCryptodome.

AES GUI Application (Using Python Libraries):

Overview:

A user-friendly GUI for AES encryption and decryption supporting multiple modes (ECB, CBC, CFB, OFB).

Features:

- Input message and password.
- Select encryption mode via buttons.
- Display encrypted text (Hex) and decrypted text instantly.

How it works:

- Passwords are hashed with SHA-256 to generate secure AES keys.
- PKCS7 padding ensures proper block sizes.
- AES encryption and decryption are handled using PyCryptodome library.
- Tkinter provides the graphical interface for user interaction.

Dependencies:

- Python 3
- Tkinter
- PyCryptodome

How to use:

1. Install the PyCryptodome library: pip install pycryptodome
2. Run the GUI script.
3. Enter your message and password.
4. Click the desired AES mode button to encrypt or decrypt the text.

Learning Points:

- Learn to implement cryptography using existing Python libraries.
- Understand AES modes of operation (ECB, CBC, CFB, OFB) in practice.
- Combine GUI programming with secure encryption logic.
- See how hashing and padding are applied in real-world encryption.

Technologies Used:

- Python 3
- Tkinter
- PyCryptodome
- SHA-256 Hashing

