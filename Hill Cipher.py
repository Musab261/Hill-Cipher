import numpy as np
import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox

def generate_key():
    while True:
        key = np.random.randint(0, 26, (3, 3))
        if int(round(np.linalg.det(key))) % 26 != 0:  # Ensure invertible
            return key

def mod_inv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def encrypt(plaintext, key):
    plaintext = plaintext.upper().replace(" ", "")
    while len(plaintext) % 3 != 0:
        plaintext += "X"  # padding
    cipher_text = ""
    for i in range(0, len(plaintext), 3):
        block = [ord(c) - 65 for c in plaintext[i:i+3]]
        enc_block = np.dot(key, block) % 26
        cipher_text += ''.join([chr(int(num) + 65) for num in enc_block])
    return cipher_text

def decrypt(ciphertext, key):
    det = int(round(np.linalg.det(key)))
    det_inv = mod_inv(det % 26, 26)
    if det_inv is None:
        messagebox.showerror("Error", "Key is not invertible for decryption!")
        return ""
    # Compute inverse matrix modulo 26
    key_inv = det_inv * np.round(det * np.linalg.inv(key)).astype(int) % 26
    plaintext = ""
    for i in range(0, len(ciphertext), 3):
        block = [ord(c) - 65 for c in ciphertext[i:i+3]]
        dec_block = np.dot(key_inv, block) % 26
        plaintext += ''.join([chr(int(num) + 65) for num in dec_block])
    return plaintext

def encode_text():
    plaintext = text_input.get("1.0", tk.END).strip()
    if not plaintext:
        return
    cipher_text = encrypt(plaintext, key_matrix)
    text_encrypted.delete("1.0", tk.END)
    text_encrypted.insert(tk.END, cipher_text)

def decode_text():
    cipher_text = text_encrypted.get("1.0", tk.END).strip()
    if not cipher_text:
        return
    plaintext = decrypt(cipher_text, key_matrix)
    text_decrypted.delete("1.0", tk.END)
    text_decrypted.insert(tk.END, plaintext)

root = tk.Tk()
root.title("Hill Cipher")

tk.Label(root, text="Enter Text:").pack()
text_input = scrolledtext.ScrolledText(root, width=60, height=5)
text_input.pack()

tk.Button(root, text="Encode", command=encode_text).pack()

tk.Label(root, text="Encrypted Text:").pack()
text_encrypted = scrolledtext.ScrolledText(root, width=60, height=5)
text_encrypted.pack()

tk.Button(root, text="Decode", command=decode_text).pack()

tk.Label(root, text="Decoded Text:").pack()
text_decrypted = scrolledtext.ScrolledText(root, width=60, height=5)
text_decrypted.pack()

key_matrix = generate_key()

root.mainloop()
