import tkinter as tk
from tkinter import ttk, messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import binascii

# ---------------- AES Functions ----------------
def aes_process(val, password, mode_choice):
    if not val or not password or not mode_choice:
        return "", ""
    
    key = hashlib.sha256(password.encode()).digest()[:16]
    iv = b'0123456789abcdef'
    plaintext = pad(val.encode(), AES.block_size)
    
    modes = {
        'ECB': AES.MODE_ECB,
        'CBC': AES.MODE_CBC,
        'CFB': AES.MODE_CFB,
        'OFB': AES.MODE_OFB
    }
    
    mode = modes[mode_choice]
    
    # Encrypt
    cipher = AES.new(key, mode) if mode_choice == 'ECB' else AES.new(key, mode, iv)
    ciphertext = cipher.encrypt(plaintext)
    hex_cipher = binascii.hexlify(ciphertext).decode()
    
    # Decrypt
    decipher = AES.new(key, mode) if mode_choice == 'ECB' else AES.new(key, mode, iv)
    decrypted = unpad(decipher.decrypt(ciphertext), AES.block_size).decode()
    
    return hex_cipher, decrypted

def update_result(mode_choice):
    val = entry_text.get()
    password = entry_password.get()
    hex_cipher, decrypted = aes_process(val, password, mode_choice)
    
    entry_cipher.config(state='normal')
    entry_cipher.delete(0, tk.END)
    entry_cipher.insert(0, hex_cipher)
    entry_cipher.config(state='readonly')
    
    entry_decrypted.config(state='normal')
    entry_decrypted.delete(0, tk.END)
    entry_decrypted.insert(0, decrypted)
    entry_decrypted.config(state='readonly')

# ---------------- GUI ----------------
root = tk.Tk()
root.title("🔐 AES Encrypt/Decrypt GUI")
root.geometry("600x400")
root.configure(bg="#1e1e1e")

font_label = ("Arial", 12, "bold")
font_entry = ("Arial", 12)

# Input Fields
tk.Label(root, text="الرسالة:", bg="#1e1e1e", fg="white", font=font_label).place(x=20, y=20)
entry_text = tk.Entry(root, width=45, font=font_entry)
entry_text.place(x=150, y=20)

tk.Label(root, text="كلمة السر:", bg="#1e1e1e", fg="white", font=font_label).place(x=20, y=60)
entry_password = tk.Entry(root, show="*", width=45, font=font_entry)
entry_password.place(x=150, y=60)

# Buttons for modes
btn_ecb = tk.Button(root, text="Encrypt/Decrypt ECB", width=20, bg="#ff5555", fg="white",
                    command=lambda: update_result("ECB"))
btn_ecb.place(x=20, y=110)

btn_cbc = tk.Button(root, text="Encrypt/Decrypt CBC", width=20, bg="#55ff55", fg="black",
                    command=lambda: update_result("CBC"))
btn_cbc.place(x=220, y=110)

btn_cfb = tk.Button(root, text="Encrypt/Decrypt CFB", width=20, bg="#5555ff", fg="white",
                    command=lambda: update_result("CFB"))
btn_cfb.place(x=20, y=160)

btn_ofb = tk.Button(root, text="Encrypt/Decrypt OFB", width=20, bg="#ffaa00", fg="black",
                    command=lambda: update_result("OFB"))
btn_ofb.place(x=220, y=160)

# Output Fields
tk.Label(root, text="النص المشفر (Hex):", bg="#1e1e1e", fg="white", font=font_label).place(x=20, y=220)
entry_cipher = tk.Entry(root, width=60, font=font_entry, state='readonly')
entry_cipher.place(x=20, y=250)

tk.Label(root, text="النص المفكوك:", bg="#1e1e1e", fg="white", font=font_label).place(x=20, y=290)
entry_decrypted = tk.Entry(root, width=60, font=font_entry, state='readonly')
entry_decrypted.place(x=20, y=320)

root.mainloop()
