import tkinter as tk

def encrypt(text, shift):
    result = ''
    for char in text:
        if char.isalpha():
            start = ord('a') if char.islower() else ord('A')
            result += chr((ord(char) - start + shift) % 26 + start)
        else:
            result += char
    return result

def decrypt(ciphertext, shift):
    return encrypt(ciphertext, -shift)

def encrypt_decrypt():
    plaintext = plaintext_entry.get()
    shift = int(shift_entry.get())

    encrypted_text = encrypt(plaintext, shift)
    decrypted_text = decrypt(encrypted_text, shift)

    encrypted_display.delete(1.0, tk.END)
    encrypted_display.insert(tk.END, encrypted_text)

    decrypted_display.delete(1.0, tk.END)
    decrypted_display.insert(tk.END, decrypted_text)

# Create GUI
root = tk.Tk()
root.title("Caesar Cipher Encryption and Decryption")

# Labels
plaintext_label = tk.Label(root, text="Enter Text:")
plaintext_label.grid(row=0, column=0, sticky=tk.W)

shift_label = tk.Label(root, text="Enter Shift (an integer):")
shift_label.grid(row=1, column=0, sticky=tk.W)

encrypted_label = tk.Label(root, text="Encrypted Text:")
encrypted_label.grid(row=2, column=0, sticky=tk.W)

decrypted_label = tk.Label(root, text="Decrypted Text:")
decrypted_label.grid(row=4, column=0, sticky=tk.W)

# Entry fields
plaintext_entry = tk.Entry(root, width=50)
plaintext_entry.grid(row=0, column=1, columnspan=2)

shift_entry = tk.Entry(root, width=50)
shift_entry.grid(row=1, column=1, columnspan=2)

# Text displays
encrypted_display = tk.Text(root, width=50, height=5)
encrypted_display.grid(row=2, column=1, columnspan=2)

decrypted_display = tk.Text(root, width=50, height=5)
decrypted_display.grid(row=4, column=1, columnspan=2)

# Encrypt/Decrypt button
encrypt_decrypt_button = tk.Button(root, text="Encrypt/Decrypt", command=encrypt_decrypt)
encrypt_decrypt_button.grid(row=3, column=1)

root.mainloop()
