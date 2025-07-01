from tkinter import *
from tkinter import messagebox
from cryptography.fernet import Fernet
import base64
import hashlib

window = Tk()
window.title("Secret Notes")
window.config(padx=20, pady=20)

# --- Fonksiyonlar ---
def write_file(title, encrypted_text):
    with open(f"{title}.txt", "wb") as file:
        file.write(encrypted_text)

def read_file(title):
    try:
        with open(f"{title}.txt", "rb") as file:
            return file.read()
    except FileNotFoundError:
        messagebox.showerror("Hata", "Dosya bulunamadı!")
        return None

def get_fernet_key(master_key):
    key = hashlib.sha256(master_key.encode()).digest()
    return base64.urlsafe_b64encode(key)

def save_encrypt():
    title = title_entry.get()
    secret = text.get("1.0", END).strip()
    master_key = key_entry.get()

    if not title or not secret or not master_key:
        messagebox.showwarning("Uyarı", "Tüm alanları doldurun!")
        return

    fernet = Fernet(get_fernet_key(master_key))
    encrypted = fernet.encrypt(secret.encode())

    write_file(title, encrypted)
    text.delete("1.0", END)
    messagebox.showinfo("Başarılı", "Not şifrelendi ve kaydedildi.")

def decrypt_note():
    title = title_entry.get()
    master_key = key_entry.get()

    if not title or not master_key:
        messagebox.showwarning("Uyarı", "Başlık ve anahtar gerekli!")
        return

    encrypted = read_file(title)
    if encrypted is None:
        return

    try:
        fernet = Fernet(get_fernet_key(master_key))
        decrypted = fernet.decrypt(encrypted).decode()
        text.delete("1.0", END)
        text.insert("1.0", decrypted)
        messagebox.showinfo("Başarılı", "Not çözüldü.")
    except Exception as e:
        messagebox.showerror("Hata", f"Şifre çözme başarısız!\n{str(e)}")


def decrypt_note():
    title = title_entry.get()
    master_key = key_entry.get()

    print(f"[DEBUG] Girilen title: {title}")
    print(f"[DEBUG] Girilen master key: {master_key}")

    if not title or not master_key:
        messagebox.showwarning("Uyarı", "Başlık ve anahtar gerekli!")
        return

    encrypted = read_file(title)
    if encrypted is None:
        print("[DEBUG] Dosya okunamadı.")
        return

    print(f"[DEBUG] Dosyadan okunan şifreli veri: {encrypted}")

    try:
        fernet = Fernet(get_fernet_key(master_key))
        print("[DEBUG] Fernet anahtarı üretildi.")
        decrypted = fernet.decrypt(encrypted).decode()
        print("[DEBUG] Şifre çözme başarılı.")
        text.delete("1.0", END)
        text.insert("1.0", decrypted)
        messagebox.showinfo("Başarılı", "Not çözüldü.")
    except Exception as e:
        print(f"[DEBUG] Şifre çözme başarısız: {e}")
        messagebox.showerror("Hata", f"Şifre çözme başarısız!\n{str(e)}")


# --- Arayüz Elemanları ---

# Logo (isteğe bağlı)
# canvas = Canvas(height=100, width=100)
# logo = PhotoImage(file="top_secret.png")
# canvas.create_image(50, 50, image=logo)
# canvas.pack()

Label(text="Enter your title").pack()
title_entry = Entry(width=30)
title_entry.pack()

Label(text="Enter your secret").pack()
text = Text(height=10, width=40)
text.pack()

Label(text="Enter master key").pack()
key_entry = Entry(width=30)
key_entry.pack()

Button(text="Save & Encrypt", command=save_encrypt).pack(pady=5)
Button(text="Decrypt", command=decrypt_note).pack()

window.mainloop()
