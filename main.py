import os
import json
import base64
from win32crypt import CryptUnprotectData
import sqlite3
import shutil
from Crypto.Cipher import AES

def get_master_key(path: str) -> str:
    if not os.path.exists(path):
        return

    if 'os_crypt' not in open(path, 'r', encoding='utf-8').read():
        return

    with open(path, "r", encoding="utf-8") as f:
        c = f.read()
    local_state = json.loads(c)

    master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    master_key = master_key[5:]
    master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
    return master_key


def decrypt_password(buff: bytes, master_key: bytes) -> str:
    iv = buff[3:15]
    payload = buff[15:]
    cipher = AES.new(master_key, AES.MODE_GCM, iv)
    decrypted_pass = cipher.decrypt(payload)
    decrypted_pass = decrypted_pass[:-16].decode()

    return decrypted_pass


def get_login_data(path: str):
    login_db = r'C:\Users\your_username\AppData\Local\Google\Chrome\User Data\Default\Login Data'
    if not os.path.exists(login_db):
        return
    conn = sqlite3.connect(login_db)
    cursor = conn.cursor()
    cursor.execute(
        'SELECT action_url, username_value, password_value FROM logins')
    for row in cursor.fetchall():
        if not row[0] or not row[1] or not row[2]:
            continue
        master_key = get_master_key(r"C:\Users\your_username\AppData\Local\Google\Chrome\User Data\Local State")
        password = decrypt_password(row[2], master_key)
        print(row[0], row[1], password)

    conn.close()


get_login_data(r'C:\Users\your_username\AppData\Local\Google\Chrome')
