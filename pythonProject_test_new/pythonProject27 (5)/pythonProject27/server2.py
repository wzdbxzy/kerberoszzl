from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QVBoxLayout, QLineEdit, QPushButton, QDialog, QMessageBox
from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP
import socket
import sqlite3
import pickle
import hashlib
import subprocess

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend
# 定义全局变量
# 定义全局变量
SEREVER_HOST = '127.0.0.1'  # TGS的主机名
SEREVER_PORT = 5003  # TGS的端口号
with open('rsa_public_key.pem', 'rb') as f:
    public_key_data = f.read()
    public_key1 = load_pem_public_key(public_key_data, default_backend())

# 导入私钥
with open('rsa_private_key.pem', 'rb') as f:
    private_key_data = f.read()
    private_key1 = load_pem_private_key(private_key_data, password=None, backend=default_backend())

# SERVER服务器逻辑
def serever_server():
    # 监听SERVER的端口
    serever_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serever_socket.bind((SEREVER_HOST, SEREVER_PORT))
    serever_socket.listen(1)
    print(f'serever server listening on {SEREVER_HOST}:{SEREVER_PORT}')

    while True:
        # 接受客户端连接
        client_socket, address = serever_socket.accept()
        print(f'Connection from {address[0]}:{address[1]}')

        response_data = b''
        while True:
            data = client_socket.recv(1024)
            response_data += data
            if len(data) < 1024:
                break


        print('good')
        response_data = pickle.loads(response_data)
        if 'tgt' in response_data:
             # 提取TGT和会话密钥
             encrypted_ticket = response_data['tgt']

             session_key = response_data['encrypted_session_key']
             key= response_data['key']
             print(session_key)

             print('des解密前的tgt')
             print(encrypted_ticket)
             loaded_signature = decrypt_des(session_key,key)
             message = decrypt_des(encrypted_ticket,key)
             # 对消息进行哈希
             digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
             digest.update(message)
             hash_value = digest.finalize()
             print(hash_value)
             try:
                public_key1.verify(
                    loaded_signature,
                    hash_value,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print("签名验证成功！消息未被篡改。")
                CHENGGONG='1'
                # 将加密后的服务器票据发送给客户端
                message = b"good"

                # 哈希
                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest.update(message)
                hash_value = digest.finalize()
                print(f'hash_value: {hash_value}')
                # 加密（数字签名）
                signature1 = private_key1.sign(
                    hash_value,
                    padding.PSS(
                       mgf=padding.MGF1(hashes.SHA256()),
                       salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print(f'signature: {signature1}')
                # 发送消息和签名
                # 在实际应用中，需要将消息和签名一起发送给验证方（例如，通过网络传输）
                response = pickle.dumps({'tgt': message, 'encrypted_session_key': signature1})
                client_socket.sendall(response)

             except Exception:
                print("签名验证失败！消息可能已被篡改或签名无效。")
        elif 'zeng' in response_data:
            # 提取TGT和会话密钥
            encrypted_ticket = response_data['zeng']

            session_key = response_data['encrypted_session_key']
            title = response_data['title']
            author = response_data['author']
            publisher = response_data['publisher']
            price = response_data['price']
            pub_date = response_data['pub_date']
            key = response_data['key']
            print(session_key)

            print('des解密前的tgt')
            print(encrypted_ticket)
            loaded_signature = decrypt_des(session_key, key)
            message = decrypt_des(encrypted_ticket, key)
            # 对消息进行哈希
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(message)
            hash_value = digest.finalize()
            print(hash_value)
            try:
                public_key1.verify(
                    loaded_signature,
                    hash_value,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print("签名验证成功！消息未被篡改。")
                CHENGGONG = '1'
                print(message)
                # 将加密后的服务器票据发送给客户端
                if validate_tgt(message):
                    # 生成服务器的会话密钥
                    print(message)
                    conn = sqlite3.connect('bookstore.db')
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT INTO books (title, author, publisher, price, pub_date) VALUES (?, ?, ?, ?, ?)",
                        (title, author, publisher, price, pub_date))
                    conn.commit()
                    conn.close()

                    message = b"good"

                    # 哈希
                    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                    digest.update(message)
                    hash_value = digest.finalize()
                    print(f'hash_value: {hash_value}')
                    # 加密（数字签名）
                    signature1 = private_key1.sign(
                        hash_value,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    print(f'signature: {signature1}')
                    # 发送消息和签名
                    # 在实际应用中，需要将消息和签名一起发送给验证方（例如，通过网络传输）
                    response = pickle.dumps({'tgt': message, 'encrypted_session_key': signature1})
                    client_socket.sendall(response)

            except Exception:
                print("签名验证失败！消息可能已被篡改或签名无效。")











           # 关闭客户端连接
        client_socket.close()


# 验证TGT的有效性和合法性
def validate_tgt(tgt):
    return tgt.endswith(b'zeng')
def decrypt_des(ciphertext, password):
    md5 = hashlib.md5()
    md5.update(password)
    des_key = md5.digest()[:8]
    cipher = DES.new(des_key, DES.MODE_ECB)
    decrypted_data = cipher.decrypt(ciphertext)
    return unpad(decrypted_data, 8)
# 生成服务器票据
def generate_server_ticket(session_key):
    server_ticket = session_key + b',SERVER_SESSION_KEY'
    return server_ticket
def encrypt_des(data, password):
    # 使用密码作为种子，生成 MD5 哈希值
    md5 = hashlib.md5()
    md5.update(password)
    # 取前 8 个字节作为 DES 密钥
    des_key = md5.digest()[:8]
    cipher = DES.new(des_key, DES.MODE_ECB)
    padded_data = pad(data, 8)
    ciphertext = cipher.encrypt(padded_data)
    return ciphertext

def encrypt_rsa(data, public_key):

    cipher = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher.encrypt(data)
    return encrypted_data

def decrypt_rsa(encrypted_data, private_key):

    cipher = PKCS1_OAEP.new(private_key)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data
if __name__ == '__main__':
    serever_server()