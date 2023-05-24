import socket
import sqlite3
from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
from Crypto.Cipher import PKCS1_OAEP
import hashlib
import pickle
import random
import threading
import time
import tkinter as tk

# 定义全局变量
zhang='1'
AS_HOST = '192.168.47.114'  # AS的主机名
AS_PORT = 5005  # AS的端口号
with open('private_key.pem', 'rb') as f:
    private_key = RSA.import_key(f.read())

with open('public_key.pem', 'rb') as f:
    TGS_PUBLIC_KEY = RSA.import_key(f.read())
AS_DATABASE = 'as.db'  # AS的数据库文件
# 创建一个 Tkinter 窗口
window = tk.Tk()
window.title("AS Server Output")  # 设置窗口标题

# 创建一个文本框小部件来显示输出
output_text = tk.Text(window)
output_text.pack()


def redirect_print(output):
    output_text.insert(tk.END, str(output) + '\n')
    output_text.see(tk.END)  # 滚动到文本框的末尾


# 将 print 函数替换为自定义的 redirect_print 函数
print = redirect_print


def add_user(username, password):
    conn = sqlite3.connect(AS_DATABASE)
    c = conn.cursor()
    c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
    conn.commit()
    conn.close()


# 创建AS数据库表
def create_database():
    conn = sqlite3.connect(AS_DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY NOT NULL,
                 password TEXT NOT NULL)''')
    conn.commit()
    conn.close()


# AS服务器逻辑
def as_server():
    # 创建AS数据库表
    create_database()

    # 监听AS的端口
    as_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    as_socket.bind((AS_HOST, AS_PORT))
    as_socket.listen(1)
    print(f'AS 服务器正在监听 {AS_HOST}:{AS_PORT}')

    while True:
        # 接受客户端连接
        client_socket, address = as_socket.accept()
        print(f'来自 {address[0]}:{address[1]} 的连接')

        # 接收客户端发送的用户名和密码
        username_password = client_socket.recv(1024).decode()
        print(f'来自 {address[0]}:{address[1]} 的连接')
        username, password, expire_time = username_password.split(':')
        print(expire_time)
        print(f'来自 {address[0]}:{address[1]} 的连接')
        # 在数据库中验证用户名和密码
        if authenticate_user(username, password, expire_time):
            # 生成会话密钥
            session_key = bytes([random.randint(0, 255) for _ in range(8)])
            encrypted_session_key = encrypt_des(session_key, password)
            print(f'加密后的session_key: {encrypted_session_key}')

            # 生成 TGT
            tgt = generate_tgt(session_key)
            print(f'生成的tgt: {tgt}')
            # 使用 AS 的私钥对 TGT 进行签名
            signed_tgt = encrypt_rsa1(tgt, TGS_PUBLIC_KEY)
            se1 = decrypt_rsa1(signed_tgt, private_key)
            print(f'加密后的TGT: {signed_tgt}')
            print(f'解密后的TGT: {se1}')
            print(f'长度: {len(signed_tgt)}')
            print('good')
            print('git test')

            # 将加密的会话密钥和 TGT 发送给客户端
            response = pickle.dumps({'tgt': signed_tgt, 'encrypted_session_key': encrypted_session_key})
            # response = f'SUCCESS:{tgt}:{encrypted_session_key}'

            client_socket.sendall(response)
            print('zhang')
        else:
            response = 'FAILURE'
            client_socket.sendall(response.encode())
            print('good2')
        # 关闭客户端连接
        client_socket.close()


# 在数据库中验证用户名和密码
def authenticate_user(username, password, expire_time):
    now = str(time.time())
    if expire_time > now:
        conn = sqlite3.connect(AS_DATABASE)
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))
        result = c.fetchone()
        conn.close()
        return result is not None


# 使用客户端密码对会话密钥进行DES加密
def encrypt_des(data, password):
    # 使用密码作为种子，生成 MD5 哈希值
    md5 = hashlib.md5()
    md5.update(password.encode())
    # 取前 8 个字节作为 DES 密钥
    des_key = md5.digest()[:8]
    cipher = DES.new(des_key, DES.MODE_ECB)
    padded_data = pad(data, 8)
    ciphertext = cipher.encrypt(padded_data)
    return ciphertext


# 生成TGT
def generate_tgt(session_key):
    tgt = session_key + b',TGS_SESSION_KEY'
    return tgt


# 使用AS的私钥对TGT进行签名
def encrypt_rsa(data, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_blocks = []
    block_size = 245  # RSA 2048-bit key limit

    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        encrypted_block = cipher_rsa.encrypt(block)
        encrypted_blocks.append(encrypted_block)

    return b''.join(encrypted_blocks)


def decrypt_rsa(encrypted_data, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_blocks = []

    for encrypted_block in encrypted_data:
        encrypted_block = bytes([encrypted_block])  # 将整数转换为字节串
        decrypted_block = cipher_rsa.decrypt(encrypted_block)
        decrypted_blocks.append(decrypted_block)

    decrypted_data = b''.join(decrypted_blocks)

    return decrypted_data


def encrypt_rsa1(data, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher.encrypt(data)
    return encrypted_data


def decrypt_rsa1(encrypted_data, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data


if __name__ == '__main__':
    # as_server()
    # 将 tgs_server() 函数作为线程运行的目标函数

    def run_tgs_server():
        as_server()


    # 创建线程实例
    tgs_thread = threading.Thread(target=run_tgs_server)

    # 启动线程
    tgs_thread.start()
    window.mainloop()
    # 等待线程结束
    tgs_thread.join()
