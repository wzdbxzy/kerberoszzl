
import random

from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP
import socket
import sqlite3
import pickle
import hashlib
# 定义全局变量
TGS_HOST = '127.0.0.1'  # TGS的主机名
TGS_PORT = 5004  # TGS的端口号
with open('public_key.pem', 'rb') as f:
    SERVER_PUBLIC_KEY = RSA.import_key(f.read())

with open('private_key.pem', 'rb') as f:
    TGS_PRIVATE_KEY = RSA.import_key(f.read())
# TGS服务器逻辑
def tgs_server():
    # 监听TGS的端口
    tgs_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tgs_socket.bind((TGS_HOST, TGS_PORT))
    tgs_socket.listen(1)
    print(f'TGS server listening on {TGS_HOST}:{TGS_PORT}')

    while True:
        # 接受客户端连接
        client_socket, address = tgs_socket.accept()
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
             print(session_key)
        print('des解密前的tgt')
        print(encrypted_ticket)
        entgt = decrypt_des(encrypted_ticket,session_key)
        print(entgt)
        print(len(entgt))
        tgt = decrypt_rsa(entgt, TGS_PRIVATE_KEY)
        #问题出在54行我的rsa加解密算法有问题无法解密，你们重写个简单的试试，我这个是之前的要加密的数据太长了简单版本无法加密而用的
        print('解密后的TGT')
        print(tgt)

        # 验证TGT的有效性和合法性
        if validate_tgt(tgt):
            # 生成服务器的会话密钥
            server_session_key = bytes([random.randint(0, 255) for _ in range(8)])


            # 生成服务器票据
            server_ticket = generate_server_ticket(server_session_key)
            print(server_ticket)
            # 使用服务器的公钥对服务器票据进行加密
            encrypted_server_ticket = encrypt_rsa(server_ticket, SERVER_PUBLIC_KEY)
            encrypted_server_session_key = encrypt_des(server_session_key,session_key)
            print(encrypted_server_ticket)
            # 将加密后的服务器票据发送给客户端
            response = pickle.dumps({'tgt': encrypted_server_ticket, 'encrypted_session_key': encrypted_server_session_key})
            #response = f'SUCCESS:{tgt}:{encrypted_session_key}'
            print('111')
            client_socket.sendall(response)

        else:
            response = 'FAILURE'
            client_socket.sendall(response.encode())

        # 关闭客户端连接
        client_socket.close()

# 使用私钥对票据进行解密
def decrypt_des(ciphertext, password):
    md5 = hashlib.md5()
    md5.update(password)
    des_key = md5.digest()[:8]
    cipher = DES.new(des_key, DES.MODE_ECB)
    decrypted_data = cipher.decrypt(ciphertext)
    return unpad(decrypted_data, 8)
# 验证TGT的有效性和合法性
def validate_tgt(tgt):
    return tgt.endswith(b'TGS_SESSION_KEY')

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
    tgs_server()