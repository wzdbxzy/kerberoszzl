from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox, QWidget, QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QHBoxLayout
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QVBoxLayout, QLineEdit, QPushButton, QDialog, QMessageBox
from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import  padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend
import sys
import socket
import sqlite3
import pickle
import hashlib
import subprocess

# 定义全局变量
AS_HOST = '127.0.0.1'  # AS的主机名
AS_PORT = 5005  # AS的端口号
TGS_HOST = '127.0.0.1'  # TGS的主机名
TGS_PORT = 5001  # TGS的端口号
SERVER_HOST = '127.0.0.1'  # 服务器的主机名
SERVER_PORT = 5002  # 服务器的端口号

CLIENT_DATABASE = 'as.db'  # 客户端的数据库文件
with open('public_key.pem', 'rb') as f:
    public_key = RSA.import_key(f.read())
with open('private_key.pem', 'rb') as f:
    private_key = RSA.import_key(f.read())
with open('rsa_public_key.pem', 'rb') as f:
    public_key_data = f.read()
    public_key1 = load_pem_public_key(public_key_data, default_backend())

# 导入私钥
with open('rsa_private_key.pem', 'rb') as f:
    private_key_data = f.read()
    private_key1 = load_pem_private_key(private_key_data, password=None, backend=default_backend())

# 创建客户端数据库表（已创建）
def create_database():
    conn = sqlite3.connect(CLIENT_DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY NOT NULL,
                 password TEXT NOT NULL)''')
    conn.commit()
    conn.close()


class RegisterWindow(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Register')
        self.setGeometry(900, 900, 650, 450)

        layout = QVBoxLayout()

        self.username_label = QLabel('Username:')
        self.username_input = QLineEdit()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)

        self.password_label = QLabel('Password:')
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)

        self.register_button = QPushButton('Register')
        self.register_button.clicked.connect(self.register)
        layout.addWidget(self.register_button)

        self.setLayout(layout)

    def register(self):
        username = self.username_input.text()
        password = self.password_input.text()

        if username == '' or password == '':
            QMessageBox.warning(self, 'Register', 'Please enter username and password.')
        else:
            conn = sqlite3.connect(CLIENT_DATABASE)
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS users
                         (username TEXT PRIMARY KEY NOT NULL,
                         password TEXT NOT NULL)''')
            # 将账号密码插入到数据库中
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            conn.commit()
            conn.close()
            QMessageBox.information(self, 'Register', 'Registration successful.')
            self.close()


# 客户端登录窗口
class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.session_key = None

    def init_ui(self):
        self.setWindowTitle('Login')
        self.setGeometry(800, 800, 650, 450)

        layout = QVBoxLayout()

        self.username_label = QLabel('Username:')
        self.username_input = QLineEdit()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)

        self.password_label = QLabel('Password:')
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)

        self.login_button = QPushButton('Login')
        self.login_button.clicked.connect(self.login)
        layout.addWidget(self.login_button)

        self.register_button = QPushButton('Register')
        self.register_button.clicked.connect(self.open_register_window)
        layout.addWidget(self.register_button)

        self.setLayout(layout)

    def login(self):
        username = self.username_input.text()
        password = self.password_input.text()

        if username == '' or password == '':
            QMessageBox.warning(self, 'Login', '账号或密码为空！')

        # 发送用户名和密码给AS进行认证
        as_response = self.authenticate_with_as(username, password)
        if as_response is None:
            print('wode')
            return

        print(as_response)

        # 发送加密的服务器票据给服务器
        server_response = self.request_server_access(as_response)
        if server_response is None:
            return

        # 打印服务器的响应
        print(f'Server Response: {server_response}')
        server_response1 = self.request_server_access1(server_response,username,password)
        if server_response1 is None:
            return

        # 打印服务器的响应
        print(f'Server Response: {server_response1}')
        server_response2=server_response1.decode()
        if server_response2 =='1' :
            self.close()
            subprocess.run(['python', 'book_manager.py'])

    def open_register_window(self):
        register_dialog = RegisterWindow()
        register_dialog.exec_()

    def authenticate_with_as(self, username, password):
        # 连接AS服务器
        as_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        as_socket.connect((AS_HOST, AS_PORT))

        # 发送用户名和密码给AS
        as_socket.sendall(f'{username}:{password}'.encode())

        # 接收AS的响应
        response_data = b''
        while True:
            data = as_socket.recv(1024)
            response_data += data
            if len(data) < 1024:
                break

        as_socket.close()
        print('good')
        response_data = pickle.loads(response_data)
        print('good1')
        if 'tgt' in response_data:
            # 提取TGT和会话密钥
            tgt = response_data['tgt']
            print('good2')
            encrypted_session_key = response_data['encrypted_session_key']
            print('good3')
            print(f'tgt: {tgt}')
            print(f'se: {encrypted_session_key}')
            session_key = self.decrypt_des(encrypted_session_key, password)
            self.session_key = session_key
            print('good4')
            print(f'tgt: {tgt}')
            print(f'se: {encrypted_session_key}')
            print(f's1: {session_key}')
            entgt = self.encrypt_des(tgt, session_key)
            # entgt1= self.decrypt_rsa(tgt ,private_key)
            # print(entgt1)

            new_response_data = pickle.dumps({'tgt': entgt, 'encrypted_session_key': session_key})
            return new_response_data

        else:
            print('Authentication failed.')

            return None

    def decrypt_des(self, ciphertext, password):
        md5 = hashlib.md5()
        md5.update(password.encode())
        des_key = md5.digest()[:8]
        cipher = DES.new(des_key, DES.MODE_ECB)
        decrypted_data = cipher.decrypt(ciphertext)
        return unpad(decrypted_data, 8)

    def decrypt_des1(self, ciphertext, password):
        md5 = hashlib.md5()
        md5.update(password)
        des_key = md5.digest()[:8]
        cipher = DES.new(des_key, DES.MODE_ECB)
        decrypted_data = cipher.decrypt(ciphertext)
        return unpad(decrypted_data, 8)

    def encrypt_des(self, data, password):
        # 使用密码作为种子，生成 MD5 哈希值
        md5 = hashlib.md5()
        md5.update(password)
        # 取前 8 个字节作为 DES 密钥
        des_key = md5.digest()[:8]
        cipher = DES.new(des_key, DES.MODE_ECB)
        padded_data = pad(data, 8)
        ciphertext = cipher.encrypt(padded_data)
        return ciphertext

    def decrypt_rsa(self, encrypted_data, private_key):
        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted_blocks = []

        # 对加密的数据进行分块解密
        for encrypted_block in encrypted_data:
            decrypted_block = cipher_rsa.decrypt(encrypted_block)
            decrypted_blocks.append(decrypted_block)

        # 拼接解密后的数据块
        decrypted_data = b''.join(decrypted_blocks)

        return decrypted_data

    def request_server_access(self, encrypted_server_ticket):
        # 连接服务器
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((TGS_HOST, TGS_PORT))
        session_key = self.session_key
        # 发送加密的服务器票据给服务器
        server_socket.sendall(encrypted_server_ticket)
        response_data = b''
        while True:
            data = server_socket.recv(1024)
            response_data += data
            if len(data) < 1024:
                break

        server_socket.close()
        # 接收服务器的响应
        response_data = pickle.loads(response_data)
        print('good1')
        if 'tgt' in response_data:
            # 提取TGT和会话密钥
            tgt = response_data['tgt']
            print('good2')
            encrypted_session_key = response_data['encrypted_session_key']
            print('good3')
            print(f'rtgt: {tgt}')
            print(f'rse: {encrypted_session_key}')
            session_key1 = self.decrypt_des1(encrypted_session_key, session_key)
            print('rgood4')
            print(f'rtgt: {tgt}')
            print(f'rse: {encrypted_session_key}')
            print(f'rs1: {session_key}')
            entgt = self.encrypt_des(tgt, session_key1)
            # entgt1= self.decrypt_rsa(tgt ,private_key)
            # print(entgt1)

            new_response_data = pickle.dumps({'tgt': tgt, 'encrypted_session_key': session_key1})
            return new_response_data

        else:
            print('Authentication failed.')

            return None

    def request_server_access1(self, encrypted_server_ticket,username, password):

        # 连接服务器
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((SERVER_HOST, SERVER_PORT))

        session_key = self.session_key
        response_data = pickle.loads(encrypted_server_ticket)
        if 'tgt' in response_data:
            # 提取TGT和会话密钥
            encrypted_ticket = response_data['tgt']

            session_key = response_data['encrypted_session_key']

            print(session_key)
        print('des解密前的tgt')
        message = encrypted_ticket

        # 哈希
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(message)
        hash_value = digest.finalize()
        print(f'hash_value: {hash_value}')
        # 加密（数字签名）
        signature = private_key1.sign(
            hash_value,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(f'signature: {signature}')
        signature1=self.encrypt_des(signature, session_key)

        # 发送消息和签名
        # 在实际应用中，需要将消息和签名一起发送给验证方（例如，通过网络传输）
        message1=self.encrypt_des(message, session_key)
        response = pickle.dumps({'tgt': message1, 'encrypted_session_key': signature1,'key': session_key})
        server_socket.sendall(response)
        response_data = b''
        while True:
            data = server_socket.recv(1024)
            response_data += data
            if len(data) < 1024:
                break
        print(response_data)
        server_socket.close()
        print('good')
        response_data = pickle.loads(response_data)
        if 'tgt' in response_data:
             # 提取TGT和会话密钥
             encrypted_ticket = response_data['tgt']

             session_key = response_data['encrypted_session_key']

             print(session_key)
        print('')
        print(encrypted_ticket)
        loaded_signature = session_key
        message = encrypted_ticket
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

            subprocess.run(['python', '2.py',username,password])

            import book_manager
            #subprocess.run(['python', 'book_manager.py'])
            print("成功登录")

        except:
            print("签名验证失败！消息未被篡改。")





        return response_data


if __name__ == '__main__':
    app = QApplication([])
    # create_database()
    login_window = LoginWindow()
    login_window.show()
    app.exec_()
