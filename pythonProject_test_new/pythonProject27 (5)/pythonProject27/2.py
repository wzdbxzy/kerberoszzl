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

# 访问命令行参数
username = sys.argv[1]
password = sys.argv[2]
#username = '123'
#password = '123'
# 定义全局变量
AS_HOST = '127.0.0.1'  # AS的主机名
AS_PORT = 5005  # AS的端口号
TGS_HOST = '127.0.0.1'  # TGS的主机名
TGS_PORT = 5001  # TGS的端口号
SERVER_HOST = '127.0.0.1'  # 服务器的主机名
SERVER_PORT = 5002  # 服务器的端口号


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

class BookManager(QMainWindow):
    def __init__(self):
        super().__init__()
        # 设置窗口标题和大小
        self.setWindowTitle("图书管理系统")
        self.setGeometry(300, 200, 700, 400)

        # 添加组件
        self.titleLabel = QLabel("书名:")
        self.titleEdit = QLineEdit()
        self.authorLabel = QLabel("作者:")
        self.authorEdit = QLineEdit()
        self.publisherLabel = QLabel("出版社:")
        self.publisherEdit = QLineEdit()
        self.priceLabel = QLabel("价格:")
        self.priceEdit = QLineEdit()
        self.pubDateLabel = QLabel("出版日期:")
        self.pubDateEdit = QLineEdit()
        self.addButton = QPushButton("添加图书")
        self.queryButton = QPushButton("查询图书")
        self.deleteButton = QPushButton("删除图书")
        self.bookTable = QTableWidget()

        # 设置表格列数和列名
        self.bookTable.setColumnCount(6)
        self.bookTable.setHorizontalHeaderLabels(["编号", "书名", "作者", "出版社", "价格", "出版日期"])
        self.bookTable.setEditTriggers(QTableWidget.NoEditTriggers)  # 设置表格不可编辑

        # 设置组件字体大小
        font = QFont()
        font.setPointSize(12)
        self.titleLabel.setFont(font)
        self.authorLabel.setFont(font)
        self.publisherLabel.setFont(font)
        self.priceLabel.setFont(font)
        self.pubDateLabel.setFont(font)
        self.addButton.setFont(font)
        self.queryButton.setFont(font)
        self.deleteButton.setFont(font)

        # 添加组件到窗口
        widget = QWidget(self)
        self.setCentralWidget(widget)
        vbox = QVBoxLayout(widget)
        hbox1 = QHBoxLayout()
        hbox1.addWidget(self.titleLabel)
        hbox1.addWidget(self.titleEdit)
        hbox1.addWidget(self.authorLabel)
        hbox1.addWidget(self.authorEdit)
        hbox2 = QHBoxLayout()
        hbox2.addWidget(self.publisherLabel)
        hbox2.addWidget(self.publisherEdit)
        hbox2.addWidget(self.priceLabel)
        hbox2.addWidget(self.priceEdit)
        hbox3 = QHBoxLayout()
        hbox3.addWidget(self.pubDateLabel)
        hbox3.addWidget(self.pubDateEdit)
        hbox4 = QHBoxLayout()
        hbox4.addWidget(self.addButton)
        hbox4.addWidget(self.queryButton)
        hbox4.addWidget(self.deleteButton)
        vbox.addLayout(hbox1)
        vbox.addLayout(hbox2)
        vbox.addLayout(hbox3)
        vbox.addLayout(hbox4)
        vbox.addWidget(self.bookTable)

        # 绑定按钮事件
        self.addButton.clicked.connect(self.add_book)
        self.queryButton.clicked.connect(self.query_book)
        self.deleteButton.clicked.connect(self.delete_book)

    def add_book(self):
        # 获取用户输入的图书信息
        title = self.titleEdit.text()
        author = self.authorEdit.text()
        publisher = self.publisherEdit.text()
        price = self.priceEdit.text()
        pub_date = self.pubDateEdit.text()
        as_response = self.authenticate_with_as(username, password)
        if as_response is None:
            print('wode')
            return

        print(as_response)
        server_response = self.request_server_access(as_response)
        if server_response is None:
            return

        # 打印服务器的响应
        print(f'Server Response: {server_response}')
        server_response1 = self.request_server_access1(server_response,title, author, publisher, price, pub_date)
        if server_response1 is None:
            return

        # 将图书信息插入到数据库中


        # 刷新图书列表
        self.query_book()

    def query_book(self):

        # 查询所有图书信息
        conn = sqlite3.connect('bookstore.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM books")
        books = cursor.fetchall()
        conn.close()

        # 在表格中显示查询结果
        self.bookTable.setRowCount(len(books))
        for i in range(len(books)):
            row = books[i]
            self.bookTable.setItem(i, 0, QTableWidgetItem(str(row[0])))
            self.bookTable.setItem(i, 1, QTableWidgetItem(row[1]))
            self.bookTable.setItem(i, 2, QTableWidgetItem(row[2]))
            self.bookTable.setItem(i, 3, QTableWidgetItem(row[3]))
            self.bookTable.setItem(i, 4, QTableWidgetItem(str(row[4])))
            self.bookTable.setItem(i, 5, QTableWidgetItem(row[5]))

    def delete_book(self):
        # 获取用户选中的图书编号
        selected = self.bookTable.selectedItems()
        if selected:
            book_id = selected[0].text()
            as_response = self.authenticate_with_as(username, password)
            if as_response is None:
                print('wode')
                return

            print(as_response)
            server_response = self.request_server_access(as_response)
            if server_response is None:
                return

            # 打印服务器的响应
            print(f'Server Response: {server_response}')
            server_response1 = self.request_server_access2(server_response, book_id)
            if server_response1 is None:
                return

            # 删除对应的图书信息


            # 刷新图书列表
            self.query_book()
        else:
            QMessageBox.warning(self, "警告", "请选择要删除的图书！")

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

    def request_server_access1(self, encrypted_server_ticket,title, author, publisher, price, pub_date):

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
        message2 = message + b',zeng'
        # 哈希
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(message2)
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
        message1=self.encrypt_des(message2, session_key)
        response = pickle.dumps({'zeng': message1, 'encrypted_session_key': signature1,'key': session_key,'title':title,'author':author,'publisher':publisher,'price':price,'pub_date':pub_date,})
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
        print('des解密前的tgt')
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
            sys.exit()
            subprocess.run(['python', 'book_manager.py'])
        except:
          print("签名验证失败！消息可能被篡改。")





        return response_data

    def request_server_access2(self, encrypted_server_ticket, title):

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
        message2 = message + b',shan'
        # 哈希
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(message2)
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
        signature1 = self.encrypt_des(signature, session_key)
        # 发送消息和签名
        # 在实际应用中，需要将消息和签名一起发送给验证方（例如，通过网络传输）
        message1 = self.encrypt_des(message2, session_key)
        response = pickle.dumps(
            {'shan': message1, 'encrypted_session_key': signature1, 'key': session_key, 'title': title })
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
        print('des解密前的tgt')
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
            sys.exit()
            subprocess.run(['python', 'book_manager.py'])
        except:
            print("签名验证失败！消息可能被篡改。")

        return response_data
# 启动应用程序
if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = BookManager()
    ex.show()
    sys.exit(app.exec_())