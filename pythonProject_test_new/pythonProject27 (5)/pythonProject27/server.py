import socket

# 定义全局变量
SERVER_HOST = '127.0.0.1'  # 服务器的主机名
SERVER_PORT = 5002  # 服务器的端口号

# 服务器逻辑
def server():
    # 监听服务器的端口
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(1)
    print(f'Server listening on {SERVER_HOST}:{SERVER_PORT}')

    while True:
        # 接受客户端连接
        client_socket, address = server_socket.accept()
        print(f'Connection from {address[0]}:{address[1]}')

        # 接收客户端发送的请求报文
        request = client_socket.recv(1024).decode()

        # 验证请求报文中的服务器票据的有效性和合法性
        if validate_server_ticket(request):
            # 向客户端发送访问资源的响应
            response = 'Access granted.'
            client_socket.sendall(response.encode())
        else:
            response = 'Access denied.'
            client_socket.sendall(response.encode())

        # 关闭客户端连接
        client_socket.close()

# 验证请求报文中的服务器票据的有效性和合法性
def validate_server_ticket(request):
    server_ticket = request.split(':')[1]
    return server_ticket.endswith(b'SERVER_SESSION_KEY')


if __name__ == '__main__':
    server()