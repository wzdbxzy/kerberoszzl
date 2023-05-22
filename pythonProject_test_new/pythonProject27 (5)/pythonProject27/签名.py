from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
with open('rsa_public_key.pem', 'rb') as f:
    public_key_data = f.read()
    public_key = load_pem_public_key(public_key_data, default_backend())

# 导入私钥
with open('rsa_private_key.pem', 'rb') as f:
    private_key_data = f.read()
    private_key = load_pem_private_key(private_key_data, password=None, backend=default_backend())
# 密钥生成




# 消息
message = b"Hello, Bob!"

# 哈希
digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(message)
hash_value = digest.finalize()
print(f'hash_value: {hash_value}')
# 加密（数字签名）
signature = private_key.sign(
    hash_value,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
print(f'signature: {signature}')
# 发送消息和签名
# 在实际应用中，需要将消息和签名一起发送给验证方（例如，通过网络传输）

# 验证
# 假设验证方收到了消息 message 和签名 signature
# 验证方需要使用发送方的公钥来验证签名的有效性

# 加载公钥
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
loaded_public_key = load_pem_public_key(public_key_pem, default_backend())

# 加载签名
loaded_signature = signature

# 对消息进行哈希
digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(message)
hash_value = digest.finalize()

# 验证签名
try:
    loaded_public_key.verify(
        loaded_signature,
        hash_value,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("签名验证成功！消息未被篡改。")
except Exception:
    print("签名验证失败！消息可能已被篡改或签名无效。")