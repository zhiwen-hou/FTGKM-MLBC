# 根据ganache的私钥生成对应的公钥

from brownie import config
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
import binascii


SELF_PUBLIC_KEYS = []


def my_generate(num="00", chain_name="self"):
    private_key_bytes = binascii.unhexlify(config["keys"][f"private_key_{num}"])
    private_key = ec.derive_private_key(
        int.from_bytes(private_key_bytes, byteorder="big"), ec.SECP256K1()
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            config["keys"]["private_key_password"].encode()
        ),
    )
    file_name = f"./configdata/sec/{chain_name}/privatekey{num}.pem"
    with open(file_name, "wb") as f:
        f.write(private_pem)

    public_key = private_key.public_key()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    file_name = f"./configdata/sec/{chain_name}/publickey{num}.pem"
    with open(file_name, "wb") as f:
        f.write(public_pem)


def my_load_private_key(num="00", chain_name="self"):
    file_name = f"./configdata/sec/{chain_name}/privatekey{num}.pem"
    with open(file_name, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=config["keys"]["private_key_password"].encode(),
        )
    return private_key


def my_load_public_key(num="00", chain_name="self"):
    file_name = f"./configdata/sec/{chain_name}/publickey{num}.pem"
    with open(file_name, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key


def my_get_public_key_bytes(num="00", chain_name="self"):
    file_name = f"./configdata/sec/{chain_name}/publickey{num}.pem"
    with open(file_name, "rb") as key_file:
        public_key_bytes = key_file.read()
    return public_key_bytes


def get_self_chain_public_keys():
    return SELF_PUBLIC_KEYS.copy()


def my_signature(message, private_key):
    if len(message) < 2048:
        sign = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    else:
        chosen_hash = hashes.SHA256()
        hasher = hashes.Hash(chosen_hash)
        hasher.update(message)
        digest = hasher.finalize()
        sign = private_key.sign(digest, ec.ECDSA(utils.Prehashed(chosen_hash)))
    return sign


def my_verify(message, sign, public_key):
    if len(message) < 2048:
        try:
            public_key.verify(sign, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception as e:
            return False
    else:
        try:
            chosen_hash = hashes.SHA256()
            hasher = hashes.Hash(chosen_hash)
            hasher.update(message)
            digest = hasher.finalize()
            public_key.verify(sign, digest, ec.ECDSA(utils.Prehashed(chosen_hash)))
            return True
        except Exception as e:
            return False


def get_public_list(num=4):
    public_key_bytes_list = []
    for i in range(num):
        num = f"0{i}"
        public_key_bytes = my_get_public_key_bytes(num)
        public_key_bytes_list.append(public_key_bytes)

    print(f"public_key_bytes_list={public_key_bytes_list}")
    return public_key_bytes_list


def generate_sec(length=4, chain_name="self"):
    for i in range(length):
        num = f"0{i}"
        my_generate(num, chain_name)
