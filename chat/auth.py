from chat.models import User
from hashlib import sha256
from secrets import randbits, randbelow
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
from django.conf import settings
import json
from base64 import b64encode, b64decode
import hashlib
import hmac
from typing import Tuple
from Crypto.Protocol.KDF import PBKDF2


def sha256(data: str | bytes) -> str:
    m = hashlib.sha256()
    if type(data) is str:
        data = data.encode()
    m.update(data)
    return m.hexdigest()

def verify(username: str, password: str) -> int:
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return -1

    if sha256(password + user.salt) == user.passwordHash:
        return 1
    else:
        return 0

def validateUsername(username: str) -> bool:
    try:
        User.objects.get(username=username)
        return False
    except User.DoesNotExist:
        return True

def validatePassword(password: str) -> bool:
    return len(password) <= 100

def saltgen() -> str:
    return long_to_bytes(randbits(128)).hex()

def pvtkeygen() -> int:
    pvtkey = 0
    while pvtkey <= 1:
        pvtkey = randbelow(settings.N-1)
    return randbelow(pvtkey)

def addUser(username: str, name: str, password: str) -> None:

    if not validateUsername(username) or not validatePassword(password):
        return

    salt = saltgen()

    passwordHash = sha256(password+salt)

    pvtkey = pvtkeygen()
    
    pvtkeyhash = sha256(str(pvtkey).encode())

    pvtkeyhex = long_to_bytes(pvtkey).hex()

    key = PBKDF2(password, salt, 16, 1000)

    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(pvtkeyhex.encode())
    
    user = User(
        username = username,
        name = name,
        passwordHash = passwordHash,
        salt = salt,
        pvtkeyhash = pvtkeyhash,
        aesciphertext = ciphertext.hex(),
        aesnonce = nonce.hex(),
        aestag = tag.hex(),
        gpowerkey = str(pow(settings.G, pvtkey, settings.N))
    )

    user.save()

def getUser(username: str, password: str) -> dict:

    user = User.objects.get(username=username)
    userinfo = dict()

    key = PBKDF2(password, user.salt, 16, 1000)
    cipher = AES.new(key, AES.MODE_EAX, nonce = bytes.fromhex(user.aesnonce))
    pvtkeyhex = cipher.decrypt(bytes.fromhex(user.aesciphertext))
    pvtkey = bytes_to_long(bytes.fromhex(pvtkeyhex.decode()))

    # cipher.verify(bytes.fromhex(user.aestag))

    userinfo['username'] = user.username
    userinfo['name'] = user.name
    userinfo['pvtkey'] = pvtkey
    userinfo['N'] = settings.N
    userinfo['G'] = settings.G

    return userinfo

def signJWT(dic: dict) -> str:
    a = b64encode(json.dumps({'type':'JWT', 'alg':'HS256'}).encode()).decode()
    b = b64encode(json.dumps(dic).encode()).decode()
    c = b64encode(hmac.new(
            key = settings.JWT_SECRET.encode(),
            msg = f'{a}.{b}'.encode(),
            digestmod = hashlib.sha256
        ).hexdigest().encode()).decode()
    
    jwt = f'{a}.{b}.{c}'
    
    return jwt


def verifyJWT(jwt: str) -> Tuple[bool, dict]:
    try:
        a, b, c = jwt.split('.')
    except ValueError:
        return False, {}
    c2 = b64encode(hmac.new(
            key = settings.JWT_SECRET.encode(),
            msg = f'{a}.{b}'.encode(),
            digestmod = hashlib.sha256
        ).hexdigest().encode()).decode()
    
    if c != c2:
        return False, {}
    
    dic = json.loads(b64decode(b.encode()).decode())

    return True, dic

def getgpowerkey(username: str):
    user = User.objects.get(username=username)
    return int(user.gpowerkey)




    




    
    
    
