#encoding:utf-8
from binascii import hexlify, unhexlify
from gmpy2 import *
from Crypto.Util.number import *
from pwn import *
import hashlib, string

context(os="linux",arch="amd64",log_level="debug")

HOST = "127.0.0.1"
PORT = 10306

r = remote(HOST, PORT)

def getHash(salt, result):
	characters = string.ascii_letters+string.digits

	for c1 in characters:
		for c2 in characters:
			for c3 in characters:
				for c4 in characters:
					proof = (c1 + c2 + c3 + c4).encode()
					if hashlib.sha256(proof + salt).hexdigest() == result:
						return proof

def recv(keepends=False):
	return r.recvline(keepends=keepends).strip()

def send(anti, msg):
	r.sendlineafter(anti, msg)

def sendHash():
	context = recv()
	salt = context[12:28]
	result = context[-64:]
	proof = getHash(salt, result)
	send("Give me XXXX:", proof)

def getMessage():
    recv()
    recv()
    m1 = unhexlify(recv()[-128:])
    m2 = unhexlify(recv()[-128:])
    r1 = int(recv().strip("The frist message's 'r':"))
    return m1, m2, r1

def int2str(data, mode="big"):
    if mode == "little":
        return sum([ord(data[_]) * 2 ** (8 * _) for _ in range(len(data))])
    elif mode == "big":
        return sum([ord(data[::-1][_]) * 2 ** (8 * _) for _ in range(len(data))])

def get_parameter(m, g, p):
    x = int2str(m, 'little')
    y = powmod(g, x, p)
    a = bytes_to_long(hashlib.sha256(long_to_bytes(y).rjust(128, "\0")).digest())
    b = powmod(a, a, p - 1)
    h = powmod(g, b, p)

    return y, h, b

def sign(m, g, p, q):
    y, h, b = get_parameter(m, g, p)
    r = getStrongPrime(512)
    s = (y * powmod(h, r, p)) % p 

    return str(r),str(s)

def verify(m, r, s, g, p):
    y, h, b = get_parameter(m, g, p)
    if s == ((y * powmod(h, r, p)) % p):
        return True
    else:
        return False

def calculate(m1, m2, r1):
    p = 12039102490128509125925019010000012423515617235219127649182470182570195018265927223
    q = 1039300813886545966418005631983853921163721828798787466771912919828750891
    g = 10729072579307052184848302322451332192456229619044181105063011741516558110216720725
    x1 = int2str(m1, 'little')
    x2 = int2str(m2, 'little')

    y1, h1, b1 = get_parameter(m1, g, p)
    s1 = int((y1 * powmod(h1, r1, p)) % p)
    assert verify(m1, r1, s1, g, p)
    sign1 = ("(%s,%s)"%(str(r1),str(s1)))
    send('Please choice your options:', "2")
    send('Please input the message(hex):', hexlify(m1))
    send('Please input the signature(r,s):', sign1)
    assert 'Verify Success!' in recv()
    
    y2, h2, b2 = get_parameter(m2, g, p)
    r2 = int(((x1 - x2 + b1 * r1) * invert(b2, q) % q))
    s2 = int(y2 * powmod(h2, r2, p) % p)
    assert verify(m2, r2, s2, g, p)
    sign2 = ("(%s,%s)"%( str(r2),str(s2) ))
    send('Please choice your options:', "2")
    send('Please input the message(hex):', hexlify(m2))
    send('Please input the signature(r,s):', sign2)
    assert 'Verify Success!' in recv()

    assert s1 == s2
    send('Please choice your options:', "3")
    send('Please give me the (r,s) of the second message:', sign2)

def main():
    sendHash()
    m1, m2, r1 = getMessage()
    calculate(m1, m2, r1)
    r.recvuntil("}")
    r.close()

if __name__ == '__main__':
    main()