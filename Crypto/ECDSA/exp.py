from gmpy2 import invert
from hashlib import sha256, sha1
from pwn import *
import string, random
import ecdsa

context(os="linux", arch="amd64", log_level="debug")

HOST = "127.0.0.1"
PORT = 10305

r = remote(HOST, PORT)

def getHash(salt, result):
	characters = string.ascii_letters+string.digits

	for c1 in characters:
		for c2 in characters:
			for c3 in characters:
				for c4 in characters:
					proof = c1 + c2 + c3 + c4 
					if sha256(proof+salt).hexdigest() == result:
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
	msg1 = recv()[-64:]
	msg2 = recv()[-64:]
	return msg1, msg2

def calculator(msg1, msg2):
	curve = ecdsa.curves.SECP256k1
	G = curve.generator
	n = G.order()

	r = 0 
	while r == 0:
		random_k = ecdsa.util.randrange(n)
		k = random_k % n
		ks = k + n
		kt = ks + n
		if ecdsa.util.bit_length(ks) == ecdsa.util.bit_length(n):
			p1 = kt * G
		else:
			p1 = ks * G
		r = p1.x() % n

	h1 = ecdsa.util.string_to_number(sha1(msg1).digest()) % n
	h2 = ecdsa.util.string_to_number(sha1(msg2).digest()) % n

	x = ((-(h1 + h2)) * invert(2*r, n)) % n
	prikey = ecdsa.SigningKey.from_secret_exponent(x, ecdsa.curves.SECP256k1, hashfunc=sha1)
	pubkey = prikey.get_verifying_key()

	send("Please choice your options:", "3")
	send("Please give me your public_key(hex):", pubkey.to_string().encode('hex'))

	sign = prikey.sign(msg1, k = k)

	send("Please choice your options:", "5")
	send("Please give me the message(hex):", msg1.encode('hex'))
	send("Please give me the signature(hex):", sign.encode('hex'))
	if "Verify successfully!" in recv():
		print ("msg1 verify successfully!")

	send("Please choice your options:", "5")
	send("Please give me the message(hex):", msg2.encode('hex'))
	send("Please give me the signature(hex):", sign.encode('hex'))
	if "Verify successfully!" in recv():
		print ("msg2 verify successfully!")

	send("Please choice your options:", "6")
	send("Please give me the signature(hex) of the frist message:", sign.encode('hex'))
	send("Please give me the signature(hex) of the second message:", sign.encode('hex'))


def main():
	sendHash()
	msg1, msg2 = getMessage()
	calculator(msg1, msg2)
	r.recvuntil("}")
	r.close()

if __name__ == '__main__':
	main()