#encoding:utf-8
from flag import flag
import os, hashlib, SocketServer, string, random, gmpy2

import ecdsa
from Crypto.Util.number import *
from binascii import hexlify, unhexlify

class Task(SocketServer.StreamRequestHandler):
    def recvline(self, keepends=False):
        try:
            msg = self.rfile.readline().strip()
            if keepends == False:
                msg = msg.strip("\n")
            return msg
        except:
            return ""

    def recvhex(self, keepends=False):
        try:
            msg = unhexlify(self.recvline(keepends))
            return msg
        except:
            pass

    def send(self, msg, keepends=True):
        try:
            if keepends:
                msg += "\n"
            self.request.sendall(msg)
        except:
            pass

    def sendhex(self, msg, keepends=True):
        try:
            self.send(hexlify(msg),keepends)
        except:
            pass

    def close(self, msg="ByeBye~"):
        if msg != "":
            self.send(msg)
        self.request.close()

    def proof_of_work(self):
        random.seed(os.urandom(8))
        proof = ''.join([random.choice(string.ascii_letters+string.digits) for _ in range(20)])
        result = hashlib.sha256(proof.encode('utf-8')).hexdigest()
        self.send("sha256(XXXX+%s) == %s" % (proof[4:],result))
        self.send('Give me XXXX:', False)
        x = self.recvline()
        if len(x) != 4 or hashlib.sha256((x+proof[4:])).hexdigest() != result: 
            return False
        return True

    def check_pubkey(self):
        # some pubkey ban!
        kr = [
        23372277234339732161528747619365498567249265222314495344099167639942101343337,
        62989355795745825677369439151540305092688296085552748840426443415018825446751,
        102176488713106866729244489891800273707111684637333927422310632936926394909791,
        66026435594671246144455917653969878330516005938452458352675649432987691640403,
        60730812236616172787517035001217259162269567592297306744057974796596985795327,
        71328054460578775795694147762085433423176885373923858840989993639076850308439,
        93684048965156849800818708327961353410079934271916420484653001940861477448163,
        100326506095047235454839840513007253310251332944606271809085596226294285260781,
        62734374738717668543020765811060232131852338490779163456413910646914798815181,
        76742788961507631670196255233793091374331144891380587410344970915201815293841,
        26051942604083573721888147565541164362481608836273532438992420790865901064629,
        34199028958826561674909965615754760982597207585888972986563178047900111405589,
        20098678567304734068592836718761264766330414460259761501002904519465930599651
        ]

        ban_pubkey = []

        for r in kr:
            curve = ecdsa.curves.SECP256k1
            G = curve.generator
            n = G.order()
            h1 = ecdsa.util.string_to_number(hashlib.sha1(self.message1).digest()) % n
            h2 = ecdsa.util.string_to_number(hashlib.sha1(self.message2).digest()) % n

            x = ((-(h1 + h2)) * gmpy2.invert(2*r, n)) % n
            prikey = ecdsa.SigningKey.from_secret_exponent(x, ecdsa.curves.SECP256k1, hashfunc=hashlib.sha1)
            pubkey = hexlify(prikey.get_verifying_key().to_string())

            ban_pubkey.append(pubkey)

        return ban_pubkey

    def check(self, pubkey):
        if hexlify(pubkey) in self.ban_pubkey:
            return True
        return False

    def show(self):
        self.send("Your public_key is: %s " % hexlify(self.h.to_string()))

    def generate(self):
        self.x = ecdsa.SigningKey.generate(curve = self.curveName)
        self.h = self.x.get_verifying_key()
        self.send("Generate finished!Now your pubkey is (hex encode):%s" % hexlify(self.h.to_string()))

    def update(self):
        self.send("Please give me your public_key(hex):", False)
        pubkey = self.recvhex()

        if self.check(pubkey):
            self.send("I know how you got this pubkey! No way~")
        else:
            try:
                self.h = self.h.from_string(pubkey, curve = self.curveName)
                self.send("Update finished!Now your public_key is: %s" % hexlify(self.h.to_string()))
            except:
                self.send("The Point isn't in this curve! Try another~")

    def sign(self):
        self.send("Please give me the message(hex):", False)
        msg = self.recvhex()
        sign = hexlify(self.x.sign(msg))
        self.send("Signature(hex): %s" % sign)

    def verify(self):
        self.send("Please give me the message(hex):", False)
        msg = self.recvhex()
        self.send("Please give me the signature(hex):", False)
        sign = self.recvhex()

        try:
            if self.h.verify(sign, msg):
                self.send("Verify successfully!")
            else:
                self.send("Verify failed!")
        except:
            self.send("Verify error!")

    def exploit(self):
        self.send("Please give me the signature(hex) of the frist message:")
        sign1 = self.recvhex()
        self.send("Please give me the signature(hex) of the second message:")
        sign2 = self.recvhex()

        if sign1 != sign2:
            self.send("Are you kidding me?")
            return
        try:
            if self.h.verify(sign1, self.message1) and self.h.verify(sign2, self.message2):
                self.send("Congratulations!Here is your flag:%s" % flag)
                return
            else:
                self.send("Exploit it failed!How is it impossible? Haaaaaaaaa~")
                return 
        except:
            self.send("Verify error!")
            return 

    def handle(self):
        if not self.proof_of_work():
            self.close("Error Hash!")
            return
        
        menu = '''
ECC Signature System:
    1. Show your pubkey
    2. Generate new prikey
    3. Update your pubkey
    4. Sign a message
    5. Verify a message
    6. Exploit
    7. Exit

You have only %d times to operate!
Please choice your options:'''

        time = 10

        self.curveName = ecdsa.SECP256k1
        self.x = ecdsa.SigningKey.generate(curve = self.curveName) # private_key
        self.h = self.x.get_verifying_key() # public_key
        random.seed(os.urandom(64))
        self.message1 = "".join(random.sample(string.printable[:-5], 64))
        random.seed(os.urandom(64))
        self.message2 = "".join(random.sample(string.printable[:-5], 64))

        self.ban_pubkey = self.check_pubkey()

        self.send("Hello,guys!Welcome to my ECC Signature System!I promise no one can exploit it!")
        self.send("Howevers if you can exploit it in 10 times,I will give what you want!")
        self.send("Here is the frist message(64 bytes):%s" % self.message1)
        self.send("Here is the second message(64 bytes):%s" % self.message2)
        self.send("Try to calculate the same signature for this two messages~")
        self.send("(((Notice: curve = SECP256k1, hashfunc = sha1)))")

        while time > 0:
            try:
                self.send(menu % time, False)
                option = self.recvline()
                if option == "1":
                    time -= 1
                    self.show()
                elif option == "2":
                    time -= 1
                    self.generate()

                elif option == "3":
                    time -= 1
                    self.update()

                elif option == "4":
                    time -= 1
                    self.sign()

                elif option == "5":
                    time -= 1
                    self.verify()

                elif option == "6":
                    time -= 1
                    self.exploit()
                    return

                elif option == "7":
                    self.close("ByeBye~")
                    return

                else:
                    time -= 1
                    self.send("Error option!")

            except:
                self.close("Something error unexpected!")
                return 

        self.close("Time over!")
        return 


class ForkedServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

if __name__ == '__main__':
    HOST = "0.0.0.0"
    PORT = int(os.getenv('PORT'))
    server = ForkedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()
