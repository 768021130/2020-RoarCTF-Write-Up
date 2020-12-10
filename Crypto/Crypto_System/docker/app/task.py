from Crypto.Util.number import long_to_bytes, bytes_to_long, getStrongPrime
from gmpy2 import powmod, mpz, invert
import os, random, string, hashlib, re, SocketServer
from binascii import hexlify, unhexlify
from flag import flag

class Task(SocketServer.StreamRequestHandler):
    def recvline(self, keepends=False):
        try:
            msg = self.rfile.readline().strip()
            if keepends == False:
                msg = msg.strip("\n")
            return msg
        except:
            return None

    def recvhex(self, keepends=False):
        try:
            msg = unhexlify(self.recvline(keepends))
            return msg
        except:
            return None

    def recvsign(self):
        try:
            msg = self.recvline()
            if re.match(r"^\([\d]{1,},[\d]{1,}\)$", msg) != None:
                r,s = eval(re.match(r"^\([\d]{1,},[\d]{1,}\)$", msg).group())
                return r,s
            return None, None
        except:
            return None, None

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

    def int2str(self, data, mode="big"):
        if mode == "little":
            return sum([ord(data[_]) * 2 ** (8 * _) for _ in range(len(data))])
        elif mode == "big":
            return sum([ord(data[::-1][_]) * 2 ** (8 * _) for _ in range(len(data))])

    def get_parameter(self, m):
        x = self.int2str(m, 'little')
        y = powmod(self.g, x, self.p)
        a = bytes_to_long(hashlib.sha256(long_to_bytes(y).rjust(128, "\0")).digest())
        b = powmod(a, a, self.p - 1)
        h = powmod(self.g, b, self.p)

        return y, h, b

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

    def sign(self, m):
        y, h, b = self.get_parameter(m)
        r = getStrongPrime(512)
        s = (y * powmod(h, r, self.p)) % self.p 

        return str(r),str(s)

    def verify(self, m, r, s):
        y, h, b = self.get_parameter(m)
        if s == ((y * powmod(h, r, self.p)) % self.p):
            return True
        else:
            return False

    def get_message(self):
        while True:
            random.seed(os.urandom(32))
            m1 = "".join([random.choice(string.printable[:-5]) for _ in range(64)])
            y1, h1, b1 = self.get_parameter(m1)
            m2 = "".join([random.choice(string.printable[:-5]) for _ in range(64)])
            y2, h2, b2 = self.get_parameter(m2)
            x1 = self.int2str(m1, 'little')
            x2 = self.int2str(m2, 'little')

            r2 = ((x1 - x2 + b1 * self.r1) * invert(b2, self.q) % self.q)
            if (y1 * powmod(h1, self.r1, self.p) % self.p) == (y2 * powmod(h2, r2, self.p) % self.p):
                self.m1 = m1
                self.m2 = m2
                return

    def gens(self):
        self.p = 12039102490128509125925019010000012423515617235219127649182470182570195018265927223
        self.q = 1039300813886545966418005631983853921163721828798787466771912919828750891
        self.g = 10729072579307052184848302322451332192456229619044181105063011741516558110216720725
        self.r1 = getStrongPrime(512)
        self.get_message()
        y1, h1, b1 = self.get_parameter(self.m1)
        self.s1 = y1 * powmod(h1, self.r1, self.p) % self.p

    def handle(self):
        if not self.proof_of_work():
            self.close("Error Hash!")
            return

        menu = '''
Crypto System:
    1. Sign message
    2. Verify Signature
    3. Getflag

You have only %d times to operate!
Please choice your options:'''

        time = 5

        self.gens()
        
        self.send("Hello! Here is my another Crypto System! It's very safe and no one can exploit!")
        self.send("But if you can exploit it in 5 times, I will give what you want!")
        self.send("Here is the frist message(64 bytes):%s" % hexlify(self.m1))
        self.send("Here is the second message(64 bytes):%s" % hexlify(self.m2))
        self.send("The frist message's 'r':%s" % str(self.r1))
        self.send("So~Have fun with it ~ (*^_^*)")

        try:
            while time > 0:
                    self.send(menu % time, False)
                    option = self.recvline()
                    if option == "1":
                        time -= 1
                        self.send("Please input the message(hex):", False)
                        m = self.recvhex()
                        if m == None:
                            self.send("Error message!")
                            continue

                        r, s = self.sign(m)
                        self.send("Signature:(%s,%s)" % (r, s))

                    elif option == "2":
                        time -= 1
                        self.send("Please input the message(hex):", False)
                        m = self.recvhex()
                        if m == None:
                            self.send("Error message!")
                            continue

                        self.send("Please input the signature(r,s):", False)
                        r, s = self.recvsign()
                        if r == None or s == None:
                            self.send("Error signature!")
                            continue

                        if self.verify(m, r, s):
                            self.send("Verify Success!")
                        else:
                            self.send("Verify Failed!")

                    elif option == "3":
                        time -= 1
                        self.send("So~Show me you have enough qualifications to get flag!")
                        self.send("Please give me the (r,s) of the second message:", False)
                        r2, s2 = self.recvsign()
                        if r2 == None or s2 == None:
                            self.send("Error signature!")
                            continue

                        if r2 == self.r1 or s2 != self.s1:
                            self.close("No No No!")
                            continue
                        if self.verify(self.m2, r2, s2):
                            self.close("Congratulation!Here is your flag: %s" % flag)
                            return
                        else:
                            self.close("You are kidding me?")
                            continue
                    else:
                        self.close("Error option!")
                        continue

            self.close("Time over!")
            return
        except:
            self.close("Something Error!")
            return

class ForkedServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

if __name__ == '__main__':
    HOST, PORT = '0.0.0.0', int(os.getenv('PORT'))
    server = ForkedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()
