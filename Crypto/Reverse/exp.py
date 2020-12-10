from gmpy2 import *
import binascii

'''
x : number to reverse
n : bits need to reverse
'''
def reverse(x,n):
	y = 0
	for i in range(n):
		y = y * 2 + x % 2
		x = x // 2
	return y

n = 158985980192501034004997692253209315116841431063210516613522548452327355222295231366801286879768949611058043390843949610463241574886852164907094966008463721486557469253652940169060186477803255769516068561042756903927308078335838348784208212701919950712557406983012026654876481867000537670622886437968839524889
enc = 103728452309804750381455306214814700768557462686461157761076359181984554990431665209165298725569861567865645228742739676539208228770740802323555281253638825837621845841771677911598039696705908004858472132222470347720085501572979109563593281375095145984000628623881592799662103680478967594601571867412886606745

res = []
for pl in range(1,4096,2):
	ql = invert(pl,4096)*(n%4096) % 4096

	if (ql*pl)%4096 == n%4096:
		qh = reverse(ql,12)
		ph = reverse(pl,12)
		min = (ph*qh) << 1000
		max = ((ph+1)*(qh+1)) << 1000

		if min <= n < max:
			res.append(pl)

for c in range(13,257):
	t_res = []
	mod = 2**c
	for x in res:
		for y in range(2):
			pl = x + (y*2)**(c-1)
			ql = (invert(pl, mod)*(n%mod)) % mod
			if (ql*pl)%mod == n%mod:
				qh = reverse(ql,c)
				ph = reverse(pl,c)
				min = ph*qh << (1024 - c*2)
				max = (ph+1)*(qh+1) << (1024 - c*2)

				if min <= n < max:
					t_res.append(pl)
	res = t_res

mod = 2**256

for pl in res:
    ql = invert(pl,mod)*(n%mod)%mod
    if ql*pl%mod==n%mod:
	    qh=reverse(ql,c)
	    ph=reverse(pl,c)
	    p=qh<<256|pl
	    q=ph<<256|ql
	    if p*q==n:
	        print("Find it!")
	        break

e=65537
d=invert(e,(p-1)*(q-1))
o=pow(enc,d,p*q)
print(binascii.unhexlify(hex(o)[2:]))

