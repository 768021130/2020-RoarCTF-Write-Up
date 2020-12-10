from gmpy2 import *
from Crypto.Util.number import *

n=17986052241518124152579698727005505088573670763293762110375836247355612011054569717338676781772224186355540833136105641118789391002684013237464006860953174190278718294774874590936823847040556879723368745745863499521381501281961534965719063185861101706333863256855553691578381034302217163536137697146370869852180388385732050177505306982196493799420954022912860262710497234529008765582379823928557307038782793649826879316617865012433973899266322533955187594070215597700782682186705964842947435512183808651329554499897644733096933800570431036589775974437965028894251544530715336418443795864241340792616415926241778326529055663
e=65537
enc=10760807485718247466823893305767047250503197383143218026814141719093776781403513881079114556890534223832352132446445237573389249010880862460738448945011264928270648357652595432015646424427464523486856294998582949173459779764873664665361437483861277508734208729366952221351049574873831620714889674755106545281174797387906705765430764314845841490492038801926675266705606453163826755694482549401843247482172026764635778484644547733877083368527255145572732954216461334217963127783632702980064435718785556011795841651015143521512315148320334442235923393757396733821710592667519724592789856065414299022191871582955584644441117223
beta=11864389277042761216996641604675717452843530574016671576684180662096506094587545173005905433938758559675517932481818900399893444422743930613073261450555599

tip = (n-1)/(beta)
u = tip/(beta)
v = tip%(beta)

def solve_c():
	sqrt_n = iroot(mpz(n),2)[0]
	C = div(sqrt_n,pow(beta,2))

	x = 2
	y = powmod(x,beta,n)
	for i in range(2,C):
		D = (iroot(C,2)[0] + 1) * i

		final = powmod(y,u,n)
		for r in range(D):
			for s in range(D):
				if powmod(y,r*D+s,n) == final: # r = 31 s = 18 i = 2
					print "r =",r,"s =",s,"i =",i
					return r * D + s

c = solve_c() # c: 1940
print "c:",c 
A = u - c 
B = v + c*beta 

delta = iroot((B*B-4*A),2)[0]
x = (B+delta)/2
y = (B-delta)/2

a = x/2
b = y/2

p = 2*beta*a + 1
q = 2*beta*b + 1

d = invert(e,(p-1)*(q-1))
m = powmod(enc,d,n)
print long_to_bytes(m)