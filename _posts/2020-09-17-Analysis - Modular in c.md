---
title: Analysis - Modulo in C
categories:
 - analysis, reversing
tags: analysis, c, reversing
---

- Introduction
- Analysis
- Exploit
- slv.py
- 느낀 점
- Reference



# Introduction

ida가 없는 환경에서 peda로 리버싱을 하면서 종종 희안한 연산을 하는 경우가 보였다. 

나중에 알고보니 나머지 연산을 하는 작업인것을 알게되었고 분석을 해보자고 결심하다가 지금 와서야 진행한다.


# Analysis


`test.c` source code

```c
#include <stdio.h>

int main(){

        int input;

        scanf("%d",  &input);

        printf("%d", input%10);
        return 0;
}
```

`test.c` assembly code

```

linux 64bit
    
    0x00000000004005c7 <+0>:     push   rbp
    0x00000000004005c8 <+1>:     mov    rbp,rsp
    0x00000000004005cb <+4>:     sub    rsp,0x10
    0x00000000004005cf <+8>:     mov    rax,QWORD PTR fs:0x28
    0x00000000004005d8 <+17>:    mov    QWORD PTR [rbp-0x8],rax
    0x00000000004005dc <+21>:    xor    eax,eax
    0x00000000004005de <+23>:    lea    rax,[rbp-0xc]
    0x00000000004005e2 <+27>:    mov    rsi,rax
    0x00000000004005e5 <+30>:    lea    rdi,[rip+0xe8]        # 0x4006d4
    0x00000000004005ec <+37>:    mov    eax,0x0
    0x00000000004005f1 <+42>:    call   0x4004d0 <__isoc99_scanf@plt>
    0x00000000004005f6 <+47>:    mov    ecx,DWORD PTR [rbp-0xc]
    0x00000000004005f9 <+50>:    mov    edx,0x66666667
    0x00000000004005fe <+55>:    mov    eax,ecx
    0x0000000000400600 <+57>:    imul   edx
    0x0000000000400602 <+59>:    sar    edx,0x2
    0x0000000000400605 <+62>:    mov    eax,ecx
    0x0000000000400607 <+64>:    sar    eax,0x1f
    0x000000000040060a <+67>:    sub    edx,eax
    0x000000000040060c <+69>:    mov    eax,edx
    0x000000000040060e <+71>:    shl    eax,0x2
    0x0000000000400611 <+74>:    add    eax,edx
    0x0000000000400613 <+76>:    add    eax,eax
    0x0000000000400615 <+78>:    sub    ecx,eax
    0x0000000000400617 <+80>:    mov    edx,ecx
    0x0000000000400619 <+82>:    mov    esi,edx
    0x000000000040061b <+84>:    lea    rdi,[rip+0xb2]        # 0x4006d4
    0x0000000000400622 <+91>:    mov    eax,0x0
    0x0000000000400627 <+96>:    call   0x4004c0 <printf@plt>
    0x000000000040062c <+101>:   mov    eax,0x0
    0x0000000000400631 <+106>:   mov    rsi,QWORD PTR [rbp-0x8]
    0x0000000000400635 <+110>:   xor    rsi,QWORD PTR fs:0x28
    0x000000000040063e <+119>:   je     0x400645 <main+126>
    0x0000000000400640 <+121>:   call   0x4004b0 <__stack_chk_fail@plt>
    0x0000000000400645 <+126>:   leave  
    0x0000000000400646 <+127>:   ret   
    

linux 32bit
    
    0x080484d6 <+0>:     lea    ecx,[esp+0x4]
    0x080484da <+4>:     and    esp,0xfffffff0
    0x080484dd <+7>:     push   DWORD PTR [ecx-0x4]
    0x080484e0 <+10>:    push   ebp
    0x080484e1 <+11>:    mov    ebp,esp
    0x080484e3 <+13>:    push   ebx
    0x080484e4 <+14>:    push   ecx
    0x080484e5 <+15>:    sub    esp,0x10
    0x080484e8 <+18>:    call   0x8048410 <__x86.get_pc_thunk.bx>
    0x080484ed <+23>:    add    ebx,0x1b13
    0x080484f3 <+29>:    mov    eax,gs:0x14
    0x080484f9 <+35>:    mov    DWORD PTR [ebp-0xc],eax
    0x080484fc <+38>:    xor    eax,eax
    0x080484fe <+40>:    sub    esp,0x8
    0x08048501 <+43>:    lea    eax,[ebp-0x10]
    0x08048504 <+46>:    push   eax
    0x08048505 <+47>:    lea    eax,[ebx-0x19f0]
    0x0804850b <+53>:    push   eax
    0x0804850c <+54>:    call   0x80483a0 <__isoc99_scanf@plt>
    0x08048511 <+59>:    add    esp,0x10
    0x08048514 <+62>:    mov    ecx,DWORD PTR [ebp-0x10]
    0x08048517 <+65>:    mov    edx,0x66666667
    0x0804851c <+70>:    mov    eax,ecx
    0x0804851e <+72>:    imul   edx
    0x08048520 <+74>:    sar    edx,0x2
    0x08048523 <+77>:    mov    eax,ecx
    0x08048525 <+79>:    sar    eax,0x1f
    0x08048528 <+82>:    sub    edx,eax
    0x0804852a <+84>:    mov    eax,edx
    0x0804852c <+86>:    shl    eax,0x2
    0x0804852f <+89>:    add    eax,edx
    0x08048531 <+91>:    add    eax,eax
    0x08048533 <+93>:    sub    ecx,eax
    0x08048535 <+95>:    mov    edx,ecx
    0x08048537 <+97>:    sub    esp,0x8
    0x0804853a <+100>:   push   edx
    0x0804853b <+101>:   lea    eax,[ebx-0x19f0]
    0x08048541 <+107>:   push   eax
    0x08048542 <+108>:   call   0x8048370 <printf@plt>
    0x08048547 <+113>:   add    esp,0x10
    0x0804854a <+116>:   mov    eax,0x0
    0x0804854f <+121>:   mov    ecx,DWORD PTR [ebp-0xc]
    0x08048552 <+124>:   xor    ecx,DWORD PTR gs:0x14
    0x08048559 <+131>:   je     0x8048560 <main+138>
    0x0804855b <+133>:   call   0x80485e0 <__stack_chk_fail_local>
    0x08048560 <+138>:   lea    esp,[ebp-0x8]
    0x08048563 <+141>:   pop    ecx
    0x08048564 <+142>:   pop    ebx
    0x08048565 <+143>:   pop    ebp
    0x08048566 <+144>:   lea    esp,[ecx-0x4]
    0x08048569 <+147>:   ret    
```

32bit, 64bit 둘다 scanf가 끝난뒤 특이한 연산을 하는 것을 볼 수 있다.

```asm
    mov    ecx,DWORD PTR [rbp-0xc]
    mov    edx,0x66666667
    mov    eax,ecx
    imul   edx
    sar    edx,0x2
    mov    eax,ecx
    sar    eax,0x1f
    sub    edx,eax
    mov    eax,edx
    shl    eax,0x2
    add    eax,edx
    add    eax,eax
    sub    ecx,eax
    mov    edx,ecx
```

edx = (0x66666667 * input) / 0x100000000


eax = (0x66666667 * input) & 0xffffffff
