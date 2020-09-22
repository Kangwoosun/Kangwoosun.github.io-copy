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

gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04) 64bit
    
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
    

gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04) 32bit
    
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

input - ((((0x66666667 * input) / 0x100000000) >> 2) - (input >> 0x1f)) * 6






사무실에서 VS 2015로 동일하게 소스코드 구성해서 진행해본 결과 `idiv`를 사용해서 모듈러를 구현한것을 보았다.


```cpp
#include <iostream>
using namespace std;

int main(){
	
	int input, modulo;
	cin >> input >> modulo;
	
	input = input % modulo;

	cout << input << endl;

	return 0;
}


   0x0000000000400817 <+0>:     push   rbp
   0x0000000000400818 <+1>:     mov    rbp,rsp
   0x000000000040081b <+4>:     sub    rsp,0x10
   0x000000000040081f <+8>:     mov    rax,QWORD PTR fs:0x28
   0x0000000000400828 <+17>:    mov    QWORD PTR [rbp-0x8],rax
   0x000000000040082c <+21>:    xor    eax,eax
   0x000000000040082e <+23>:    lea    rax,[rbp-0x10]
   0x0000000000400832 <+27>:    mov    rsi,rax
   0x0000000000400835 <+30>:    lea    rdi,[rip+0x200944]        # 0x601180 <std::cin@@GLIBCXX_3.4>
   0x000000000040083c <+37>:    call   0x4006d0 <std::istream::operator>>(int&)@plt>
   0x0000000000400841 <+42>:    mov    rdx,rax
   0x0000000000400844 <+45>:    lea    rax,[rbp-0xc]
   0x0000000000400848 <+49>:    mov    rsi,rax
   0x000000000040084b <+52>:    mov    rdi,rdx
   0x000000000040084e <+55>:    call   0x4006d0 <std::istream::operator>>(int&)@plt>
   0x0000000000400853 <+60>:    mov    eax,DWORD PTR [rbp-0x10]
   0x0000000000400856 <+63>:    mov    ecx,DWORD PTR [rbp-0xc]
   0x0000000000400859 <+66>:    cdq    
   0x000000000040085a <+67>:    idiv   ecx
   0x000000000040085c <+69>:    mov    eax,edx
   0x000000000040085e <+71>:    mov    DWORD PTR [rbp-0x10],eax
   0x0000000000400861 <+74>:    mov    eax,DWORD PTR [rbp-0x10]
   0x0000000000400864 <+77>:    mov    esi,eax
   0x0000000000400866 <+79>:    lea    rdi,[rip+0x2007f3]        # 0x601060 <std::cout@@GLIBCXX_3.4>
   0x000000000040086d <+86>:    call   0x400720 <std::ostream::operator<<(int)@plt>
   0x0000000000400872 <+91>:    mov    rdx,rax
   0x0000000000400875 <+94>:    mov    rax,QWORD PTR [rip+0x200764]        # 0x600fe0
   0x000000000040087c <+101>:   mov    rsi,rax
   0x000000000040087f <+104>:   mov    rdi,rdx
   0x0000000000400882 <+107>:   call   0x4006f0 <std::ostream::operator<<(std::ostream& (*)(std::ostream&))@plt>
   0x0000000000400887 <+112>:   mov    eax,0x0
   0x000000000040088c <+117>:   mov    rcx,QWORD PTR [rbp-0x8]
   0x0000000000400890 <+121>:   xor    rcx,QWORD PTR fs:0x28
   0x0000000000400899 <+130>:   je     0x4008a0 <main+137>
   0x000000000040089b <+132>:   call   0x400700 <__stack_chk_fail@plt>
   0x00000000004008a0 <+137>:   leave  
   0x00000000004008a1 <+138>:   ret    
   
   
   
   0x0000000000400853 <+60>:    mov    eax,DWORD PTR [rbp-0x10]
   0x0000000000400856 <+63>:    mov    ecx,DWORD PTR [rbp-0xc]
   0x0000000000400859 <+66>:    cdq    
   0x000000000040085a <+67>:    idiv   ecx
   0x000000000040085c <+69>:    mov    eax,edx
   0x000000000040085e <+71>:    mov    DWORD PTR [rbp-0x10],eax
   0x0000000000400861 <+74>:    mov    eax,DWORD PTR [rbp-0x10]
   0x0000000000400864 <+77>:    mov    esi,eax
   
```



`http://www.openrce.org/blog/view/892/function.session-start`에서 찾아보니
```
couple of things to remember:
Compilers love to work with multiples of 2. The processor can can just shift registers left and right (shifting is incredibly fast, that is moving the contents of a register left or right padding with o or 1 as appropriate). Shifting to the left for multiplication by 2 and towards the right for division by 2 (this is akin to having a number in base 10 and multiplying by 10 by adding zeros to the right and dividing by by removing the rightmost digit).
Compilers hate to use the division instruction. The division takes a lot of steps, or cycles, for the CPU to complete. Hence they will avoid to use it at all cost.

The code looked like this:
(irrelevant interleaved code left out)

mov ecx, [esp+4+arg_4]
mov eax, 66666667h
imul ecx
sar edx, 3


In the snippet we can see function argument being multiplied by 0x66666667, and the result being stored as a 64 bit value in EDX:EAX (topmost 32 bits in EDX, the lower 32 in EAX)
Then the top 32 bits are shifted ("arithmetically") to the right. That is, divided by 2 thrice, same as 2^3 = 8. Effectively dividing the value by 8.
But the division is applied only to the top 32 bits, ignoring the lower 32. That could be understood to also mean that, by taking the topmost 32 bits and ignoring the bottom ones, the result of the multiplication is implicitly being divided by 2^32. (Thats only guessed by the subsequent usage of the value just obtained, theres never again a reference to the lower 32bits, so I assume that they are discarded)


What do we have so far?

[ (Value * 0x66666667) / 2^32 ] / 2^3 ]

But, whats that 0x66666667? why to multiply by something so large and then divide?
The reason is that such computation allows the processor to keep most of the precision of the division it is trying to perform, still obtaining an integer in the end but without having to resort to using floating point arithmetic (which is far slower)

Lets do an example in base 10. Imagine that you only can multiply and divide by 10 (shifting numbers left and right) and we want to divide a number by 30. By shifting we can only divide by 10, 100, 1000, etc

But we have that: Value/30 = value * 1/3 * 1/10

Given that, represented as an integer, 1/3 would produce 0 we can "scale" it by multiplying by a large constant that later, once we are done, we divide by to get the value were after. Given that the easiest for us is to multiply/divide by 10, we can "scale" 1/3 and make it 100000/3 which approximately equals 33333, which is a nice integer value. We would want to make this value as large as it fits in our registers in order to be as precise as possible. The bigger it is the more precision it will retain for subsequent operations.

Value/30 = ( Value*33333 ) / 1000000

Hence, we now have a clue now of where that 0x66666667 value might be coming from. Given that the processor works in base 2. We can assume that its going to prefer multiples of 2. Also, given that it will try to obtain the largest value that fits in a 32bit register, that gives us an idea of the range of the power-of-two in use. We can get there with a bit of trial and error (We want to obtain an integer as a result of dividing a power of two by 0x66666667).

2.0^33/0x66666667 = 4.9999999982537702 ~= 5

Therefore:

0x66666667 ~= 2^33/5

So, in the end we get to

( [ (Value * 2^33)/5] /2^32 ) / 2^3

And with some algebra it simplifies to:

Value / (5*2^2) = Value/20

Effectively dividing the value by 20, without actually using the division instruction. Thats to the extent that compilers will go to avoid using the division instruction...

```
진짜 귀찮다.. ㅋㅋㅋ 전역하자..!

0x66666667 ~= 2^33/5


edx = (0x66666667 * input) / 0x100000000
eax = (0x66666667 * input) & 0xffffffff

input - ((((0x66666667 * input) / 0x100000000) >> 2) - (input >> 0x1f)) * 6


input - ((((input * 2^33/5) / 2^32) / 2^2) - (input >> 0x1f) * 6

input - (input * 2 / 5 / 2^2) - (input >> 0x1f) * 6



input - (((input / 10)(버림) - (input >> 0x1f))) * 10


#Reference

- [https://en.wikipedia.org/wiki/Modulo_operation](https://en.wikipedia.org/wiki/Modulo_operation)
- [https://stackoverflow.com/questions/15596318/is-it-better-to-avoid-using-the-mod-operator-when-possible](https://stackoverflow.com/questions/15596318/is-it-better-to-avoid-using-the-mod-operator-when-possible)
- [http://www.openrce.org/blog/view/892/function.session-start](http://www.openrce.org/blog/view/892/function.session-start)
- [http://index-of.es/Security/Addison%20Wesley%20-%20Hackers%20Delight%202002.pdf](http://index-of.es/Security/Addison%20Wesley%20-%20Hackers%20Delight%202002.pdf)
- [https://www.hex-rays.com/blog/reading-assembly-code](https://www.hex-rays.com/blog/reading-assembly-code)