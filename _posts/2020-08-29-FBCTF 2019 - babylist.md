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

libc_leak은 성공..(20.08.31)


## 느낀 점


## Reference