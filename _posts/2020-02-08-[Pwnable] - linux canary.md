---
title: Pwnable - linux canary
categories:
 - pwnable
tags: pwn, canary, tls
---

codegate 2019의 aeiou 문제를 풀면서 canary, tcb, tls 등에 관심이 생겨서 분석을 진행해보려고 한다.

glibc 2.29 버전의 소스코드를 정적분석, glibc 2.19 버전으로 동적분석을 진행했다.

(환경이 환경인지라 양해를 부탁드립니다..)


이번 포스팅에서는 linux x86-64 stack canary에 대해 포스팅하고 tcb, tls 관련 포스팅은 추후 하도록 하겠다.



먼저 canary의 프롤로그와 에필로그를 살펴보면

```c
Prologue

0x400da5:    mov    rax,QWORD PTR fs:0x28
0x400dae:    mov    QWORD PTR [rbp-0x8],rax

.
.
.

Epilogue

0x400fdf:    mov    rax,QWORD PTR [rbp-0x8]
0x400fe3:    xor    rax,QWORD PTR fs:0x28
0x400fec:    je     0x400ff3
0x400fee:    call   __stack_chk_fail)

```

여기서 fs:0x28은 fs 레지스터가 가리키는 포인터의 0x28 offset의 값을 말하는데

fs 레지스터는 TLS(Thread Local Storage) 구조체의 주소를 담고 있다.

바로 `tcbhead_t struct`의 주소를 담고있는데

```c
typedef struct
{
  void *tcb;                /* Pointer to the TCB.  Not necessarily the
                           thread descriptor used by libpthread.  */
  dtv_t *dtv;
  void *self;                /* Pointer to the thread descriptor.  */
  int multiple_threads;
  int gscope_flag;
  uintptr_t sysinfo;
  uintptr_t stack_guard;
  uintptr_t pointer_guard;
  unsigned long int vgetcpu_cache[2];
  /* Bit 0: X86_FEATURE_1_IBT.
     Bit 1: X86_FEATURE_1_SHSTK.
   */
  unsigned int feature_1;
  int __glibc_unused1;
  /* Reservation of some values for the TM ABI.  */
  void *__private_tm[4];
  /* GCC split stack support.  */
  void *__private_ss;
  /* The lowest address of shadow stack,  */
  unsigned long long int ssp_base;
  /* Must be kept even if it is no longer used by glibc since programs,
     like AddressSanitizer, depend on the size of tcbhead_t.  */
  __128bits __glibc_unused2[8][4] __attribute__ ((aligned (32)));
  void *__padding[8];
  
} tcbhead_t;
```

여기서 0x28의 offset은 stack_guard이다.

해당 구조체는 thread마다 하나씩 할당이 되는데 main thread에서 제일 처음 canary를 생성한다.

그 뒤에 tcb 구조체가 만들어지고 non main thread가 생성이 되면 main thread의 canary를 복사해오는 형식으로 진행이 된다.

먼저 pthread_create로 만들어진 non main thread에서 canary를 어떻게 복사해오는 지 살펴보도록 하겠다.

# linux stack canary (non main thread)


`pthread struct`

```c
struct pthread
{
	union
	{
		#if !TLS_DTV_AT_TP
		/* This overlaps the TCB as used for TLS without threads (see tls.h).  */
		tcbhead_t header;
		#else
		struct
		{
		  /* multiple_threads is enabled either when the process has spawned at
			 least one thread or when a single-threaded process cancels itself.
			 This enables additional code to introduce locking before doing some
			 compare_and_exchange operations and also enable cancellation points.
			 The concepts of multiple threads and cancellation points ideally
			 should be separate, since it is not necessary for multiple threads to
			 have been created for cancellation points to be enabled, as is the
			 case is when single-threaded process cancels itself.
			 Since enabling multiple_threads enables additional code in
			 cancellation points and compare_and_exchange operations, there is a
			 potential for an unneeded performance hit when it is enabled in a
			 single-threaded, self-canceling process.  This is OK though, since a
			 single-threaded process will enable async cancellation only when it
			 looks to cancel itself and is hence going to end anyway.  */
		  int multiple_threads;
		  int gscope_flag;
		} header;
		#endif
		/* This extra padding has no special purpose, and this structure layout
		   is private and subject to change without affecting the official ABI.
		   We just have it here in case it might be convenient for some
		   implementation-specific instrumentation hack or suchlike.  */
		void *__padding[24];
	};
  
	/* This descriptor's link on the `stack_used' or `__stack_user' list.  */
	list_t list;
	/* Thread ID - which is also a 'is this thread descriptor (and
	 therefore stack) used' flag.  */
	pid_t tid;
	/* Ununsed.  */
	pid_t pid_ununsed;

.
.
.

	void *(*start_routine) (void *);
	void *arg;
	/* Debug state.  */
	td_eventbuf_t eventbuf;
	/* Next descriptor with a pending event.  */
	struct pthread *nextevent;
	/* Machine-specific unwind info.  */
	struct _Unwind_Exception exc;
	/* If nonzero, pointer to the area allocated for the stack and guard. */
	void *stackblock;
	/* Size of the stackblock area including the guard.  */
	size_t stackblock_size;
	/* Size of the included guard area.  */
	size_t guardsize;
	/* This is what the user specified and what we will report.  */
	size_t reported_guardsize;
	/* Thread Priority Protection data.  */
	struct priority_protection_data *tpp;
	/* Resolver state.  */
	struct __res_state res;
	/* Indicates whether is a C11 thread created by thrd_creat.  */
	bool c11;
	/* This member must be last.  */
	char end_padding[];
	#define PTHREAD_STRUCT_END_PADDING \
	(sizeof (struct pthread) - offsetof (struct pthread, end_padding))

} __attribute ((aligned (TCB_ALIGNMENT)));
```

pthread_create의 첫번째 인자로 들어가는 구조체다.


## pthread_create



```c
int
__pthread_create_2_1 (pthread_t *newthread, const pthread_attr_t *attr,
                      void *(*start_routine) (void *), void *arg)
{
  STACK_VARIABLES;
  const struct pthread_attr *iattr = (struct pthread_attr *) attr;
  struct pthread_attr default_attr;
  bool free_cpuset = false;
  bool c11 = (attr == ATTR_C11_THREAD);
  if (iattr == NULL || c11)
    {
      lll_lock (__default_pthread_attr_lock, LLL_PRIVATE);
      default_attr = __default_pthread_attr;
      size_t cpusetsize = default_attr.cpusetsize;
      if (cpusetsize > 0)
        {
          cpu_set_t *cpuset;
          if (__glibc_likely (__libc_use_alloca (cpusetsize)))
            cpuset = __alloca (cpusetsize);
          else
            {
              cpuset = malloc (cpusetsize);
              if (cpuset == NULL)
                {
                  lll_unlock (__default_pthread_attr_lock, LLL_PRIVATE);
                  return ENOMEM;
                }
              free_cpuset = true;
            }
          memcpy (cpuset, default_attr.cpuset, cpusetsize);
          default_attr.cpuset = cpuset;
        }
      lll_unlock (__default_pthread_attr_lock, LLL_PRIVATE);
      iattr = &default_attr;
    }
  struct pthread *pd = NULL;
  
  
  int err = ALLOCATE_STACK (iattr, &pd);
  
  
  int retval = 0;
  if (__glibc_unlikely (err != 0))
    /* Something went wrong.  Maybe a parameter of the attributes is
       invalid or we could not allocate memory.  Note we have to
       translate error codes.  */
    {
      retval = err == ENOMEM ? EAGAIN : err;
      goto out;
    }
  /* Initialize the TCB.  All initializations with zero should be
     performed in 'get_cached_stack'.  This way we avoid doing this if
     the stack freshly allocated with 'mmap'.  */
#if TLS_TCB_AT_TP
  /* Reference to the TCB itself.  */
  pd->header.self = pd;
  /* Self-reference for TLS.  */
  pd->header.tcb = pd;
#endif
  /* Store the address of the start routine and the parameter.  Since
     we do not start the function directly the stillborn thread will
     get the information from its thread descriptor.  */
  pd->start_routine = start_routine;
  pd->arg = arg;
  pd->c11 = c11;
  /* Copy the thread attribute flags.  */
  struct pthread *self = THREAD_SELF;
  pd->flags = ((iattr->flags & ~(ATTR_FLAG_SCHED_SET | ATTR_FLAG_POLICY_SET))
               | (self->flags & (ATTR_FLAG_SCHED_SET | ATTR_FLAG_POLICY_SET)));
  /* Initialize the field for the ID of the thread which is waiting
     for us.  This is a self-reference in case the thread is created
     detached.  */
  pd->joinid = iattr->flags & ATTR_FLAG_DETACHSTATE ? pd : NULL;
  /* The debug events are inherited from the parent.  */
  pd->eventbuf = self->eventbuf;
  /* Copy the parent's scheduling parameters.  The flags will say what
     is valid and what is not.  */
  pd->schedpolicy = self->schedpolicy;
  pd->schedparam = self->schedparam;
  /* Copy the stack guard canary.  */
  
  
#ifdef THREAD_COPY_STACK_GUARD
  THREAD_COPY_STACK_GUARD (pd);
  
  
#endif
  /* Copy the pointer guard value.  */
#ifdef THREAD_COPY_POINTER_GUARD
  THREAD_COPY_POINTER_GUARD (pd);
#endif
  /* Setup tcbhead.  */
  tls_setup_tcbhead (pd);
  
  .
  .
  .
  
    }
  if (__glibc_unlikely (__nptl_nthreads == 1))
    _IO_enable_locks ();
  /* Pass the descriptor to the caller.  */
  *newthread = (pthread_t) pd;
  
  .
  .
  .

```

여기서 분석하고자 하는 부분이 `ALLOCATE_STACK (iattr, &pd)`와 `THREAD_COPY_STACK_GUARD (pd)`다.


`ALLOCATE_STACK (iattr, &pd)`는 추후에 포스팅하도록 하겠다.

`THREAD_COPY_STACK_GUARD (pd)`

```c
# define THREAD_COPY_STACK_GUARD(descr) \
    ((descr)->header.stack_guard                                              \
     = THREAD_GETMEM (THREAD_SELF, header.stack_guard))
	 
# define THREAD_SELF \
  ({ struct pthread *__self;                                                      \
     asm ("mov %%fs:%c1,%0" : "=r" (__self)                                      \
          : "i" (offsetof (struct pthread, header.self)));                       \
     __self;})
	 
# define THREAD_GETMEM(descr, member) \
  ({ __typeof (descr->member) __value;                                              \
     if (sizeof (__value) == 1)                                                      \
       asm volatile ("movb %%fs:%P2,%b0"                                      \
                     : "=q" (__value)                                              \
                     : "0" (0), "i" (offsetof (struct pthread, member)));     \
     else if (sizeof (__value) == 4)                                              \
       asm volatile ("movl %%fs:%P1,%0"                                              \
                     : "=r" (__value)                                              \
                     : "i" (offsetof (struct pthread, member)));              \
     else                                                                      \
       {                                                                      \
         if (sizeof (__value) != 8)                                              \
           /* There should not be any value with a size other than 1,              \
              4 or 8.  */                                                      \
           abort ();                                                              \
                                                                              \
         asm volatile ("movq %%fs:%P1,%q0"                                      \
                       : "=r" (__value)                                              \
                       : "i" (offsetof (struct pthread, member)));              \
       }                                                                      \
     __value; })
	 
```

`THREAD_SELF`는 pthread의 header.self를 참조하는데 해당 값은 TLS, 즉 TCB 구조체를 가리키고 있다.

`THREAD_GETMEM`는 descr->member의 size에 따라 비트를 체크해서 해당 비트 (ex, 64bit)에 맞게 fs:offset에 값을 넣어주고 있다.

`THREAD_COPY_STACK_GUARD`는 현재 thread(THREAD_SELF)의 stack_guard값을 인자로 넣은 pthread구조체에 복사해주는 매크로인 것이다.

따라서 pthread_created에서 `ALLOCATE_STACK (iattr, &pd)`로 library stack 공간에 pd 구조체의 공간을 제공해주고 `THREAD_COPY_STACK_GUARD (pd)`로 만들어지는 thread의 tcb구조체에 stack_guard를 세팅해주는 역할을 해준다.

그래서 non main thread의 stack에서 stack buffer overflow가 발생하게 되면 library stack의 공간에 할당된 stack_guard의 값을 건들 수 있게 된다.

이를 통해 canary를 우회할 수 있는 가능성이 생기는 것이다.

이렇게 non main thread에서 main thread의 canary를 복사해오는 과정을 살펴보았으니 main thread에서 어떻게 canary값을 초기화 해주는 지 살펴보도록 하겠다.


# linux stack canary (main thread)

```c
```
```c
```
```c
```


```c
void
_dl_aux_init (ElfW(auxv_t) *av)
{
  int seen = 0;
  uid_t uid = 0;
  gid_t gid = 0;
  _dl_auxv = av;
  for (; av->a_type != AT_NULL; ++av)
    switch (av->a_type)
      {
      case AT_PAGESZ:
        if (av->a_un.a_val != 0)
          GLRO(dl_pagesize) = av->a_un.a_val;
        break;
      case AT_CLKTCK:
        GLRO(dl_clktck) = av->a_un.a_val;
        break;
      case AT_PHDR:
        GL(dl_phdr) = (const void *) av->a_un.a_val;
        break;
      case AT_PHNUM:
        GL(dl_phnum) = av->a_un.a_val;
        break;
      case AT_PLATFORM:
        GLRO(dl_platform) = (void *) av->a_un.a_val;
        break;
      case AT_HWCAP:
        GLRO(dl_hwcap) = (unsigned long int) av->a_un.a_val;
        break;
      case AT_HWCAP2:
        GLRO(dl_hwcap2) = (unsigned long int) av->a_un.a_val;
        break;
      case AT_FPUCW:
        GLRO(dl_fpu_control) = av->a_un.a_val;
        break;
#ifdef NEED_DL_SYSINFO
      case AT_SYSINFO:
        GL(dl_sysinfo) = av->a_un.a_val;
        break;
#endif
#ifdef NEED_DL_SYSINFO_DSO
      case AT_SYSINFO_EHDR:
        GL(dl_sysinfo_dso) = (void *) av->a_un.a_val;
        break;
#endif
      case AT_UID:
        uid ^= av->a_un.a_val;
        seen |= 1;
        break;
      case AT_EUID:
        uid ^= av->a_un.a_val;
        seen |= 2;
        break;
      case AT_GID:
        gid ^= av->a_un.a_val;
        seen |= 4;
        break;
      case AT_EGID:
        gid ^= av->a_un.a_val;
        seen |= 8;
        break;
      case AT_SECURE:
        seen = -1;
        __libc_enable_secure = av->a_un.a_val;
        __libc_enable_secure_decided = 1;
        break;
      case AT_RANDOM:
	  
	  
        _dl_random = (void *) av->a_un.a_val;
		
		
        break;
# ifdef DL_PLATFORM_AUXV
      DL_PLATFORM_AUXV
# endif
      }
  if (seen == 0xf)
    {
      __libc_enable_secure = uid != 0 || gid != 0;
      __libc_enable_secure_decided = 1;
    }
}
#endif
```


```c
static void
security_init (void)
{
  /* Set up the stack checker's canary.  */
  uintptr_t stack_chk_guard = _dl_setup_stack_chk_guard (_dl_random);
#ifdef THREAD_SET_STACK_GUARD
  THREAD_SET_STACK_GUARD (stack_chk_guard);
#else
  __stack_chk_guard = stack_chk_guard;
#endif
  /* Set up the pointer guard as well, if necessary.  */
  uintptr_t pointer_chk_guard
    = _dl_setup_pointer_guard (_dl_random, stack_chk_guard);
#ifdef THREAD_SET_POINTER_GUARD
  THREAD_SET_POINTER_GUARD (pointer_chk_guard);
#endif
  __pointer_chk_guard_local = pointer_chk_guard;
  /* We do not need the _dl_random value anymore.  The less
     information we leave behind, the better, so clear the
     variable.  */
  _dl_random = NULL;
}

```



`uintptr_t stack_chk_guard = _dl_setup_stack_chk_guard (_dl_random)`

`THREAD_SET_STACK_GUARD (stack_chk_guard)`


# Referenece

```
https://chao-tic.github.io/blog/2018/12/25/tls
https://code.woboq.org/userspace/glibc/nptl/pthread_join.c.html
https://code.woboq.org/userspace/glibc/nptl/pthread_create.c.html
https://nekoplu5.tistory.com/206
https://hackability.kr/entry/SSP-Stack-Canary%EC%97%90-%EB%8C%80%ED%95%9C-Phrack-%EC%9E%90%EB%A3%8C-%EB%B2%88%EC%97%AD

```