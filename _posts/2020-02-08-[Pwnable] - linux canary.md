---
title: Pwnable - linux canary
categories:
 - pwnable
tags: pwn, canary, tls
---

glibc 2.29

# linux stack canary (main thread)



# linux stack canary (non main thread)

pthread struct
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
  
  
  
tcbhead_t struct

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

```c
```

```c
```

```c
# define THREAD_COPY_STACK_GUARD(descr) \
    ((descr)->header.stack_guard                                              \
     = THREAD_GETMEM (THREAD_SELF, header.stack_guard))
```
```c
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
## pthread_join
```c

```

# Referenece

```
https://chao-tic.github.io/blog/2018/12/25/tls

```