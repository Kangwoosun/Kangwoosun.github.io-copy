---
title: Pwnable - linux canary
categories:
 - pwnable
tags: pwn, canary, tls
---
# linux stack canary (main thread)



# linux stack canary (non main thread)

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

```
## pthread_join
```c

```

# Referenece

```
https://chao-tic.github.io/blog/2018/12/25/tls

```