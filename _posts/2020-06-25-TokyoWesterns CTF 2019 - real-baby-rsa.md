---
title: TokyoWestern CTF 2019 - real-baby-rsa
categories:
 - crypto
tags: rsa, crypto
---

- Introduction
- Exploit
- slv.py
- 느낀 점
- Reference

## Introduction

TokyoWesterns 2019 문제 중에 정말 쉬울것같은 rsa 문제가 있길래 건들여봤다.

## Vunlnerability

처음에 `problem.py`를 돌려보고선 ...? 이게 뭐 어떻게 하라는거지 생각했는데 `output`파일이 있다는것을 깨닫고 `flag`를 암호화한 결과물이라는 것을 알게됬당.

## Exploit

한글자씩 암호화를 하길래 이걸 어떻게 찾지... 0x20 - 0x7f 까지 ASCII 범위니까 0x60^(flag 문자열 수)만큼 걸리는 줄 알고 다른 방법을 생각해봤다가... 그냥 dictionary 만들어서 각 ascii에 해당하는 암호화값이랑 대입해서 찾으면 되는거였어서 0x60 * (flag 문자열 수)로 문제를 풀었당.

## slv.py

```python

N = 36239973541558932215768154398027510542999295460598793991863043974317503405132258743580804101986195705838099875086956063357178601077684772324064096356684008573295186622116931603804539480260180369510754948354952843990891989516977978839158915835381010468654190434058825525303974958222956513586121683284362090515808508044283236502801777575604829177236616682941566165356433922623572630453807517714014758581695760621278985339321003215237271785789328502527807304614754314937458797885837846005142762002103727753034387997014140695908371141458803486809615038309524628617159265412467046813293232560959236865127539835290549091

e = 65537
dictionary = {}

for i in range(0x30, 0x7f):
    
    dictionary[chr(i)] = pow(i,e,N)
    

flag = ''

with open('output', 'r') as f:
    
    while True:
        
        line = f.readline()
        
        if not line : break
        
        line = int(line.strip())
        
        for key, value in dictionary.items():
            if value == line:
                flag += key
                break

print(flag)
```

## 느낀 점

- RSA의 개념을 알게되었다. 

- 알고리즘, 암호와 관련된 문제들도 건들여봐야겠다.


## Reference
- [https://defenit.kr/2019/09/24/Crypto/%E3%84%B4%20Research/RSA_for_CTF/](https://defenit.kr/2019/09/24/Crypto/%E3%84%B4%20Research/RSA_for_CTF/)

- [https://blog.encrypted.gg/876](https://blog.encrypted.gg/876)