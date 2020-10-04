---
title: Pwnable - Meltdown
categories:
 - pwnable
tags: kernel, computer architecture, leak, cache, race condition
---

# Introduction

예전에 번역했던 `Dirty Cow`를 하고나서 `Meltdown` 논문을 읽어보고 포스팅하기로 했는데 그동안 귀찮아서 미뤄놨던 것을 지금에 와서야 포스팅한다.

사실 CTF문제를 계속 풀어야되는데 진짜.. 너무 의욕이 안나서 도피겸 논문 읽고 정리하는 시간을 갖기 위해 포스팅한다.

그리고 이 글은 읽은 내용을 정리 및 번역하기 위한 글이니... 되도록이면 글을 읽어보고 `Reference`에 있는 논문을 읽는 것을 강력히 추천한다.

# Background

일단 `meltdown`을 알아보기전에 알아야될 배경지식 먼저 설명하도록 하겠다.

- out-of-order excution

한글로 비순차적 명령어 처리, 비순차적 실행 이라고 불리는데, `https://ko.wikipedia.org/wiki/%EB%B9%84%EC%88%9C%EC%B0%A8%EC%A0%81_%EB%AA%85%EB%A0%B9%EC%96%B4_%EC%B2%98%EB%A6%AC`을 보면 

비순차적 실행은 순차적 실행과 다르게 소스코드의 흐름대로 즉 순차적으로 실행하는 것이 아닌 병렬적으로 처리하는 것을 말한다.

다 제쳐두고 왜 비순차적으로 실행을 시킬까? 병렬적으로? 답은 cpu의 활용도를 높이기 위해서다. 다시 말하면 cpu가 노는 시간을 줄이고 코드실행속도를 빠르게 하기 위해서이다.(필자가 알기로는 멀티코어 cpu에서 하나의 실행파일에 대해 더 빠르게 실행시키기 위해서 만든것으로 알고 있다.)

그럼 순차적이지 않다는게 어떤것인지 알아보자. 예를 살펴보면,

```
y = input
x = y + 1
z = y + 2
```

이런 코드가 있을때 2,3번째 있는 코드는 1번째 값이 `stdin`이든 뭐든 input값이 들어 온뒤에 실행되어야 된다. 하지만 2,3번의 관계를 한번 살펴보면 굳이 3번째 코드가 2번째 코드를 실행한 다음에 실행할 필요가 없다.

이때 2,3번째 코드를 병렬적으로 즉 비순차적으로 실행을 한다. 이것이 순차적이지 않다는 것이다.

비순차 실행을 위해서는 위에서 설명한것과 같이 데이터 의존성, 파이프라인 등 고려해야 될 부분이 많다. 자세한 내용은 따로 찾아보도록 하고 여기서 알아야되는 내용은 `예측실행(Speculative Execution)`이다.

`예측실행(Speculative Execution)`을 설명하기 위해서 코드하나를 살펴보면

```c
#include <stdio.h>

int main(){
    
    unsigned int a, b = 20, c;
 
    scanf("%d", &a);
    
    if(a < 10){
        b = 10;
    }
    
    c = b + 35;
    
    foo(c);
    
    return 0;
}
```

위의 코드에서 c의 값이 정해지는 시점은 분명 if문을 통과하고, b의 값이 확정된 후다. 엄밀히 말하면 b의 값이 10인지 20인지 정해지고 나서 c의 값이 정해진다.

하지만 병렬컴퓨팅, 즉 비순차 실행을 위해 거의 대부분의 cpu에서 if문의 분기점을 예측한다. 즉 b의 값을 예측해서 c의 값을 결정짓고 `foo(c)`를 실행시킨다.

예측을 할때는 확률이 높은 쪽의 분기를 먼저 실행시킨다. 예시 코드의 경우에는 아마 b = 20을 미리 예측한 뒤에 `foo(c)`를 실행시킬 것이다.(온전히 필자의 뇌피셜이다.)

여기서 드는 의문점이 있는 독자가 있을것이다. 예측이 틀리면 어떻게 되는거지? 

~~어떻게 되긴 ㅈ되는거지ㄹㅇㅋㅋ~~ 가 아니고 예측 분기 이후의 명령 파이프들을 전부 폐기하고 예측실패한 분기부터 다시 명령어를 실행한다. 

이 때문에 어느 분기로 갈지 예측하는 것이 성능에 큰 영향을 끼치게 되고 관련 내용도 엄청 많다. (따로 찾아보는 것을 추천한다.)










- address space

- cache attack




# Reference

- [https://meltdownattack.com/meltdown.pdf](https://meltdownattack.com/meltdown.pdf)
- [http://cloudrain21.com/out-of-order-processor-pipeline-1](http://cloudrain21.com/out-of-order-processor-pipeline-1)
- [https://ko.wikipedia.org/wiki/%EB%B9%84%EC%88%9C%EC%B0%A8%EC%A0%81_%EB%AA%85%EB%A0%B9%EC%96%B4_%EC%B2%98%EB%A6%AC](https://ko.wikipedia.org/wiki/%EB%B9%84%EC%88%9C%EC%B0%A8%EC%A0%81_%EB%AA%85%EB%A0%B9%EC%96%B4_%EC%B2%98%EB%A6%AC)
- [http://blog.skby.net/%ED%8C%8C%EC%9D%B4%ED%94%84%EB%9D%BC%EC%9D%B8-%EB%B6%84%EA%B8%B0%EC%98%88%EC%B8%A1%EA%B3%BC-%EC%98%88%EC%B8%A1%EC%8B%A4%ED%96%89/](http://blog.skby.net/%ED%8C%8C%EC%9D%B4%ED%94%84%EB%9D%BC%EC%9D%B8-%EB%B6%84%EA%B8%B0%EC%98%88%EC%B8%A1%EA%B3%BC-%EC%98%88%EC%B8%A1%EC%8B%A4%ED%96%89/)