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





- address space

- cache attack




# Reference

- [https://meltdownattack.com/meltdown.pdf](https://meltdownattack.com/meltdown.pdf)
- [http://cloudrain21.com/out-of-order-processor-pipeline-1](http://cloudrain21.com/out-of-order-processor-pipeline-1)
- [https://ko.wikipedia.org/wiki/%EB%B9%84%EC%88%9C%EC%B0%A8%EC%A0%81_%EB%AA%85%EB%A0%B9%EC%96%B4_%EC%B2%98%EB%A6%AC](https://ko.wikipedia.org/wiki/%EB%B9%84%EC%88%9C%EC%B0%A8%EC%A0%81_%EB%AA%85%EB%A0%B9%EC%96%B4_%EC%B2%98%EB%A6%AC)