---
title: PHP simple trick (1)
categories:
 - Web
tags: php, web
---


#  Function call by string

```php
'phpinfo'(); // call phpinfo
```


#  Array indexing

```php
$array = array("a", "b", "c")

echo $array[1] // result : b
echo $array{1} // result : b
```


#  String operations

```php
'qerialize'|'r' // result : 'serialize'
```


#  Error by finfo()

```php
echo new finfo(0, '/')
```


# Change variable to string

```php
qerialize|r($a) // result : print some error message and call serialize($a)
```