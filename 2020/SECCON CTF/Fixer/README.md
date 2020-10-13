# SECCON CTF 2020 Fixer (reversing) writeup

This writeup is written in Japanese.

## 問題文
```
usage

$ python3.9 fixer.cpython-39.pyc
SECCON{DUMMY_FLAG}
wrong
$

Note: SECCON{DUMMY_FLAG} is not the actual flag.
```

問題ファイルは pyc ファイルです。とりあえず [uncompyle6](https://github.com/rocky/python-uncompyle6) でデコンパイルしようとしたのですがエラーになってしまいました。

```
PS C:\Users\user\Desktop> uncompyle6.exe -o . .\fixer.cpython-39.pyc
Unknown type 64 @
Unknown type 0
Unknown type 0
Unknown type 0
Unknown type 100 d
Unknown type 2 
Unknown type 4 
Unknown type 0
Unknown type 100 d
Unknown type 5 
Unknown type 100 d
Unknown type 2 
Unknown type 100 d
Traceback (most recent call last):
  File "c:\users\user\appdata\local\programs\python\python38\lib\site-packages\xdis\load.py", line 297, in load_module_from_file_object
... 以下省略 ...
```

uncompyle6 の後継版の [decompyle3](https://github.com/rocky/python-uncompyle6) ではどうだろうと試してみたところ、こちらもエラーになりました。

```
PS C:\Users\user\Desktop> decompyle3.exe -o . .\fixer.cpython-39.pyc
Unknown type 64 @
Unknown type 0
Unknown type 0
Unknown type 0
Unknown type 100 d
Unknown type 2 
Unknown type 4 
Unknown type 0
Unknown type 100 d
Unknown type 5 
Unknown type 100 d
Unknown type 2 
Unknown type 100 d
Traceback (most recent call last):
  File "c:\users\user\appdata\local\programs\python\python38\lib\site-packages\xdis\load.py", line 297, in load_module_from_file_object
... 以下省略 ...
```

pyc ファイルはリリースされて間もない Python 3.9 で作成されたもののようでしたので、もしかしたらヘッダを 3.8 のものに書き換えたらデコンパイルできないか、と思い付きました。色々調べてみたところ、こちらがとても参考になりました。

> pycのマジックナンバーについて調べました。  
> http://niyarin-code.hatenablog.com/entry/2017/06/13/044117

pyc ファイルの先頭4バイトがマジックナンバーになっていて、どのバージョンで作成されたのかが分かるようになっているそうです。fixer.cpython-39.pyc の先頭4バイトは 61 0D 0D 0A でしたので、このページに書かれている方法で計算してみます。

```python
>>> 0x61 + 0xd * (1<<8) + 0xd * (1<<16) + 0xa * (1<<24)
168627553
>>> 168627553 & int("FFFF",16)
3425
>>>
```

https://github.com/python/cpython/blob/master/Lib/importlib/_bootstrap_external.py のコメントを見てみると、3425 は Python 3.9a2 のところと一致しました。おそらくリリース版もこの値になるのではないかと思われます。

```
#     Python 3.8a1  3400 (move frame block handling to compiler #17611)
#     Python 3.8a1  3401 (add END_ASYNC_FOR #33041)
#     Python 3.8a1  3410 (PEP570 Python Positional-Only Parameters #36540)
#     Python 3.8b2  3411 (Reverse evaluation order of key: value in dict
#                         comprehensions #35224)
#     Python 3.8b2  3412 (Swap the position of positional args and positional
#                         only args in ast.arguments #37593)
#     Python 3.8b4  3413 (Fix "break" and "continue" in "finally" #37830)
#     Python 3.9a0  3420 (add LOAD_ASSERTION_ERROR #34880)
#     Python 3.9a0  3421 (simplified bytecode for with blocks #32949)
#     Python 3.9a0  3422 (remove BEGIN_FINALLY, END_FINALLY, CALL_FINALLY, POP_FINALLY bytecodes #33387)
#     Python 3.9a2  3423 (add IS_OP, CONTAINS_OP and JUMP_IF_NOT_EXC_MATCH bytecodes #39156)
#     Python 3.9a2  3424 (simplify bytecodes for *value unpacking)
#     Python 3.9a2  3425 (simplify bytecodes for **value unpacking)
#     Python 3.10a1 3430 (Make 'annotations' future by default)
```

ということで、3.8 に相当する 3413 になるように先頭4バイトを 55 0D 0D 0A に (61 -> 55) 書き換えてみました。すると、decompyle3 で正常にデコンパイルできました。

```
PS C:\Users\user\Desktop> decompyle3.exe -o . .\modified-fixer.cpython-39.pyc
.\modified-fixer.cpython-39.pyc --
# Successfully decompiled file
PS C:\Users\user\Desktop>
```

decompyle3 で以下のようなコードが出力されました。

```python
# decompyle3 version 3.3.2
# Python bytecode 3.8 (3413)
# Decompiled from: Python 3.8.5 (tags/v3.8.5:580fbb0, Jul 20 2020, 15:57:54) [MSC v.1924 64 bit (AMD64)]
# Embedded file name: fixer.py
# Compiled at: 2020-10-09 12:49:00
# Size of source mod 2**32: 961 bytes
import re
s = input()
m = re.match('^SECCON{([A-Z]+)}$', s)
if not m:
    print('invalid flag')
else:
    s = m.group(1)
    f = lambda s: lambda a: lambda b: a == b(13611142019359843741091679554812914051545792465993098606064046040462991)(lambda a: lambda b: a(lambda c: b(b)(c))(lambda b: a(lambda c: b(b)(c)))(lambda f: lambda b: lambda c: lambda d: d if len(c) == 0 else b(f(b)(c[1:])(d))(c[0]))(lambda a: lambda b: a * lambda a: lambda b: a(lambda c: b(b)(c))(lambda b: a(lambda c: b(b)(c)))(lambda a: lambda b: b - 10 if b > 266 else a(a(b + 11)))(b) + b)(lambda a: lambda b: a(lambda c: b(b)(c))(lambda b: a(lambda c: b(b)(c)))(lambda f: lambda b: lambda c: [] if len(c) == 0 else [b(ord(c[0]) - 65)] + f(b)(c[1:]))(lambda a: lambda b: a(lambda c: b(b)(c))(lambda b: a(lambda c: b(b)(c)))(lambda a: lambda b: 1 if b == 0 else (b + 1) * a(b - 1) + 7 & 255))(s))(0))
    if f(s):
        print('correct')
    else:
        print('wrong')
```

lambda がいっぱいでどうしたもんか・・・と考えていたところ、一緒に参加している同僚から「不動点コンビネータで再帰呼び出ししてるかもしれない」との助言がありました。

不動点コンビネータ?何それ?と調べてみると、任意の関数 f に対して f(g(f)) = g(f) が成立する高階関数 g を不動点コンビネータ(fixed point combinator)と呼び、これを使うと関数に名前を付けずに再帰呼び出しを行えるそうです。

> 不動点コンビネータ  
> https://ja.wikipedia.org/wiki/%E4%B8%8D%E5%8B%95%E7%82%B9%E3%82%B3%E3%83%B3%E3%83%93%E3%83%8D%E3%83%BC%E3%82%BF

デコンパイルしたコードをじっくり見ていると、この Wikipedia のページに書かれていた以下のサンプルコードのZコンビネータに相当するコードが含まれていることが分かりました。

```python
>>> Z = lambda f: (lambda x: f(lambda *args: x(x)(*args)))(lambda x: f(lambda *args: x(x)(*args)))
>>> fact = lambda f: lambda x: 1 if x == 0 else x * f(x-1)
>>> Z(fact)(5)
120
```

Zコンビネータを Z と定義して、デコンパイルしたコードの "f = " のところを書き換えてみると以下のように少し読みやすくなりました。

```python
Z = lambda a: (lambda b: a(lambda c: b(b)(c)))(lambda b: a(lambda c: b(b)(c))) # Z combinator

f = lambda s: lambda a: lambda b: a == b(13611142019359843741091679554812914051545792465993098606064046040462991)(Z(lambda f: lambda b: lambda c: lambda d: d if len(c) == 0 else b(f(b)(c[1:])(d))(c[0]))(lambda a: lambda b: a * Z(lambda a: lambda b: b - 10 if b > 266 else a(a(b + 11)))(b) + b)(Z(lambda f: lambda b: lambda c: [] if len(c) == 0 else [b(ord(c[0]) - 65)] + f(b)(c[1:]))(Z(lambda a: lambda b: 1 if b == 0 else (b + 1) * a(b - 1) + 7 & 255))(s))(0))
```

このコードを読み解いていって再帰を使わない形で書き直しました。

```python
import re

def func1(b):
    if b == 0:
        return 1
    else:
        return (b + 1) * func1(b - 1) + 7 & 255

def func2(c):
    if len(c) == 0:
        return []
    else:
        return [func1(ord(c[0]) - 65)] + func2(c[1:])

# always returns 257
def func3(b):
    if b > 266:
        return b - 10
    else:
        return func3(func3(b + 11))

def func4(a, b):
    return a * func3(b) + b

def func5(c, d):
    if len(c) == 0:
        return d
    else:
        return func4(func5(c[1:], d), c[0])

s = input()
m = re.match('^SECCON{([A-Z]+)}$', s)
if not m:
    print('invalid flag')
else:
    s = m.group(1)
    if func5(func2(s), 0) == 13611142019359843741091679554812914051545792465993098606064046040462991:
        print('correct')
    else:
        print('wrong')
```

書き直したコードを不動点コンビネータの助言をしてくれた同僚に見せたら爆速でフラグを出力するスクリプトを書いてくれました。

```python
d = {1: 'A',
 9: 'B',
 12: 'W',
 26: 'U',
 34: 'C',
 39: 'X',
 67: 'V',
 71: 'P',
 96: 'S',
 99: 'R',
 103: 'H',
 131: 'J',
 135: 'T',
 143: 'D',
 148: 'O',
 163: 'N',
 166: 'I',
 168: 'K',
 172: 'G',
 190: 'Q',
 194: 'M',
 195: 'Z',
 210: 'E',
 214: 'Y',
 231: 'L',
 243: 'F'}
n = 13611142019359843741091679554812914051545792465993098606064046040462991
s = ""
while n > 0:
    a = n % 257
    n //= 257
    s += d[a]
print("SECCON{" + s + "}")
```

```
PS C:\Users\user\Desktop> py -3 .\solver.py
SECCON{MYCJILJCZEKRDNNWZUGSEZQSKKPKZA}
PS C:\Users\user\Desktop>
```

かなり難しかったですが、pyc ファイルのマジックナンバーや不動点コンビネータの勉強になってとても面白い問題でした。
今回解けたのはこの1問だけでしたが解けなかった他の問題も面白かったです。

