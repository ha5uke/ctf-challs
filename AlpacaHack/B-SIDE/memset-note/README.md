# memset note

## 概要
- stack overflow
- checksec
'''
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
'''

## 解説
- memset()で適当にcanary終端のヌル文字まで埋めると、その後のputs()でcanaryをリークできる。
- 次に、リターンアドレスをwin()のアドレスに書き換えたいが、スタックは１種類の値でしか埋められない。
- そこで、リターンアドレスの先頭からcanaryの終端まで、適当な値を１バイトずつセットしていく。
