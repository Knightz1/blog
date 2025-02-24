---
layout: post
title: "[BALSN 2022]: Propaganda"
categories: rev
toc: true
---


## 1. Propaganda

Đề cho 3 file: `launcher.js`, `run.py` và `propaganda.wasm`

-file `run.py` dùng để chạy file `launcher.js` bằng `node` và `launcher.js` load và compile file `propaganda.wasm` 

-Chương trình gộp 8 byte flag thành 1 số 64 bit (little-endian) vồi đưa vô hàm `f` trong `propaganda.wasm`

-Dùng `wasm2c` của `wabt` để decompile wasm thành code c rồi sau đó compile thành file ELF bằng gcc để tiện cho việc debug

-Đưa vào IDA và tìm hàm f dưới tên `w2c_f`:

![image](https://user-images.githubusercontent.com/91442807/188601432-ddfc8a66-e992-4566-ab01-a24ed62cba3e.png)

-Quan sát và phân tích ta thấy:

  +Hàm sẽ chạy 1 vòng lặp 0x12C lần trong đó gồm 2 vòng lặp nhỏ v8 và v6 và input mình đưa vào tại indirect function thông qua `call rdx` rồi lấy kết quả đưa tiếp vào hàm như vậy và lặp lại tiếp tục ...
  
  +Search trên mạng `call indirect` trong wasm thì nó sẽ lấy hàm trong danh sách hàm được gọi là table theo offset nào đó nên mình search table trong wasm2c code và thấy `init_table`:
  
  ![image](https://user-images.githubusercontent.com/91442807/188603723-7196d781-a110-4404-8968-d3073d119e71.png)

  +Trong khi debug thì mình thấy hàm quyết định offset của function tại `v11`
  
  +Tới đây mình viết 1 script để đặt bp tại v11, v8, v6 để dump các giá trị đó ra 
  
### Gdb script - find order
```python
base=0x0000555555554000

import gdb

info=[]
gdb.execute("file ./abcdef")


#TEST FUNC RESULT

gdb.execute("b *0x5555555609B2")
gdb.execute("r")
gdb.execute("set $rdi=0x7b")

gdb.execute("b *0x555555560A40")
gdb.execute("c")
gdb.execute("set *(int64_t *)0x5555555900A0=0x555555590101")


for i in range(0x12c):
    gdb.execute("b *0x555555564F85")        #if 
    gdb.execute("c")
    v7=gdb.parse_and_eval("$rax")

    gdb.execute("b *0x555555564FDB")        #for
    gdb.execute("c")
    v6=gdb.parse_and_eval("$rax")

    gdb.execute("b *0x555555565027")        #func
    gdb.execute("c")
    v11=gdb.parse_and_eval("$rax")
    
    v8=-1
    if v7-1>=7:
        gdb.execute("b *0x555555565080")        #while
        gdb.execute("c")
        v8=gdb.parse_and_eval("$rax")


    info.append([hex(v11), hex(v8), hex(v6)])

print(info)
```
-Kết quả:
```python
order=[['0x13', '0xffffffe0', '0x5'], ['0xc', '0xffffffc8', '0x6'], ['0x1a', '-0x1', '0x1'], ['0x14', '0xffffff78', '0x7'], ['0x1', '0xffffff78', '0x5'], ['0xd', '0xffffffb0', '0x6'], ['0xb', '0xffffff38', '0x1'], ['0x1c', '0xffffff30', '0x6'], ['0x14', '0xffffffa0', '0x0'], ['0x13', '0xffffff50', '0x5'], ['0x1c', '0xffffff70', '0x2'], ['0x3', '0xffffff78', '0x3'], ['0x1c', '0xffffffe8', '0x7'], ['0x18', '0xffffffa0', '0x2'], ['0x18', '0xffffff28', '0x2'], ['0xa', '0xffffff98', '0x6'], ['0x10', '0xffffff98', '0x5'], ['0x1e', '0xffffff70', '0x1'], ['0xd', '0xffffffd0', '0x4'], ['0x19', '0xfffffff8', '0x7'], ['0xe', '0xffffffe8', '0x5'], ['0x2', '0xffffff10', '0x2'], ['0x1e', '0xfffffee0', '0x4'], ['0x9', '0xfffffee8', '0x2'], ['0x11', '0xfffffed8', '0x1'], ['0x18', '0xffffffe0', '0x4'], ['0xb', '0xffffff60', '0x4'], ['0x6', '0xffffff50', '0x5'], ['0xa', '0xfffffff0', '0x4'], ['0x16', '0xffffff60', '0x2'], ['0x2', '0xffffff08', '0x6'], ['0x7', '0xffffffc0', '0x1'], ['0x7', '0xffffff08', '0x1'], ['0x1e', '0xfffffef0', '0x0'], ['0x12', '0xffffffa0', '0x0'], ['0x15', '0xfffffee8', '0x5'], ['0x6', '0xffffff58', '0x0'], ['0x1e', '0xffffff40', '0x7'], ['0x17', '0xfffffee0', '0x5'], ['0x13', '0xffffffc8', '0x0'], ['0x14', '0xffffff70', '0x3'], ['0x7', '0xffffff20', '0x6'], ['0x11', '0xffffff30', '0x0'], ['0xa', '0xfffffff0', '0x2'], ['0x1', '0xffffff98', '0x5'], ['0x8', '0xffffffa8', '0x3'], ['0x1e', '0xffffff90', '0x0'], ['0x7', '-0x1', '0x5'], ['0x12', '0xffffff60', '0x1'], ['0x1d', '0xffffff48', '0x0'], ['0x1b', '0xffffff28', '0x4'], ['0x15', '0xffffff48', '0x4'], ['0x1', '0xffffffa8', '0x1'], ['0xa', '0xffffffa8', '0x4'], ['0x1c', '0xffffffb8', '0x2'], ['0x2', '0xfffffed8', '0x3'], ['0x18', '0xffffff78', '0x5'], ['0x5', '0xffffffb8', '0x4'], ['0x19', '0xffffff98', '0x5'], ['0x1e', '0xffffffb8', '0x4'], ['0x9', '0xffffffe8', '0x7'], ['0x18', '0xffffff68', '0x6'], ['0x4', '0xffffff98', '0x3'], ['0x10', '0xffffffe8', '0x3'], ['0x1e', '0xffffff20', '0x3'], ['0x1b', '0xffffff88', '0x6'], ['0x17', '0xffffff40', '0x5'], ['0x8', '0xfffffee0', '0x5'], ['0x10', '0xfffffff0', '0x6'], ['0xf', '0xffffff58', '0x3'], ['0x10', '0xfffffed8', '0x1'], ['0x2', '0xffffff28', '0x2'], ['0x1', '0xffffffd8', '0x0'], ['0x1b', '0xffffffd0', '0x5'], ['0x1c', '0xffffff28', '0x3'], ['0x7', '0xfffffef0', '0x4'], ['0x7', '0xfffffef8', '0x2'], ['0x6', '0xffffff18', '0x5'], ['0x1a', '0xffffff88', '0x7'], ['0x8', '0xffffff50', '0x0'], ['0xc', '0xfffffff0', '0x1'], ['0x19', '0xffffff10', '0x3'], ['0x13', '0xffffff90', '0x4'], ['0x1d', '0xfffffee8', '0x3'], ['0x13', '0xffffffc8', '0x0'], ['0x15', '0xffffff90', '0x4'], ['0x15', '0xffffffb0', '0x2'], ['0x1e', '0xffffffd8', '0x7'], ['0x3', '0xffffff58', '0x5'], ['0x19', '0xffffff68', '0x0'], ['0x1d', '0xfffffed8', '0x2'], ['0x11', '0xffffff88', '0x3'], ['0x7', '0xffffff18', '0x4'], ['0x1', '0xffffff70', '0x4'], ['0xb', '0xffffff48', '0x5'], ['0xc', '0xfffffed8', '0x3'], ['0x16', '0xffffff90', '0x2'], ['0x11', '0xffffffa8', '0x5'], ['0xe', '0xffffff90', '0x6'], ['0x4', '0xffffff08', '0x4'], ['0xa', '0xfffffff8', '0x3'], ['0xd', '0xffffff60', '0x4'], ['0x1a', '0xffffff60', '0x6'], ['0x1e', '0xffffff78', '0x3'], ['0x14', '0xffffff08', '0x1'], ['0xe', '0xffffffb0', '0x3'], ['0x18', '0xfffffff0', '0x5'], ['0xf', '0xffffffd8', '0x0'], ['0x6', '0xffffff10', '0x0'], ['0x18', '0xffffff28', '0x7'], ['0x16', '0xffffff38', '0x5'], ['0x16', '0xffffffa8', '0x1'], ['0x8', '-0x1', '0x6'], ['0xc', '0xffffffe8', '0x6'], ['0x1c', '0xffffff48', '0x3'], ['0x6', '0xffffff08', '0x1'], ['0x10', '0xffffffe8', '0x6'], ['0x10', '0xffffffe0', '0x3'], ['0x19', '0xffffffd0', '0x0'], ['0x5', '0xfffffee8', '0x0'], ['0x14', '0xffffffd0', '0x0'], ['0xe', '0xffffffe8', '0x7'], ['0x15', '0xffffff90', '0x6'], ['0x14', '0xffffff30', '0x4'], ['0x10', '0xffffffc8', '0x3'], ['0x7', '0xffffffc8', '0x0'], ['0x15', '0xffffff70', '0x3'], ['0x4', '0xffffff20', '0x3'], ['0x18', '0xfffffee0', '0x3'], ['0x7', '0xffffff48', '0x3'], ['0xb', '0xfffffef8', '0x5'], ['0x3', '0xffffff10', '0x5'], ['0x6', '0xffffff60', '0x2'], ['0xf', '0xffffffc0', '0x3'], ['0x1b', '0xffffff60', '0x3'], ['0x6', '0xfffffef8', '0x4'], ['0x14', '0xffffffe8', '0x7'], ['0x17', '0xfffffef8', '0x5'], ['0x12', '0xfffffef8', '0x3'], ['0x1e', '0xffffffc0', '0x4'], ['0x1', '0xffffffd8', '0x6'], ['0x1d', '0xffffff10', '0x2'], ['0x9', '0xffffff20', '0x4'], ['0x18', '0xfffffee8', '0x6'], ['0xb', '0xfffffef0', '0x2'], ['0xb', '0xffffff18', '0x2'], ['0x14', '0xffffff60', '0x5'], ['0x14', '0xfffffff0', '0x6'], ['0xd', '0xffffff38', '0x0'], ['0x9', '0xffffff28', '0x3'], ['0xd', '0xfffffee8', '0x1'], ['0x4', '-0x1', '0x4'], ['0x12', '0xffffffa0', '0x3'], ['0x1c', '0xffffffd0', '0x3'], ['0x2', '0xffffff58', '0x1'], ['0x1b', '0xffffffa8', '0x5'], ['0x4', '0xfffffef0', '0x5'], ['0x8', '0xffffff80', '0x2'], ['0xa', '0xffffff78', '0x1'], ['0xb', '0xfffffef0', '0x2'], ['0x5', '0xfffffee0', '0x6'], ['0x19', '0xffffffd8', '0x4'], ['0x7', '0xffffff10', '0x6'], ['0x11', '0xffffffd0', '0x2'], ['0x1e', '0xffffffb0', '0x2'], ['0x5', '0xffffff90', '0x3'], ['0x18', '0xfffffee0', '0x5'], ['0x5', '0xfffffff0', '0x4'], ['0xb', '0xffffff98', '0x0'], ['0xd', '0xffffff98', '0x0'], ['0x17', '0xffffff90', '0x6'], ['0x14', '0xffffff90', '0x3'], ['0x7', '0xffffffd8', '0x7'], ['0x2', '0xffffff00', '0x1'], ['0x1a', '0xffffff50', '0x3'], ['0x13', '0xffffffd0', '0x4'], ['0xb', '0xffffff08', '0x2'], ['0x10', '0xffffff70', '0x7'], ['0x5', '0xfffffed8', '0x0'], ['0x9', '0xffffffd8', '0x2'], ['0x6', '0xfffffef0', '0x3'], ['0x6', '0xffffff70', '0x6'], ['0x1', '0xffffff80', '0x2'], ['0x16', '0xffffffb8', '0x7'], ['0x14', '0xfffffee8', '0x4'], ['0x9', '0xfffffef0', '0x0'], ['0x1a', '0xffffff20', '0x2'], ['0x1a', '0xffffffd0', '0x6'], ['0x14', '0xfffffee0', '0x2'], ['0x15', '0xffffff68', '0x5'], ['0xf', '0xffffff20', '0x7'], ['0x6', '0xffffff60', '0x4'], ['0x16', '0xffffffb0', '0x0'], ['0xb', '0xffffffa0', '0x5'], ['0xe', '-0x1', '0x6'], ['0x16', '0xffffff88', '0x5'], ['0x10', '0xffffffd0', '0x4'], ['0x10', '-0x1', '0x6'], ['0x10', '0xffffffd8', '0x3'], ['0x1d', '0xffffff30', '0x3'], ['0x8', '0xffffff70', '0x6'], ['0x1d', '-0x1', '0x6'], ['0x11', '0xfffffed8', '0x2'], ['0x17', '0xffffff48', '0x3'], ['0x3', '0xffffffd0', '0x0'], ['0x17', '0xffffff20', '0x7'], ['0x1b', '0xffffffb0', '0x6'], ['0x4', '0xfffffff0', '0x2'], ['0xe', '0xfffffff8', '0x1'], ['0x1', '0xffffff98', '0x6'], ['0xb', '0xffffff10', '0x3'], ['0x12', '-0x1', '0x6'], ['0x12', '0xfffffff0', '0x6'], ['0x11', '0xffffffb8', '0x3'], ['0x5', '0xfffffee8', '0x3'], ['0x15', '0xfffffef8', '0x2'], ['0x3', '0xffffff90', '0x2'], ['0xd', '0xffffffb8', '0x2'], ['0x5', '0xffffff98', '0x3'], ['0xf', '0xfffffed8', '0x1'], ['0x18', '0xfffffed8', '0x4'], ['0x1d', '0xffffffe0', '0x3'], ['0x12', '0xffffff78', '0x4'], ['0x14', '0xfffffef8', '0x0'], ['0xc', '0xfffffee0', '0x4'], ['0x1a', '0xfffffef0', '0x3'], ['0xc', '0xffffffd8', '0x4'], ['0x12', '0xffffffe8', '0x7'], ['0x14', '0xffffff20', '0x6'], ['0x2', '0xffffff70', '0x6'], ['0xb', '0xffffff60', '0x2'], ['0xa', '0xffffff08', '0x6'], ['0x1d', '0xffffffe0', '0x3'], ['0x1e', '0xfffffef8', '0x2'], ['0x1e', '0xffffffc0', '0x2'], ['0x17', '0xffffff58', '0x2'], ['0x2', '0xffffff50', '0x6'], ['0x1d', '0xffffff20', '0x0'], ['0x1d', '0xfffffef0', '0x4'], ['0x14', '0xffffffa8', '0x1'], ['0x12', '0xfffffef8', '0x7'], ['0x8', '0xffffff28', '0x6'], ['0x10', '0xffffff70', '0x3'], ['0x12', '-0x1', '0x5'], ['0xa', '0xffffffd0', '0x6'], ['0xf', '0xffffff20', '0x7'], ['0x5', '0xffffff90', '0x1'], ['0xf', '0xfffffef0', '0x2'], ['0x8', '0xffffffe0', '0x5'], ['0xd', '0xffffff88', '0x2'], ['0x6', '0xffffff98', '0x7'], ['0x16', '0xffffff18', '0x4'], ['0x5', '0xfffffed8', '0x1'], ['0x16', '0xffffffc8', '0x3'], ['0x14', '0xffffff30', '0x3'], ['0x3', '0xffffff18', '0x5'], ['0x19', '0xffffffe0', '0x6'], ['0xe', '0xffffffb0', '0x1'], ['0x8', '0xffffff80', '0x1'], ['0x18', '0xffffffe0', '0x0'], ['0x18', '0xffffff20', '0x4'], ['0x5', '0xffffffc0', '0x0'], ['0x10', '0xfffffef0', '0x1'], ['0x1d', '0xffffff38', '0x2'], ['0x1a', '0xffffff68', '0x7'], ['0x14', '0xfffffef8', '0x4'], ['0x8', '0xffffff40', '0x5'], ['0xc', '0xffffff40', '0x1'], ['0x13', '0xffffffa8', '0x0'], ['0x2', '0xffffff90', '0x2'], ['0x1e', '0xfffffff0', '0x2'], ['0x12', '0xffffffe0', '0x2'], ['0x11', '0xffffff78', '0x0'], ['0x12', '0xffffffd0', '0x5'], ['0xe', '0xfffffed8', '0x2'], ['0x17', '0xffffff78', '0x7'], ['0x1d', '0xffffffb8', '0x5'], ['0x19', '0xffffff70', '0x4'], ['0x17', '0xffffff08', '0x5'], ['0x16', '0xffffff38', '0x0'], ['0x7', '0xfffffee8', '0x7'], ['0x10', '0xffffffa8', '0x2'], ['0x1a', '0xffffffe0', '0x7'], ['0x1c', '0xffffff98', '0x6'], ['0x1b', '0xffffff98', '0x3'], ['0x14', '0xffffff28', '0x3'], ['0x1e', '0xffffff90', '0x7'], ['0x10', '-0x1', '0x7'], ['0x1c', '0xfffffed8', '0x0'], ['0x8', '0xffffff70', '0x1'], ['0xf', '0xffffff00', '0x2'], ['0x6', '0xffffffe8', '0x1'], ['0x6', '0xfffffff0', '0x1'], ['0xd', '0xffffffd0', '0x2'], ['0xb', '0xffffff58', '0x7'], ['0x1c', '0xffffffa0', '0x7'], ['0x8', '0xffffffe0', '0x7'], ['0x1d', '0xffffff70', '0x0'], ['0x1b', '0xfffffff8', '0x0'], ['0x1a', '0xffffff78', '0x6']]
```

-Trong quá trình làm mình thấy pseudo code của ghidra lại ra kết quả chính xác hơn IDA và cũng dễ viết script để lấy code:
### Ghidra script - dump decompiled code
```python

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

program = getCurrentProgram()
ifc = DecompInterface()
ifc.openProgram(program)

func=['w2c__ZN10propaganda3p2917hfd7f494733a078d8E', 'w2c__ZN10propaganda3p2817he27455e4cd995b83E', 
'w2c__ZN10propaganda3p2717h8a7d87e17da8fc0eE', 'w2c__ZN10propaganda3p2617he727b6abf87f90c8E', 'w2c__ZN10propaganda3p2517h87c16b6b5115d429E', 'w2c__ZN10propaganda3p2417h3d22c5be10ddc8dbE', 'w2c__ZN10propaganda3p2317h4a3b8602317a8daeE', 'w2c__ZN10propaganda3p2217h6da710315a7e2eccE', 'w2c__ZN10propaganda3p2117h567244e1cbe734e2E', 'w2c__ZN10propaganda3p2017h32497499afcc623cE', 'w2c__ZN10propaganda3p1917h6a53dfde22cc706eE', 'w2c__ZN10propaganda3p1817h44f8fd2ff7300d3cE', 'w2c__ZN10propaganda3p1717hd9ca530b301574b6E', 'w2c__ZN10propaganda3p1617hc85d80eff4ba480aE', 'w2c__ZN10propaganda3p1517h5060049a2246c191E', 'w2c__ZN10propaganda3p1417h107e9531a1019d42E', 'w2c__ZN10propaganda3p1317ha92239738854c15eE', 'w2c__ZN10propaganda3p1217h5b8cf4a705c82ff2E', 'w2c__ZN10propaganda3p1117h8fbd45fc64774508E', 'w2c__ZN10propaganda3p1017h098a84bf5693bb8aE', 'w2c__ZN10propaganda2p917h3a51030aa13ff5deE', 'w2c__ZN10propaganda2p817h2a0221cd2c4636b0E', 'w2c__ZN10propaganda2p717h5a888a95f52a44b4E', 'w2c__ZN10propaganda2p617h1d94232d543e2e8dE', 'w2c__ZN10propaganda2p517h3e44f560511a137bE', 'w2c__ZN10propaganda2p417hf1e6c1a24781f115E', 'w2c__ZN10propaganda2p317he86dcba8a8dbde4fE', 'w2c__ZN10propaganda2p217h78e98b0bb46abc07E', 'w2c__ZN10propaganda2p117he0f8c476c26d81ceE', 'w2c__ZN10propaganda2p017h1127525241f966daE']
for i in range(len(func)):
    function = getGlobalFunctions(func[i])[0]

    results = ifc.decompileFunction(function, 0, ConsoleTaskMonitor())
    decompiled=results.getDecompiledFunction().getC()
    decompiled=decompiled.replace(func[i], "def func_%d"%(i+1)).replace(";","").replace("ulong","").replace("{","").replace("}","").replace("\n","")
    ff=open("D:\download\Tool RE\ghidra_10.0.4_PUBLIC\decompiled.txt", 'a')
    ff.write(decompiled)
```
-Cuối cùng sửa syntax lại cho đúng rồi đem vào z3 thôi, ở đây mình lấy kết quả kế cuối rồi rồi tiếp tục trace ngược lại lên đầu:

Xem [propaganda.py](https://github.com/Twi1ight12/CTF/blob/main/Balsn/2022/propaganda.py)

Kết quả đối với số đầu tiên: 0x61797b4e534c4142 -> BALSN{ya

Tiếp tục đối với các số còn lại, script chạy khá lâu nên mình lười chạy lại :))


