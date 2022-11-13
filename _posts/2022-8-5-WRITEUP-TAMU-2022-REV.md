---
layout: post
title: "[TAMU 2022]: Labyrinth"
categories: rev
toc: true
---


## Labyrinth

-Như đề nói thì chương trình cho 5 cái binary tạo maze, nhiệm vụ là phải nhập input đúng cho liên tục 5 binary để nhận flag

-Lấy 1 binary phân tích thử::

![image](https://user-images.githubusercontent.com/91442807/201515899-38f28415-846b-43cc-bb10-37d862bf9f1d.png)

-Main bắt đầu với function_213

-![image](https://user-images.githubusercontent.com/91442807/201515926-96fb1ce5-c87e-47fb-9ade-c53c83f4eafd.png)

-Function xử lí input rồi đi tới các hàm khác dựa vào kết quả tính được (sau khi phân tích thì có 3 cách xử lí input là add, sub và xor).

-Function_354 là hàm cần tới vì nó trả về exit(0) như đề nói:

![image](https://user-images.githubusercontent.com/91442807/201515954-7f1c3aa8-2272-4901-8e5e-b5d3139a3d78.png)


--> Tóm lại chương trình: bắt đầu với function_213 rồi với mỗi function chọn input phù hợp để đến các function khác và cuối cùng phải đến được function_354.

-Đầu tiên là lấy các function được gọi, đặc biệt là function đầu và cuối

->Để ý thấy function đầu trong hàm main và function cuối nằm tại địa chỉ của call exit(call 1050) đầu -9, (ta chỉ cần lấy địa chỉ của call exit một lần để tính toán hàm cuối còn về sau ko cần lấy nữa.)

![image](https://user-images.githubusercontent.com/91442807/201516000-200c3e10-064a-4b14-af50-8a2a97781aef.png)

![image](https://user-images.githubusercontent.com/91442807/201516012-b7c9e473-c8b4-47bd-8b1f-bacfa2002bef.png)

-> Kết quả các hàm được gọi được lưu vào call_graph

-Tiếp đến ta phân tích các đoạn code từ các hàm trong call_graph trở đi để lấy các giá trị và điều kiện của nó:

![image](https://user-images.githubusercontent.com/91442807/201516040-872082be-7e78-474a-8c4b-f88e38bc0cd8.png)

-Lấy các giá trị tính toán và giá trị so sánh, đồng thời đảo ngược tính toán để tìm ra các input phù hợp

![image](https://user-images.githubusercontent.com/91442807/201516048-ee86b81b-ad2a-4cd0-b712-8b8411911f82.png)

![image](https://user-images.githubusercontent.com/91442807/201516059-5cf3c8ec-e31d-475e-8ecf-60f69eb8a466.png)

-> Sử dụng biến ma[] vì một số hàm có 2 giá trị trùng nhau với điều kiện khác nhau.

-Sau khi lấy tính toán được địa chỉ và các giá trị input phù hợp nhưng có vấn đề là làm sao biết giá trị input nào gắn với địa chỉ nào (vì không như IDA tính toán ra 300 thì nhảy vô func_300)

-Quan sát trong IDA có 2 lệnh nhảy cần quan tâm là jz và jnz (trong capstone là je và jne) :

  +đối với jz sau lệngh cmp thì cần phân tích đoạn code từ địa chỉ trong jz trở đi để lấy địa chỉ cần tới.
  
  +đối với jnz thì sau lệnh cmp chỉ cần phân tích tiếp đoạn code.
  
  +còn một số lệnh như ja thì không quan trọng.
  
![image](https://user-images.githubusercontent.com/91442807/201516097-600df035-4d17-4114-9421-c47b54c789bd.png)

![image](https://user-images.githubusercontent.com/91442807/201516103-ba83a373-44db-485a-9a15-39321a78dd17.png)

-Tới đây là coi như xong

->Mục đích là mình tạo ra call_graph có định dạng như sau:

  +Ví dụ hàm đó tính toán input và có 3 hàm cần chọn để nhảy: call_graph={func_x: [input1, func_a, input2, func_b, input3, func_c], ....}

  +Tức là nếu chọn input1 thì nhảy tới func_a, nếu chọn input2 thì nhảy tới func_b ,.....
  
->Tới đây thì có thể dùng BFS để giải:

![image](https://user-images.githubusercontent.com/91442807/201516175-2ca217c3-c458-4bf9-bc3f-cd1f8fa67fcd.png)


-Kết quả:

![image](https://user-images.githubusercontent.com/91442807/201516186-0ba5d9bc-8d43-41dd-8688-243b854ef996.png)

### Script solve (dùng capston + bfs)

```python
from capstone import *
from capstone.x86 import *


md=Cs(CS_ARCH_X86, CS_MODE_64)
f=open('inss.txt','r').read()
code=open('elf','rb').read()[0x1155:0x18890]

call_graph={}
pattern=b'\x55\x48\x89\xe5'             #push rbp, mov rbp, rsp
idx=0
for inss in md.disasm(code,0x1155):
    #print(inss)
   
    if inss.mnemonic=='call' and inss.op_str[:2]=='0x':
        if inss.address>0x1155:
            if inss.op_str not in call_graph:
                if inss.op_str=='0x1050' or inss.op_str=='0x1040' or inss.op_str=='0x1030':
                    if inss.op_str=='0x1050':
                        if idx==0:
                            nn=hex(inss.address-9)
                            idx+=1
                    continue
                call_graph[inss.op_str]=[]


# print(call_graph)

for i in call_graph:
    # print(i)
    addr_func=i
    if addr_func==nn:continue
    mapp=[]
    ma=[]
    for ins in md.disasm(open('elf','rb').read()[int(addr_func,16):0x18890],int(addr_func,16)):
        if ins.address==int(addr_func,16) and ins.mnemonic=='push' and ins.op_str=='rbp':
            #print(f"Found:{ins.address} {ins.mnemonic} {ins.op_str}")
            sstc=1
        
        if ins.op_str.split(', ')[0]=='eax' and ins.mnemonic=='sub' or ins.mnemonic=="add" or ins.mnemonic=='xor':
            #print(f'{ins.mnemonic} {ins.op_str}')
            val=int(ins.op_str.split(', ')[1],16)
            if ins.mnemonic=='sub':
                status=1
            if ins.mnemonic=='add':
                status=2
            if ins.mnemonic=='xor':
                status=3
            
        if ins.mnemonic=='cmp':
            
            cmpval=int(ins.op_str.split(', ')[1],16)
            if cmpval not in ma:
                if status==1:
                    ma.append(cmpval)
                    mapp.append(str((cmpval+val)))
                if status==2:
                    ma.append(cmpval)
                    mapp.append(str((cmpval-val)&0xffffffff))
                if status==3:
                    ma.append(cmpval)
                    mapp.append(str(val^cmpval))
        
        if ins.mnemonic=="je":
            for k in md.disasm(open('elf','rb').read()[int(ins.op_str,16):0x18890],int(ins.op_str,16)):
                
                if k.mnemonic=='call' and k.op_str!='0x1040' and k.op_str!='0x1050' and k.op_str!='0x1030':
                    mapp.append(k.op_str)
                    break
        
        if ins.mnemonic=="jne":
            for k in md.disasm(open('elf','rb').read()[ins.address:0x18890],ins.address):
                
                if k.mnemonic=='call' and k.op_str!='0x1040' and k.op_str!='0x1050' and k.op_str!='0x1030':
                    mapp.append(k.op_str)
                    break

                      
        if ins.mnemonic=='ret':
            break
       
       
    call_graph[i]=mapp
print(call_graph)
print("Done")    

src=''
for mm in call_graph:
    if src=='':
        src=mm
        break
dest=nn
print(f'Start: {src}')
print(f'End: {dest}')    
queue = []                                          # 1.
visited = set()                                     # 2.
queue.append((src, ''))                             # 3.
while len(queue) > 0:                               # 4.0
    first, path = queue[0]
    if first == dest:                               # Handle reaching dest
        print(path,end='')
        break
    visited.add(first)                              # 4.1
    for index in range(len(call_graph[first])//2):     # Require index
        reachable = call_graph[first][2*index+1]
        if reachable not in visited:
            char = call_graph[first][2*index]                    # To get NEWS[index] for path//neu chon index thi lay char[index]
            queue.append((reachable, path + char+'\n'))  # 4.2
    del queue[0]
```


