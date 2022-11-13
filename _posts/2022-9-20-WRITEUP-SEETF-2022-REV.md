---
layout: post
title: "[SEETF 2022]: REV"
categories: rev
toc: true
---


## 1. babyreeee

Chương trình lấy chuỗi mình nhập, sau đó lấy từng kí tự trong chuỗi +69 xor với thứ tự của kí tự trong chuỗi rồi so sánh với chuỗi cố định

->Làm ngược lại là ra flag


## 2. bestsoftware

Reverse file .NET: chương trình lấy name, email và licensekey trong đó name và email được cho trước.

![image](https://user-images.githubusercontent.com/91442807/173990631-03dcaf41-092d-4c12-9e13-f3d3eaccce64.png)

Lúc đó ta chỉ cần lấy chuỗi (name + "1_l0v3_CSh4rp" + email) đem đi SHA256 là ra flag


## 3. stomped 

Cái này mình debug rồi dùng z3 để giải thôi hoặc nếu lười reverse thì dùng angr (angr cũng hoạt động tương tự z3 nhưng thay vì z3 mình tự tìm các điều kiện để thêm vào thì angr sẽ tìm các điều kiện đó cho mình)

```python
import angr
import claripy

FLAG_LEN = 59


proj = angr.Project("./chall", main_opts={'base_addr': 0x0}) 

flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(FLAG_LEN)]
flag = claripy.Concat( *flag_chars + [claripy.BVV(b'\n')]) 

state = proj.factory.full_init_state(args=['./chall'], stdin=flag)

for k in flag_chars:
    state.solver.add(k >= 0x20)
    state.solver.add(k <= 0x70)

simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x1257, avoid=0x128a)

if (len(simgr.found) > 0):
    for found in simgr.found:
        print(found.posix.dumps(0))
```
![1](https://user-images.githubusercontent.com/91442807/177960662-e11fbe03-62f7-4b86-b183-fc2a521c12a9.png)

## 4. magic

-Quan sát pseudo-code của main không thấy chương trình không lấy input hay in ra cái gì đặc biệt

-Chuyển qua asm xem thử:

![1](https://user-images.githubusercontent.com/91442807/173991885-d63b425c-0f30-47b6-ab5b-968d7a3df4d7.png)

-Ta thấy 2 cái quan trọng là fgets() có lẽ là dùng để lấy input  mà "nope" có lẽ là kết quả sau khi check input nhưng nằm ở vùng text màu đỏ nên có IDA không nhận diện được.

->Ta thử fix lại bằng cách kéo vùng code của main đến hết vùng text màu đỏ

-Tới đây có vẻ main đã nhận được đầy đủ code nhưng F5 lại không có gì khác so với trước đó.

-Ta thấy được mỗi vùng code được chia ra và ở cuối là call function sub_401290() hoặc sub_4012F0(), bấm vào xem thử: 

![image](https://user-images.githubusercontent.com/91442807/173993458-9b4f1446-6231-4b16-a481-3f04f24fa885.png)

-Thấy được hai hàm timeGetTime() và ExitProcess() nên có vẻ là anti-debug

->Nope nó lệnh call lại và đúng là F5 nó decompile được thêm một chút -> nope tiếp các lệnh call còn lại ta được main hoàn chỉnh.

-Phân tích hàm main và debug ta thấy được chương trình mở thanh ghi và check giá trị của một key:

![image](https://user-images.githubusercontent.com/91442807/173995005-df66eb5b-045e-4edc-a88f-cda050336820.png)

-Key ở đây là v13 sau khi encrpt bằng RC4(sub_401170) sẽ check vơi giá trị tại v24, decrypt RC4 ta thu được v13="hunter_123456_qwerty"

-Pass được sẽ thấy chương trình lấy tiếp input khác nữa và yêu cầu tối đa số (vì có hàm atoi() nên input phải là số) và số sánh với 0xB0241528

![image](https://user-images.githubusercontent.com/91442807/173995490-0aaf2eb5-9232-42e9-8fdb-0db8e2ea14cf.png)

Hàm check khá đơn giản:

![image](https://user-images.githubusercontent.com/91442807/173995728-fa8c22f9-c2cd-4047-96fd-01babea9d95d.png)

Nên tới đây ta viết lại hàm check rồi bruteforce từ 0 đến 99999999 là ra.



















