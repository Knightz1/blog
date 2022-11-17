---
layout: post
title: "[FLAREON9 2022]: Part2"
categories: rev
toc: true
---


## 7 - anode

### Phân tích ban đầu 

- Chạy thử chương trình chỉ hỏi flag và check flag

- Kích thước file khá lớn khiến mình nghĩ có nên load vào IDA không vì có thể rất lâu IDA mới load xong

![image](https://user-images.githubusercontent.com/91442807/202184897-aa92f10e-c0e3-4c8c-b657-17356a80eb86.png)

- Có vẻ là chương trình có **code js** ở bên trong

- Mở file bằng **notepad++** thử:

![image](https://user-images.githubusercontent.com/91442807/202185542-6e288855-64ae-4802-9b00-fe2dcf00e7f4.png)

- Có vẻ phần check flag cũng là phần code js nằm ở cuối file 

- Searh gg mình tìm được một tool là [nexe-decompile](https://www.npmjs.com/package/nexe-decompile) dùng để extract file js ra [xem ở đây](https://github.com/Twi1ight12/CTF/blob/main/flareon9/7-anode/anode.js)

- Đọc code ta thấy đầu tiên nó check độ dài flag phải bằng 44 

-Nhập thử: 

![image](https://user-images.githubusercontent.com/91442807/202187763-2b75a965-fd60-4cfb-ac77-2128f79585c1.png)

- Quan sát ta thấy đối với cái script bị extract thì bị lỗi còn cái file exe thì lại không (có lẽ là yếu tố code c của file exe ảnh hưởnng), suy nghĩ hoài mình ko biết cách pass làm sao nên mình quyết định làm việc trực tiếp trên file exe luôn, bỏ script js qua một bên.


### Dump kết quả cuối

- Đầu tiên mình sửa code lại để in ra kết quả cuối cùng:

![image](https://user-images.githubusercontent.com/91442807/202188868-2ae75584-a825-4dfe-9f18-2f19a6dea994.png)

- Lưu ý: ***vừa thêm và xóa code phải đảm bảo sao cho số bytes xóa và số bytes thêm bằng nhau để đảm bảo kích thước cho file khi chạy không bị crash***

- Các trường hợp **switch-case** có các số random nên mình đoán khi chạy cùng input ở các thời điểm khác nhau sẽ cho ra kết quả khác nhau nhưng lại không như vậy:

![image](https://user-images.githubusercontent.com/91442807/202190505-b3e7c094-a3b1-43a0-bab7-f79240c08296.png)


### Dump giá trị state

- Ta cần giá trị state để biết thứ tự các **case** trong suốt quá trình chạy đến kết quả cuối

![image](https://user-images.githubusercontent.com/91442807/202196902-eb987a7e-5534-4e49-b9ef-8d959ae21fe5.png)

- [anode_pat1.exe]()

![image](https://user-images.githubusercontent.com/91442807/202197238-67fb8466-d5cd-47ad-9288-4b63113b0900.png)


### Dump giá trị random

- Ta cần biết giá trị random ở một số case:

![image](https://user-images.githubusercontent.com/91442807/202198163-42bbc9e3-ca37-4ee9-93a9-90c10e27d222.png)

- Tiếp tục patch để in ra bởi vì chúng ta biết nó không hề random, như vầy:

![image](https://user-images.githubusercontent.com/91442807/202198531-fec2a19d-cf94-45a6-9649-4d898c8aae07.png)

--> Có quá nhiều trường hợp có số random nên ta không thể patch bằng tay hết và còn phải lo về kích thước bytes nữa -> script:

```python
f=open("anode_pat1.exe", 'rb').readlines()
f1=open("anode_pat1.exe", 'rb').read()
out=b""
patch=open("anode_pat2.exe", 'wb')

for li in f:
    
    if b'Math.floor(Math.random() * 256)' in li:
        add=b'console.log("-->"+Math.floor(Math.random() * 256));\n'
        add=add.rjust(len(li),b' ')
        f1=f1.replace(li, add)
    
patch.write(f1)
```

![image](https://user-images.githubusercontent.com/91442807/202199625-7968dc65-4b8c-4e44-b0e1-5c6da6f89377.png)

### Dump if/else

- Các case còn có 2 trường hợp if/else nên ta cần phải dump ra xem mỗi case nó theo nhánh nào

![image](https://user-images.githubusercontent.com/91442807/202201268-5c337556-be46-48c8-8620-09ce9dab69f9.png)

- Thêm như vầy nếu mỗi case theo trường hợp **if** thì in ra **c1** còn không in ra gì thì theo trường hợp **else**

- Tương tự như trên rất khó để làm bằng tay

```python
f=open("anode_pat1.exe", "rb").readlines()
f1=open("anode_pat1.exe", "rb").read()

case=open("case.exe", 'wb')

import re

for li in range(len(f)):
    if (re.findall(r"""case \d{3,}:\n""".encode(),f[li]) != []):
        if b'case 185078700' in f[li]:
            continue
        assert b"if" in f[li+1]
        if b'Math.floor(Math.random()' in f[li+2]:
            add=b'console.log("c1,  "+Math.floor(Math.random() * 256));\n'
            add=add.rjust(len(f[li+2]),b' ')

        else:
            add=b'console.log("c1");\n'
            add=add.rjust(len(f[li+2]),b' ')
        
        f1=f1.replace(f[li+2], add)
case.write(f1)
```
![image](https://user-images.githubusercontent.com/91442807/202202081-0447eb85-8d15-4f54-b691-799113bb8069.png)


### Kết hợp

- Đến đây ta đã có hết dữ liệu ta cần, bây giờ chỉ việc build lại luồng thôi

- Code build dựa trên điều kiện của mỗi trường hợp:

- [print_flow.py](https://github.com/Twi1ight12/CTF/blob/main/flareon9/7-anode/print_flow.py)

- Kết quả: [flow.txt](https://github.com/Twi1ight12/CTF/blob/main/flareon9/7-anode/flow.txt)

### Get flag

- Đến đây thì đảo ngược thứ tự flow lại thôi 

- [solve.py](https://github.com/Twi1ight12/CTF/blob/main/flareon9/7-anode/solve.py)

![image](https://user-images.githubusercontent.com/91442807/202204647-5ddedd69-31ac-47c1-9a5f-05484a69b79b.png)


## 8 - backdoor

(Phần deobfuscate không nhớ mình đem code vứt đi mà mình thì lười làm lại nên xin dời lại có gì viết sau :<<)
