---
layout: post
title: "[FLAREON9 2022]: Part3"
categories: rev-writeup
toc: true
---

## 9 - encryptor

- Hàm cần quan tâm:

![image](https://user-images.githubusercontent.com/91442807/202218850-5796cfbc-d11a-4cab-8edb-f6124a730e35.png)

![image](https://user-images.githubusercontent.com/91442807/202219020-44afd606-4057-4e4f-b26c-e973bcafa624.png)

- Cơ bản là chương trình sẽ nhận tham số là file có đuôi **.EncryptMe** sau khi encrypt sẽ lưu kết quả vào file có đuôi **.Encrypted**

### Encrypt data

- Hàm encrypt:

![image](https://user-images.githubusercontent.com/91442807/202221934-da5d2eb0-638d-4065-bfa4-f5c513f4493e.png)

- **sub_4020F0** có chuỗi hex **expand 32-byte k** nên ta có thể đoán được là chacha20 hoặc salsa20

![1](https://user-images.githubusercontent.com/91442807/202222662-70b47b13-ccad-47e3-bc17-783700d80fb5.png)

- Do tham số đầu vào một chuỗi bytes gồm 32 bytes và 1 chuỗi 12 bytes nên ta đoán đây là **key** và **nonce** của thuật toán, do **salsa20** chỉ sử dụng 8 bytes cho **nonce** nên ta có thể chắc rằng đây là thuật toán **chacha20**

- Tham số **a2** đưa vào chính là nội dung của file cần encrypt

- Kết quả được lưu vào file **.Encrypted**

### Encrypt key+nonce

![image](https://user-images.githubusercontent.com/91442807/202232530-538409ae-c194-48a4-a799-511c99b1cff8.png)

- Tiếp đến key+nonce được encrypt bởi **sub_4016CC** sau đó lưu kết quả vào **v9** sau đó được đưa vào file **.Encrypted** luôn

- Phân tích hàm đó ta thấy nó thực hiện việc encrypt dựa vào các bytes từ **unk_404020**

- Trace ngược lại xem nó được tạo từ đâu


![image](https://user-images.githubusercontent.com/91442807/202225802-b93d41c0-b33a-47c4-b384-844f549b4f91.png)

- Có vẻ nó được tạo từ lúc chạy chương trình 

- Nếu để ý các giá trị ban đầu của mảng ta sẽ nhận thấy : 0x10001=65537 giống với số e trong thuật toán RSA

- Dựa vào đó có thể phân tích lại các hàm: 

![image](https://user-images.githubusercontent.com/91442807/202232681-29e547e3-a2b5-47fb-b029-03ff4ff3cfd9.png)

--> Thuật toán để encrypt key+nonce là **RSA**  (tham khảo [ở đây](https://phgvee.wordpress.com/2022/10/05/crypto-rsa-va-nhung-hinh-thuc-tan-cong/))

### Decrypt key+nonce và get flag

- Bây giờ ta có **N**, **d=65537** và **v9** đều được lưu vào file **.Encrypted** --> Tính toán được key+nonce

- Từ key+nonce -> flag

```python
from Crypto.Cipher import ChaCha20
#lấy data của e, N, key_enc ngăn cách nhau bởi "\x0A" từ file SuspiciousFile.txt.Encrypted 
e=65537
N=0xdc425c720400e05a92eeb68d0313c84a978cbcf47474cbd9635eb353af864ea46221546a0f4d09aaa0885113e31db53b565c169c3606a241b569912a9bf95c91afbc04528431fdcee6044781fbc8629b06f99a11b99c05836e47638bbd07a232c658129aeb094ddaf4c3ad34563ee926a87123bc669f71eb6097e77c188b9bc9
key_enc=0x5a04e95cd0e9bf0c8cdda2cbb0f50e7db8c89af791b4e88fd657237c1be4e6599bc4c80fd81bdb007e43743020a245d5f87df1c23c4d129b659f90ece2a5c22df1b60273741bf3694dd809d2c485030afdc6268431b2287c597239a8e922eb31174efcae47ea47104bc901cea0abb2cc9ef974d974f135ab1f4899946428184c

res=hex(pow(key_enc,e,N))[2:]
res=bytes.fromhex(res)[::-1]

key=res[:32]
nonce=res[32:].replace(b"\x00\x00\x00\x00",b'')

ct=b'\x7f\x8a\xface\x9c^\xf6\x9e\xb9\xc3\xdc\x13\xe8\xb21:\x8f\xe3m\x94\x864!F+o\xe8\xad0\x8d*y\xe8\xea{f\t\xd8\xd0X\x02=\x97\x14k\xf2\xaa`\x85\x06HM\x97\x0eq\xea\x82\x065\xbaK\xfcQ\x8f\x06\xe4\xadi+\xe6%['
decipher=ChaCha20.new(key=key, nonce=nonce)
print(decipher.decrypt(ct))
```
- Kết quả: 
 
![image](https://user-images.githubusercontent.com/91442807/202233734-ab2d29b3-ff51-49ce-ad17-3ee41055e087.png)


## 10 - Nur geträumt

- Bài này chỉ hơi khó ở chỗ cài tool

- Có thể tham khảo các bước cài đặt [ở đây](https://www.emaculation.com/doku.php/mini_vmac_setup)

- Sau khi cài xong có thể kéo thể tệp image vào (lưu ý đổi tên image lại vì chương trình có vẻ ko nhận image có kí tự non-ascii)

- Đề cho chương trình + disassembler luôn:

![image](https://user-images.githubusercontent.com/91442807/202242988-a43eda3f-f4b5-49b6-94a9-168e5c7e136c.png)

- Chạy thử: 

![image](https://user-images.githubusercontent.com/91442807/202243158-42a2bb81-cbb2-478b-a806-a8c0713c59e3.png)

- Dựa vào đó có thể đoán được là cần nhập đúng **password** để chương trình decode ra flag.

- Mở disassembler lên thử thấy **flag bị encrypt**:

![image](https://user-images.githubusercontent.com/91442807/202243784-b5581b15-a7cc-4c48-8628-e1a506262ff0.png)

- Xem bằng hex view:

![image](https://user-images.githubusercontent.com/91442807/202243982-dd82ae74-2ea7-4572-8e48-58f02afdd7a0.png)

- Coi code thử thấy có một hàm khá quan trọng:

![image](https://user-images.githubusercontent.com/91442807/202244310-c6572f82-771b-4266-8da8-dca90a577769.png)

- Vừa tham khảo assembly [ở đây](http://wpage.unina.it/rcanonic/didattica/ce1/docs/68000.pdf) vừa đọc code, chương trình chỉ đơn giản là **xor** cái **encrypted flag** đó với **password** mình nhập

- Dựa vào phần đuôi của flag **@flare-on.com** xor ngược lại có **du etwas Zeit** search thử trên mạng thì thấy đó là lời của một bài hát 

- Lấy lời bài hát xor với phần còn lại có **Dann_singe_ich_ein...**

```python
known=b"@flare-on.com"

kn=list(b'Hast du etwas Zeit f')+[252]+list(b"r mich ")
enc_flag=[0xc, 0x0, 0x1d, 0x1a, 0x7f, 0x17, 0x1c, 0x4e, 0x2, 0x11,0x28, 0x8, 0x10, 0x48, 0x5, 0x0, 0x0, 0x1a, 0x7f, 0x2a, 0xf6, 0x17, 0x44, 0x32, 0xf, 0xfc, 0x1a, 0x60, 0x2c, 0x8, 0x10, 0x1c, 0x60, 0x2, 0x19, 0x41, 0x17, 0x11, 0x5a, 0xe, 0x1d, 0xe,0x39, 0xa,0x4]
print(len(kn))

for i in range(len(enc_flag)):
    
    print(chr(enc_flag[i]^kn[i%len(kn)]),end="")
```

- Thấy đó là lời thứ 2 của bài hát, mình copy nguyên câu rồi thêm **@flare-on.com** thay **ü** thành **u**

-> Flag: **Dann_singe_ich_ein_Lied_fur_dich@flare-on.com**

- P/S: bài nhảm vcl


## 11 - The challenge that shall not be named

- Bài này dùng **Pyinstaller** để chuyển từ file **python** -> **exe**

- Dùng [pyinstxtractor.py](https://github.com/extremecoders-re/pyinstxtractor) để dump source (lưu ý ***chạy script bằng python 3.7 vì author khi sử dụng Pyinstaller dùng python 3.7***)

- Sau khi dump source, decompile file **11.pyc** bằng [pycdc](https://github.com/zrax/pycdc)

![image](https://user-images.githubusercontent.com/91442807/202346454-e77cd035-df57-4196-bf56-8751caec051e.png)

- Có vẻ author dùng [Pyarmor](https://pyarmor.readthedocs.io/en/latest/usage.html) để bảo vệ nội dung file python.

- Theo doc ta sắp xếp file như dưới và chạy thử:

![image](https://user-images.githubusercontent.com/91442807/202347311-28ae20d3-b2dc-498b-9732-63965feadd2f.png)

- Kết quả: 

![image](https://user-images.githubusercontent.com/91442807/202347942-686a0424-11b0-4d88-b9bb-7dc8930cae3c.png)

- Sau đó mình lấy file **crypt.pyc** trong source dump được thì chương trình lại yêu cầu thêm các thư viện khác và làm tiếp tục tương tự

![image](https://user-images.githubusercontent.com/91442807/202348740-f217407c-f2fa-4aed-8f32-d08d2e788c90.png)

- Tới đây thì chương trình file **11.pyc** chạy bình thường

- Decompile thử file **crypt.pyc** thì thấy cũng bị encrypt bằng **pyarmor**:

![image](https://user-images.githubusercontent.com/91442807/202349827-5eccc3c7-f4f0-4d3c-963e-52ad5c47fcdc.png)

-> Có nghĩa là file **crypt.pyc** này không phải là file thư viện gốc của python là file author tạo ra rồi encrypt cùng lúc với pyarmor

- Tham khảo [write-up](https://devilinside.me/blogs/unpacking-pyarmor) mình biết là có thể ghi đè code lên file thư viện để chương trình in ra thứ mình cần

- Tạo thử một file **crypt.py** rồi chạy thử:

![image](https://user-images.githubusercontent.com/91442807/202350050-43bd9ef1-5bc3-49a4-82d3-ae259190ac21.png)

-> Do **pyarmor** decrypt code trong lúc chương trình chạy nên ta có thể lợi dụng điều này để lúc chương trình gọi code của **crypt.py** ta có thể biết được phần nào nội dung của file

-> Thư viện thiếu hàm **ARC4**, tới đây có vẻ là đang đi đúng hướng vì flareon kì này dùng RC4 cipher khá nhiều.

- Tạo hàm RC4:

```python
def ARC4():
    return
```
![image](https://user-images.githubusercontent.com/91442807/202350688-fdf8744e-4799-4efa-8fc6-f3f5557231e7.png)

- Hàm này lấy 1 tham số -> thêm vào sẵn tiện in ra luôn :))

```python
def ARC4(x):
    print(x)
    return 
```

![image](https://user-images.githubusercontent.com/91442807/202350911-003d8b71-488f-458a-af5b-450e236e51d1.png)

 - Ban đầu mình thử tạo hàm **encrypt** tương tự thì lại không được, xem lại source của **crypt.pyc** gốc thì mình tạo hàm ARC4 thành 1 class thì được, từ đó theo lỗi tương tự như trên để viết lại hàm **encrypt**

```python
class ARC4:
    def __init__(self,key):
        print(key)
        return
    def encrypt(a,b):
        print(a)
        print(b)
        return
```

-> Kết quả: 

![image](https://user-images.githubusercontent.com/91442807/202351816-a6f90caa-fe57-49ca-8ea4-9abb327d3a6b.png)

  
 














