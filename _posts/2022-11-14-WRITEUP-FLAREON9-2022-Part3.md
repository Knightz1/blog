---
layout: post
title: "[FLAREON9 2022]: Part3"
categories: rev
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

### Encrypt buffer

![image](https://user-images.githubusercontent.com/91442807/202232530-538409ae-c194-48a4-a799-511c99b1cff8.png)

- Tiếp đến key+nonce được encrypt bởi **sub_4016CC** sau đó lưu kết quả vào **v9** sau đó được đưa vào file **.Encrypted** luôn

- Phân tích hàm đó ta thấy nó thực hiện việc encrypt dựa vào các bytes từ **unk_404020**

- Trace ngược lại xem nó được tạo từ đâu

### Encrypt key+nonce 

![image](https://user-images.githubusercontent.com/91442807/202225802-b93d41c0-b33a-47c4-b384-844f549b4f91.png)

- Có vẻ nó được tạo từ lúc chạy chương trình 

- Nếu để ý các giá trị ban đầu của mảng ta sẽ nhận thấy : 0x10001=65537 giống với số e trong thuật toán RSA

- Dựa vào đó ta có thể phân tích lại các hàm: 

![image](https://user-images.githubusercontent.com/91442807/202232681-29e547e3-a2b5-47fb-b029-03ff4ff3cfd9.png)

--> Thuật toán để encrypt key+nonce là **RSA**  (tham khảo [ở đây](https://phgvee.wordpress.com/2022/10/05/crypto-rsa-va-nhung-hinh-thuc-tan-cong/))

### Decrypt key+nonce và get flag

- Bây giờ ta có **N**, **d=65537** và **v9** đều được lưu vào file **.Encrypted** --> Tính toán được key+nonce

- Từ key+nonce -> flag

```python
from Crypto.Cipher import ChaCha20

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





