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

![image](https://user-images.githubusercontent.com/91442807/202224890-5e056420-dde6-4811-967e-e7772d717565.png)

- Tiếp đến key được encrypt bởi **sub_4016CC** sau đó lưu kết quả vào **unk_409100** sau đó được đưa vào file **.Encrypted** luôn

- Phân tích hàm đó ta thấy nó thực hiện việc encrypt dựa vào các bytes từ **unk_404020**

- Trace ngược lại xem nó được tạo từ đâu

### Encrypt key chacha20

![image](https://user-images.githubusercontent.com/91442807/202225802-b93d41c0-b33a-47c4-b384-844f549b4f91.png)

- Có vẻ nó được tạo từ lúc chạy chương trình 

- Nếu để ý các giá trị ban đầu của mảng ta sẽ nhận thấy : 0x10001=65537 giống với số e trong thuật toán RSA

- Dựa vào đó ta có thể phân tích lại các hàm: 

![image](https://user-images.githubusercontent.com/91442807/202228764-ea06c7e5-8aea-4384-9f4c-b8d890e7c0cf.png)

--> Thuật toán để encrypt key là **RSA**




