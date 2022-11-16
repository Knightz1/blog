---
layout: post
title: "[FLAREON9 2022]: Part1"
categories: rev
toc: true
---

## 5 - T8

- Reverse C++ binary

- Khi phân tích các C++ binary cộng thêm quan sát hàm main thì thứ nên quan tâm là  ***vftable***

![image](https://user-images.githubusercontent.com/91442807/202148679-b44ef965-a73f-48c0-a09e-16428357c719.png)

- Sau khi phân tích một số hàm cùng với việc dùng plugin [findcrypt-yara](https://github.com/polymorf/findcrypt-yara) thì mình xác định chức năng của cơ bản của một số hàm như trên

### Reverse hàm **http_process**:

![image](https://user-images.githubusercontent.com/91442807/202154238-acb4cf60-9cc8-46a1-9ef1-08dacb5c17d2.png)

- Ta thấy đầu tiên ***http_process*** gọi hàm ***RC4*** 

- Reverse hàm ***RC4*** ta thấy hàm dùng một key có format ***"F09 + 1_số_random_gồm_5_chữ_số"*** để encypt một string ***"ahoy"***

- Sau đó kết quả encrypt sẽ được đi ***base64*** encode

- Sau đó thực hiện kết nối http thông qua một số winAPI gì đó mà các bạn có thể thấy kết quả thông qua debug

- Kết quả là chuỗi được lưu giống trong file pcap:

![image](https://user-images.githubusercontent.com/91442807/202156504-e6140ef1-602d-40f8-b790-758eb3fd9e4e.png)

- Tiếp tục debug ta biết được chỗ số 1 là ***"F09 + 1_số_random_gồm_5_chữ_số"*** và chỗ số 2 là kết quả sau khi ***base64*** encode ở trên

-> Từ đó ta test thử xem dùng ***"FO911950"*** có thể decrypt ***"ydN8BXq16RE="*** ra được ***"ahoy"*** giống phân tích ở trên hay không

```python
from base64 import b64decode, b64encode
from Crypto.Cipher import ARC4
from hashlib import md5

data=b'ydN8BXq16RE='
data=b64decode(data)    

key_format=f"FO911950"
li1=b''
for j in key_format:
    li1+=str(j).encode()+b'\x00'

md5_res=md5(li1).hexdigest()
li2=b''
for j in md5_res:
    li2+=str(j).encode()+b'\x00'

res=ARC4.new(li2).decrypt(data)
print(res)
```

- Kết quả :  **b'a\x00h\x00o\x00y\x00'**

## Phân tích số random 

- Giờ ta cần xem nguồn gốc số random là từ đâu

![image](https://user-images.githubusercontent.com/91442807/202159082-2a0a43f7-9f8f-4fec-8c13-462fb59f2510.png)

- Có vẻ nó được tạo ra từ hàm **random** với seed là **time**

## Phân tích tiếp hàm **http_process**

![image](https://user-images.githubusercontent.com/91442807/202159663-a8b43635-eaa0-4010-b98c-944525fd7e72.png)

- Hàm [**WinHttpReadData**](https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpreaddata) là hàm ta cần quan tâm tiếp 

- Hàm nhận **data response** sau khi kết nối đến **http server**

- Hàm này được gọi 2 lần:

![image](https://user-images.githubusercontent.com/91442807/202161250-c542aa5f-a241-42ca-9d98-a67c966fafab.png)

-> Cả 2 lần đều trả về source của 1 webpage

- Tới đây mình lại không biết làm tiếp thế nào nhưng mình khá chắc là muốn tìm flag thì phải decode được đoạn **base64** trong file pcap.

- Suy nghĩ thêm một lúc thì mình thấy đoạn base64 đó nằm trong phần **response** của file pcap nhưng tại sao lại trả về source web chứ không phải một chuỗi **base64** nào đó. Tới đây mình đoán có lẽ cái số random để nó trả về đoạn base64 lúc kết nối chắc chỉ có số ***11950***

- Tới đây mình tiến hành patch cái số random lại thành ***11950*** trong lúc debug (patch giá trị EAX):

![image](https://user-images.githubusercontent.com/91442807/202163680-d10d8e20-73ae-4ed4-8477-a6a2e0514e97.png)

-Tiếp đó patch tiếp kết quả trả về của **WinHttpReadData** tại lần gọi thứ 2 thành đoạn ***base64*** trong file pcap bằng **IDApython**

```python 
import idaapi

data=b'TdQdBRa1nxGU06dbB27E7SQ7TJ2+cd7zstLXRQcLbmh2nTvDm1p5IfT/Cu0JxShk6tHQBRWwPlo9zA1dISfslkLgGDs41WK12ibWIflqLE4Yq3OYIEnLNjwVHrjL2U4Lu3ms+HQc4nfMWXPgcOHb4fhokk93/AJd5GTuC5z+4YsmgRh1Z90yinLBKB+fmGUyagT6gon/KHmJdvAOQ8nAnl8K/0XG+8zYQbZRwgY6tHvvpfyn9OXCyuct5/cOi8KWgALvVHQWafrp8qB/JtT+t5zmnezQlp3zPL4sj2CJfcUTK5copbZCyHexVD4jJN+LezJEtrDXP1DJNg=='

for i in range(len(data)):
    idaapi.patch_byte(0x95EE40+i,data[i])    #thay đổi giá trị 0x95EE40 thành địa chỉ của "lpBuffer" trong lúc debug
```

![image](https://user-images.githubusercontent.com/91442807/202165171-7c3b037a-7ae7-4b54-a1a7-a23ba488067d.png)

- Sau khi patch và debug thêm 1 lúc nữa ta thấy flag được load trong memory

![image](https://user-images.githubusercontent.com/91442807/202167165-734a47a8-4586-4f13-ad1b-f7f30e25b322.png)


## 6 - à la mode

## Phân tích file .NET

- Mở bằng [DnSpy](https://github.com/dnSpy/dnSpy):

![1](https://user-images.githubusercontent.com/91442807/202173649-23d06ead-c67d-4a24-a428-5aeabb03bbcb.png)

- Code khá đơn giản: thực hiện kết nối đến các **pipe** gì đó rồi đem vào **password** là tham số vào sau đó đọc 0x40 bytes từ **pipe** chuyển thành UTF-8 rồi trả về.

- Vấn đề là ta không thấy được các hàm xử lí kết nối (server side) hay bất kì hàm nào khác hữu dụng.

## Phân tích C code

- Tới đây thì mình load vào IDA xem thử

- Phân tích một hồi mình tới được đây:

![image](https://user-images.githubusercontent.com/91442807/202175670-63112e2d-1c3c-4e32-8d3e-641990b4d783.png)

- Hàm đầu tiên (**create_PEB**):

    ![image](https://user-images.githubusercontent.com/91442807/202175891-7174b377-f230-4ac8-a097-450596107f59.png)
    
    + Sử dụng hàm **decode_string** để resolve lại đúng mấy cái tên hàm 
   
    + Có thể viết lại hàm để decode(khá đơn giản) hoặc debug để thấy
    
    + Kết quả sau khi decode mình đổi tên lại như trên

- Hàm thứ 2 (**connect_and_write_file**):
    
    ![image](https://user-images.githubusercontent.com/91442807/202176900-37cc9874-b802-4498-8073-02966bf8ecdf.png)
    
    + Thực hiện kết nối PIPE gì đó (tương tự như phần .NET)
    
    + Hàm cần quan tâm là **Authorization**
    
- Hàm **Authorization**:

    + Hàm này có thể dùng để check **password** của bên .NET

    ![image](https://user-images.githubusercontent.com/91442807/202177399-8b08263f-2eac-4222-a6ad-ba585168b49d.png)
    
    + Phân tích ta thấy hàm thực hiện 2 lần RC4 
    
    + Tiến hành decrypt ở hàm RC4 thứ nhất:
    
    ```python
    from Crypto.Cipher import ARC4

    key=b'\x55\x8B\xEC\x83\xEC\x20\xEB\xFE'
    data=b'>9Q\xfb\xa2\x11\xf7\xb9,'
    print(ARC4.new(key).decrypt(data))
    ```
    
    + Ta thu được: **b'MyV0ic3!\x00'**

    + Nhưng thực hiện tương tự đối hàm RC4 thứ 2 lại không được (đã thử mọi cách)
    
    + Tới lúc này mình quyết định debug để coi nó là cái gì (dùng **rundll32.exe**)
    
    ![image](https://user-images.githubusercontent.com/91442807/202180104-1f5b1b23-6364-45f9-a17a-8205b156026e.png)
    
    ![image](https://user-images.githubusercontent.com/91442807/202180900-d042777d-02f1-4ae3-be74-10b56a6f0221.png)

    + Có vẻ phần đầu mình đã làm đúng
    
    ![image](https://user-images.githubusercontent.com/91442807/202181310-14161a04-a771-4d50-a421-f9466c496e6f.png)

    + Yay hàm RC4 thứ 2 đã decode flag bằng cách nào đó

    ![image](https://user-images.githubusercontent.com/91442807/202181484-c2658753-bf48-4f35-acba-ef4b71ab1d64.png)



    
    
 
 
    





  
  
  
  




