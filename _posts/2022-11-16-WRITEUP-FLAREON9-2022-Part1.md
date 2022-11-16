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

### Reverse hàm ***http_process***:

![image](https://user-images.githubusercontent.com/91442807/202154238-acb4cf60-9cc8-46a1-9ef1-08dacb5c17d2.png)

- Ta thấy đầu tiên ***http_process*** gọi hàm ***RC4*** 

- Reverse hàm ***RC4*** ta thấy hàm dùng một key có format ***"F09 + 1_số_random_gồm_5_chữ_số"*** để encypt một string ***"ahoy"***

- Sau đó kết quả encrypt sẽ được đi ***base64*** encode

- Sau đó thực hiện kết nối http thông qua một số winAPI gì đó mà các bạn có thể thấy kết quả thông qua debug

- Kết quả là chuỗi được lưu giống trong file pcap:

![image](https://user-images.githubusercontent.com/91442807/202156504-e6140ef1-602d-40f8-b790-758eb3fd9e4e.png)

- Tiếp tục debug ta biết được chỗ số 1 là ***"F09 + 1_số_random_gồm_5_chữ_số"*** và chỗ số 2 là kết quả sau khi ***base64*** encode ở trên

-> Từ đó ta test thử xem dùng ***FO911950*** có thể decrypt ***ydN8BXq16RE=*** ra được ***ahoy*** giống phân tích ở trên hay không





