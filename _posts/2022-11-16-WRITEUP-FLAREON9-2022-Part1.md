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

- Reverse hàm ***http_process***:

![image](https://user-images.githubusercontent.com/91442807/202154238-acb4cf60-9cc8-46a1-9ef1-08dacb5c17d2.png)

- Ta thấy đầu tiên ***http_process*** gọi hàm ***RC4*** 

- Reverse hàm ***RC4*** ta thấy hàm dùng một key có format ***"F09 + 1_số_random_gồm_5_chữ_số"*** để encypt một string ***"ahoy"***

- Sau đó kết quả encrypt sẽ được đi ***base64*** encode



