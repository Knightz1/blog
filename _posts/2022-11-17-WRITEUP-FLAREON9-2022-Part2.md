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

### Phân tích trên file exe 

#### Dump kết quả cuối

- Đầu tiên mình sửa code lại để in ra kết quả cuối cùng:

![image](https://user-images.githubusercontent.com/91442807/202188868-2ae75584-a825-4dfe-9f18-2f19a6dea994.png)

- Lưu ý: ***vừa thêm và xóa code phải đảm bảo sao cho số bytes xóa và số bytes thêm bằng nhau để đảm bảo kích thước cho file khi chạy không bị crash***

- Các trường hợp **switch-case** có các số random nên mình đoán khi chạy cùng input ở các thời điểm khác nhau sẽ cho ra kết quả khác nhau nhưng lại không như vậy:

![image](https://user-images.githubusercontent.com/91442807/202190505-b3e7c094-a3b1-43a0-bab7-f79240c08296.png)


#### Dump giá trị state

- Ta cần giá trị state để biết thứ tự các **case** trong suốt quá trình chạy đến kết quả cuối

![image](https://user-images.githubusercontent.com/91442807/202196902-eb987a7e-5534-4e49-b9ef-8d959ae21fe5.png)

- [Tham khảo]()

![image](https://user-images.githubusercontent.com/91442807/202197238-67fb8466-d5cd-47ad-9288-4b63113b0900.png)


#### Dump giá trị random






