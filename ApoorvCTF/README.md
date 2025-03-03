# ApoorvCTF 2025 Write-up

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

