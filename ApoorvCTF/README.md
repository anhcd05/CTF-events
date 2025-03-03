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
