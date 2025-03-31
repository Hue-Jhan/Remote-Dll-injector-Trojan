# Remote Dll injector Trojan
Trojan using dll injection of a custom library that spawns a shell on a target machine, undetected by Windows defender and Bitdefener

# 💻 Code

<img align="right" src="media/a1.png" width="440" />

This malware injects a malicious library into a target process or directly creates a process and uploads the library into it, the dll contains a simple encoded base64 data that spawns a reverse shell.

#### DLL

#### Local Injection

#### Remote Injection

# 🛡 Obfuscation and AV Detection 

<img align="right" src="media/av1.png" width="340" />

Both coes are undetected by Windows defender, but the local injection is detected by 10 antiviruses. Using a simple certificate and metadata manager like Process Hacker (free an open source) i uploaded the data of a common app (in my case it was github desktop setup) and the AVs went from 10 to 1 in an instant, and for the first time Bitdefender didn't flag it as suspicious 😀!!! The file went from a few kilobytes to like 100mb tho so i think i'll have to work on that, maybe by embedding only the essential metadata and certificates.


<img align="left" src="media/av4.png" width="340" />
