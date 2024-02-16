# SeDebugPrivilege-Abuse

While solving the "POV" machine from @HackTheBox, I got into a situation where I have to abuse SeDebugPrivilege for privilege escalation. At that time, I used metasploit and its "migrate" feature to get a shell as SYSTEM.

After solving that box, I thought of creating a program which does the same thing and here it is!.

Right now, It will target winlogon.exe and then pop's up a cmd.exe process as SYSTEM. 

Maybe, I will modify/create a new program that will inject a shellcode and get shell that way.

