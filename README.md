
![calmweb](https://github.com/user-attachments/assets/3508836a-b2dd-4c0b-ac6f-93a490b5ee94)

# Calm Web

A proxy / Web filter aimed to protect eldry or unconfident people on the internet, protecting them from ads, scams and block remote control softwares like Teamviewer.

Why use Caml Web?  
Calm Web is meant to protect people with no or poor internet knowledge.  
It's aggressive by design, simple yet efficient ( i hope)
It works system wide, so no matter the browser you use, it will work and will block already installed programs or tools, even the Windows remote assistance tool!

![Find more informations and a demonstration here!](https://www.youtube.com/watch?v=hA5_J1NefKE)


## Installation:
Download and run calmweb_proxy.exe.

The program will:
- Copy himself in C:\Program Files\CalmWeb
- Setup a firewall rule
- Add a scheduled task at startup (admins rights required to setup proxy)
- Start the program, setup the proxy, download whitelists and blocklists

## What is allowed and what is blocked?
### By default it will block the following:
- Traffic on http port
- Browsing using IP addresses to avoid scams
- Browsing on non standard port (80/443)
- Domains listed in thoses lists: All credits to them!  
    "https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts"  
    "https://raw.githubusercontent.com/easylist/listefr/refs/heads/master/hosts.txt"  
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt"  
    "https://raw.githubusercontent.com/Tontonjo/calmweb/refs/heads/main/filters/blocklist.txt"  
- Domains manually added in the blocklist at %appdata%\calmweb\custom.cfg  
<img width="668" height="17" alt="image" src="https://github.com/user-attachments/assets/01b07662-9826-4461-acd8-ae34e458ad81" />

### By default the following domains are whitelisted.
- Domains listed in thoses lists:  
    "https://raw.githubusercontent.com/Tontonjo/calmweb/refs/heads/main/filters/whitelist.txt"  
- Domains manually added in the whitelist at %appdata%\calmweb\custom.cfg  

### Known problems:
- Opening and closing the log crash the program

### todo:
Everything is subject to discussion and enhancements! Share your knolwedges.  
- Test on windows 10
- Ensure the proxy will not cause problms: correct stop at shutdown, multi users
- Enhance the program, make it perfectly stable and robust.
- Correct encoding (some messages are displayer weirdly)
- Configure a self-updating method
- Allow to setup a system wide, "discrete" mode where the program runs  in background showing no icons at all
- Add domains in whitelist that are needed
- Add blocked domains when you discover a new scam, risky website.
- Ensure whitelists are working perfectly no matter what
