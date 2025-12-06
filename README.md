![calmweb](https://github.com/user-attachments/assets/3508836a-b2dd-4c0b-ac6f-93a490b5ee94)

# Calm Web

A proxy / Web filter aimed to protect elderly or unconfident people on the internet, protecting them from ads, scams and blocking remote control software like TeamViewer.

Why use Calm Web?
Calm Web is meant to protect people with no or poor internet knowledge.
It's aggressive by design, simple yet efficient (I hope).
It works system-wide, so no matter the browser you use, it will work and will block already installed programs or tools, even the Windows remote assistance tool!

![Find more information and a demonstration here!](https://www.youtube.com/watch?v=hA5_J1NefKE)

## Installation:

Download and run calmweb_proxy.exe.

The program will:

- Copy itself into C:\Program Files\CalmWeb
- Set up a firewall rule
- Add a scheduled task at startup (admin rights required to set up the proxy)
- Start the program, set up the proxy, download whitelists and blocklists

## What is allowed and what is blocked?

### By default it will block the following:

- Traffic on http port
- Browsing using IP addresses to avoid scams
- Browsing on non-standard port (80/443)
- Domains listed in those lists: All credits to them!  
   https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts  
   https://raw.githubusercontent.com/easylist/listefr/refs/heads/master/hosts.txt  
   https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt  
   https://raw.githubusercontent.com/Tontonjo/calmweb/refs/heads/main/filters/blocklist.txt  
   https://dl.red.flag.domains/pihole/red.flag.domains.txt  
   https://urlhaus.abuse.ch/downloads/csv/
- Domains manually added in the blocklist at %appdata%\calmweb\custom.cfg  
  <img width="668" height="17" alt="image" src="https://github.com/user-attachments/assets/01b07662-9826-4461-acd8-ae34e458ad81" />

### By default the following domains are whitelisted.

- Domains listed in those lists:  
   "https://raw.githubusercontent.com/Tontonjo/calmweb/refs/heads/main/filters/whitelist.txt"
- Domains manually added in the whitelist at %appdata%\calmweb\custom.cfg

### Useful blocked domains:

[This list ](https://raw.githubusercontent.com/Tontonjo/calmweb/refs/heads/main/filters/usefull_domains.txt) contains domains that may be useful if you're a "power user" but appear to be listed in blocklists.

### Known problems:

- Sandbox not working when calmweb is running

### todo:

Everything is subject to discussion and enhancements! Share your knowledge.

- Test on Windows 10
- Ensure the proxy will not cause problems: correct stop at shutdown, multiple users
- Displaying the log crashes the program
- Enhance the program, make it perfectly stable and robust.
- Correct encoding (some messages are displayed weirdly)
- Configure a self-updating method
- Allow to set up a system-wide, "discrete" mode where the program runs in the background showing no icons at all
- Add domains in whitelist that are needed
- Add blocked domains when you discover a new scam, risky website.
- Ensure whitelists are working perfectly no matter what
- URLHaus provides URLs and IPs. For now only the domains are used and it may be more accurate to block the whole URL instead of domain in order to not block file sharing services that may be used for decent purposes.
- Show in which list a blocked or whitelisted domain appears

## Build the Windows installer from this workspace

1. On Windows, install Python 3.12+ and dependencies: `py -3 -m pip install --user -r requirements.txt` (or `py -3.14 ...` if you use 3.14). This installs PyInstaller + Pillow/pystray/pywin32.
2. From the repository root, run `build_calmweb.cmd` (double-click or from `cmd`). It will locate PyInstaller automatically, add a hidden import for `urllib3`, clean previous builds, and pause to show any errors.
3. If you hit icon format issues, either install Pillow (step 1 covers it), provide a valid `ressources\\calmweb.ico`, or set `NO_ICON=1` before running the script.
4. The built executable is written to `dist\\calmweb_installer.exe`.
