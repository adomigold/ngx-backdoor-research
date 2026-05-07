# Nginx Backdoor Module — Security Research & Defense Presentation

> **Audience:** System administrators, blue-team defenders, security engineers  
> **Purpose:** Understand how trusted software (Nginx) can be weaponized as a
> persistent backdoor, and how to detect and prevent it.  
> **Ethics:** All techniques described here are for **authorized lab environments
> only**. Deploying this against systems you do not own is illegal under the law.

---

## 1. What This Is

`ngx_http_authg_module` is a **malicious Nginx dynamic module** that turns any
endpoint into a remote command execution (RCE) backdoor.

When loaded, it intercepts HTTP requests to a configured location (e.g.
`/authg`) and passes the value of the `?c=` query parameter directly to
`popen()`, executing it as a shell command under the Nginx worker process
identity (typically `www-data` or `nginx`).

```
GET /authg?c=id HTTP/1.1
Host: victim.example.com

→ uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

This is functionally a **web shell** embedded inside a trusted system binary,
making it significantly harder to detect than a PHP/ASP web shell dropped in
the document root.

---

## 2. Why This Is Dangerous (Attack Perspective)

### 2.1 Hiding in Plain Sight

| Attribute | Web Shell (PHP) | This Module |
|---|---|---|
| File in webroot | ✅ Obvious | ❌ Not visible |
| Shows in `ps aux` | ❌ No separate process | ❌ No separate process |
| AV / file scan catches it | Often yes | Unlikely, it's a `.so` file |
| Survives webroot wipe | ❌ No | ✅ Yes |
| Runs as web server user | ✅ | ✅ |
| Persists across restarts | ❌ Manual reload needed | ✅ `load_module` in nginx.conf |

### 2.2 Delivery Vectors

A real attacker could install this module via:

1. **Supply chain compromise**: A tampered Nginx package in a third-party repo  
2. **Dependency confusion / malicious apt mirror**  
3. **Post-exploitation**: Attacker already has root, installs the module as
   persistence after initial intrusion  
4. **Insider threat**: Malicious sysadmin or CI/CD pipeline  
5. **Misconfigured build pipeline**: Injecting the module during a custom
   Nginx compile step  

### 2.3 What an Attacker Can Do

Because the module runs as the Nginx worker user, an attacker can:

- Read any file readable by `www-data` (config files, `.env`, secrets)  
- Exfiltrate data over plain HTTP, blends with normal web traffic  
- Pivot internally: `curl`, `wget`, `nc` are typically available  
- Escalate privileges if `www-data` has `sudo` rights or SUID binaries exist  
- Establish a reverse shell for interactive access  
- Persist across reboots (module is loaded at Nginx start via `nginx.conf`)  

---

## 3. Detection: How a Sysadmin Finds This

### 3.1 Audit Loaded Modules

```bash
# List all dynamic modules loaded by Nginx
nginx -T 2>/dev/null | grep load_module

# Or inspect the config directly
grep -r "load_module" /etc/nginx/
```

Any `.so` file you did not explicitly install is suspicious.

### 3.2 Verify Module File Integrity

```bash
# List all .so files in the Nginx modules directory
ls -lah /etc/nginx/modules/
ls -lah /usr/lib/nginx/modules/

# Check file hashes against known-good baseline
sha256sum /etc/nginx/modules/*.so

# Compare against package manager's expected hashes
dpkg --verify nginx          # Debian/Ubuntu
rpm -V nginx                 # RHEL/CentOS
```

### 3.3 Check for Unknown Symbols in Module Binaries

```bash
# A legitimate Nginx module should NOT import popen, system, exec*
nm -D /etc/nginx/modules/suspicious_module.so | grep -E "popen|system|exec|fork"
strings /etc/nginx/modules/*.so | grep -E "popen|/bin/sh|bash|cmd"
```

### 3.4 Monitor Nginx Configuration Changes

```bash
# Use auditd to watch nginx.conf and module directory for writes
auditctl -w /etc/nginx/nginx.conf -p wa -k nginx_config_change
auditctl -w /etc/nginx/modules/ -p wa -k nginx_module_change

# View audit log
ausearch -k nginx_config_change
ausearch -k nginx_module_change
```

### 3.5 Inspect Network Traffic

Backdoor traffic looks like normal HTTP GET requests. Look for:

- Requests to unusual paths (`/authg`, `/status2`, `/health_check`, etc.) with
  `?c=` or similar single-character parameters  
- Responses containing `/etc/passwd`, shell output, or command-looking strings  
- Outbound connections from the Nginx worker process (unusual)  

```bash
# Watch outbound connections from nginx workers
ss -tp | grep nginx
lsof -p $(pgrep -d, nginx) -i
```

### 3.6 Behavioral Detection with eBPF / auditd

```bash
# Detect popen/execve calls from nginx worker process
# Using auditd:
auditctl -a always,exit -F arch=b64 -S execve -F exe=/usr/sbin/nginx -k nginx_exec

# Any execve from Nginx is highly suspicious in a legitimate deployment
ausearch -k nginx_exec
```

---

## 4. Prevention — Hardening Against This Attack

### 4.1 Lock Down the Module Directory

```bash
# Only root should write to the modules directory
chmod 755 /etc/nginx/modules/
chown root:root /etc/nginx/modules/
# Make existing modules immutable (requires root)
chattr +i /etc/nginx/modules/*.so
```

### 4.2 Use Package Manager Verification

```bash
# Only install Nginx from official distro repos or nginx.org
# Never compile from untrusted sources or use third-party PPAs
apt-get install --only-upgrade nginx   # keeps package manager in control
```

### 4.3 Restrict Nginx to Only Required Modules

In `nginx.conf`, explicitly enumerate every permitted module. Anything not
listed should not exist on disk.

### 4.4 Run Nginx in a Restricted Environment

```bash
# Use systemd to restrict what Nginx workers can do
# In /etc/systemd/system/nginx.service.d/hardening.conf:

[Service]
# Prevent writing to most of the filesystem
ReadOnlyPaths=/
ReadWritePaths=/var/log/nginx /var/cache/nginx /run

# Prevent new privilege escalation
NoNewPrivileges=true

# Block outbound network from worker (if Nginx only serves, not fetches)
# IPAddressDeny=any   ← enable if Nginx doesn't need to make outbound calls

# Restrict system calls — popen/execve are blocked by this filter
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @mount
```

### 4.5 Apply AppArmor or SELinux Policy

```bash
# Ubuntu: enforce AppArmor profile for Nginx
aa-enforce /etc/apparmor.d/usr.sbin.nginx

# The default Nginx AppArmor profile denies execution of child processes.
# Verify popen/exec is denied:
cat /etc/apparmor.d/usr.sbin.nginx | grep exec
```

With a proper AppArmor profile, even if the malicious module is loaded,
`popen()` will be denied by the kernel — the backdoor is neutered.

### 4.6 File Integrity Monitoring (FIM)

```bash
# AIDE — monitor nginx binaries and config
# /etc/aide/aide.conf:
/etc/nginx       CONTENT_EX
/usr/sbin/nginx  CONTENT_EX
/etc/nginx/modules  CONTENT_EX

# Initialize and check
aide --init
aide --check
```

### 4.7 Principle of Least Privilege for the Worker User

```bash
# Ensure www-data / nginx user cannot sudo, has no shell, owns no sensitive files
grep www-data /etc/sudoers /etc/sudoers.d/*   # should return nothing
grep nginx /etc/sudoers /etc/sudoers.d/*

# Lock the account shell
usermod -s /usr/sbin/nologin www-data
```

---

## 5. Incident Response Checklist

If you suspect a malicious Nginx module is present:

- [ ] **Do not restart Nginx**, a restart may reload the module and reset logs  
- [ ] Take a memory dump of the Nginx process: `gcore $(pgrep nginx | head -1)`  
- [ ] Copy suspicious `.so` files for forensic analysis before removing  
- [ ] Check `nginx -T` for all active configuration including loaded modules  
- [ ] Review access logs for `?c=` style RCE patterns  
- [ ] Rotate all secrets accessible by `www-data` (DB passwords, API keys, `.env`)  
- [ ] Audit all files modified in the last N days: `find / -newer /var/log/nginx/access.log -not -path "/proc/*"`  
- [ ] Restore Nginx from a known-good package: `apt-get install --reinstall nginx`  
- [ ] Review sudoers, crontabs, authorized_keys for persistence  

---

## 6. Key Takeaways for the Presentation

1. **Trust is a vulnerability.** Nginx is trusted by firewalls, WAFs, and
   defenders. A malicious module inherits that trust completely.

2. **Persistence without files in the webroot.** Traditional defenses (scanning
   webroot for web shells) completely miss this technique.

3. **The attack surface is the build/deploy pipeline.** Securing the server
   is not enough, you must secure where and how Nginx is built and configured.

4. **Kernel-level enforcement wins.** AppArmor/SELinux policies and seccomp
   filters can neutralize the backdoor even after it is loaded, because `popen`
   requires `execve` which the kernel can deny.

5. **Detection requires behavioral monitoring**, not just static file scans.
   `auditd` + eBPF watching for `execve` calls originating from `nginx` is the
   most reliable signal.

---

## 7. Lab Setup (Safe Demo Environment)

To reproduce this safely:

```bash
# Use an isolated VM with no internet access
# Recommended: VirtualBox / VMware with host-only networking
# OS: Ubuntu 22.04 LTS

# Install build dependencies
sudo apt-get install -y nginx nginx-dev build-essential libpcre3-dev zlib1g-dev

# Build the module (see main source file for full instructions)
# Test only against localhost
curl "http://127.0.0.1:8080/authg?c=id"

# When done, remove the module and restore nginx.conf
sudo rm /etc/nginx/modules/ngx_http_authg_module.so
sudo nginx -t && sudo systemctl reload nginx
```

**Never test against any system you do not own and have written authorization to test.**

---

## References

- [Nginx Dynamic Module Development](https://nginx.org/en/docs/dev/development_guide.html)  
- [MITRE ATT&CK T1505.003 — Web Shell](https://attack.mitre.org/techniques/T1505/003/)  
- [MITRE ATT&CK T1547 — Boot/Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)  
- [AppArmor Nginx Profile](https://wiki.ubuntu.com/AppArmor)  
- [Linux Audit Framework (auditd)](https://linux.die.net/man/8/auditd)  
- [AIDE File Integrity Monitor](https://aide.github.io/)