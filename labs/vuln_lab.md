# Building a vulnerable Linux lab for Sentinel

You don't need this to *run* Sentinel (use `--offline labs/sample_findings.json`),
but to exercise the live enumerator (`--local` / `--ssh`) against real data, spin
up a throwaway Linux VM and plant a few classic misconfigurations. **Do this only
in an isolated lab you control.**

A quick Ubuntu VM (VirtualBox/VMware/multipass) plus, as root:

```bash
# 1. A low-priv user to be your foothold
useradd -m -s /bin/bash bob && echo 'bob:bob' | chpasswd

# 2. SUID GTFOBins binary
cp /usr/bin/find /usr/local/bin/find && chmod 4755 /usr/local/bin/find

# 3. sudo NOPASSWD on a GTFOBins binary
echo 'bob ALL=(root) NOPASSWD: /usr/bin/find' > /etc/sudoers.d/bob

# 4. cap_setuid capability
setcap cap_setuid+ep /usr/bin/python3

# 5. docker group membership (install docker first)
usermod -aG docker bob

# 6. writable /etc/passwd (dangerous — lab only!)
chmod 666 /etc/passwd

# 7. NFS export with no_root_squash
echo '/home *(rw,sync,no_root_squash)' >> /etc/exports && exportfs -ra
```

Then, as `bob`:

```bash
# On the box:
py sentinel.py --local

# Or remotely from your attacker host:
py sentinel.py --ssh <vm-ip> -u bob -p bob --save loot.json
```

Great intentionally-vulnerable targets to point Sentinel at instead of building
your own: **TryHackMe** (Linux PrivEsc, Vulnversity), **HackTheBox** starting-point
boxes, and **VulnHub** images. All are authorized practice environments.

> Reset the VM afterwards — several of these changes (world-writable `/etc/passwd`,
> `no_root_squash`) make the machine genuinely insecure.
