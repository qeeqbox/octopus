<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/octopus/main/readme/octopus.png"></p>

Deploy a single Honeypot or multiple Honeypots with an automated bash script. All honeypots are regular servers (Not emulators) with specific settings\configurations. And, they should log all the actions into `/var/log/` folder. This folder is adjustable based on your needs.

If you are interested in emulators not servers, check out the Honeypots python package (pip3 install honeypots)

## Install & setup with defualt ports
```
git clone https://github.com/qeeqbox/octopus.git && cd octopus && chmod +x setup.sh
./setup.sh "ssh,rdp,ldap,ftp,samba,mongodb,redis,vnc"
```

## Install & setup with ports
```
git clone https://github.com/qeeqbox/octopus.git && cd octopus && chmod +x setup.sh
./setup.sh "ssh:22,rdp:3389"
```

## Current Servers (10 out 41)
- ssh using modfided version of OpenSSH
- - Port: 22
- - Log file: `/var/log/auth.log`
- ldap using slapd with custom settings
- - Port: 389
- - Log file: `/var/log/ldap.log`
- mysql using mysql-server with custom settings
- - Port: 
- - Log file: 
- redis using redis-server with custom settings
- - Port: 6379
- - Log file: `/var/log/redis-monitor.log`
- mongodb using mongodb
- - Port: 27017
- - Log file: `/var/log/mongodb/mongod.log`
- samba using samba with custom settings
- - Port: 445
- - Log file: `/var/log/smb.log`
- ftp using vsftpd with custom settings
- - Port: 21
- - Log file: `/var/log/vsftpd.log`
- vnc using tightvncserver
- - Port: 5900
- - Log folder: `/var/log/vnc`
- rdp using xrdp with custom settings
- - Port: 3389
- - Log file: `/var/log/xrdp.log`
- http\https using apache2 with custom settings
- - Port: 80\443
- - Log file:
- proxy using squid with custom settings
- - Port: 8080
- - Log file: `/var/log/proxy.log`

## acknowledgement
By using this framework, you are accepting the license terms of all these packages: `OpenSSH slapd mysql-server redis-server mongodb samba vsftpd tightvncserver xrdp apache2`

## Other Projects
[![](https://github.com/qeeqbox/.github/blob/main/data/social-analyzer.png)](https://github.com/qeeqbox/social-analyzer) [![](https://github.com/qeeqbox/.github/blob/main/data/analyzer.png)](https://github.com/qeeqbox/analyzer) [![](https://github.com/qeeqbox/.github/blob/main/data/chameleon.png)](https://github.com/qeeqbox/chameleon) [![](https://github.com/qeeqbox/.github/blob/main/data/osint.png)](https://github.com/qeeqbox/osint) [![](https://github.com/qeeqbox/.github/blob/main/data/url-sandbox.png)](https://github.com/qeeqbox/url-sandbox) [![](https://github.com/qeeqbox/.github/blob/main/data/mitre-visualizer.png)](https://github.com/qeeqbox/mitre-visualizer) [![](https://github.com/qeeqbox/.github/blob/main/data/woodpecker.png)](https://github.com/qeeqbox/woodpecker) [![](https://github.com/qeeqbox/.github/blob/main/data/docker-images.png)](https://github.com/qeeqbox/docker-images) [![](https://github.com/qeeqbox/.github/blob/main/data/seahorse.png)](https://github.com/qeeqbox/seahorse) [![](https://github.com/qeeqbox/.github/blob/main/data/rhino.png)](https://github.com/qeeqbox/rhino)
