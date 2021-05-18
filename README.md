<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/octopus/main/readme/octopus.png"></p>

Deploy single or multiple different Honeypots with supervisor. The Honeypots are regular or modified servers with custom settings. This will configure them with for a temp username and password. Also, output the logs into /var/log folder for easy integration with tools such as filebeat and logstach

If you are interested in emulators not servers, check out the Honeypots python package (pip3 install honeypots)

## Install & setup with defualt ports
```
git clone https://github.com/qeeqbox/octopus
chmod +x setup.sh
./setup.sh "ssh,rdp,ldap,ftp,samba,mongodb,redis,vnc"
```

## Install & setup with ports
```
git clone https://github.com/qeeqbox/octopus
chmod +x setup.sh
./setup.sh "ssh:22,rdp:3389,ldap:389,ftp:21,samba:445,mongodb:27017,redis:6379,vnc:5900"
```

## Current Servers (10 out 41)
- ssh using modfided version of OpenSSH
- ldap using slapd with custom settings
- mysql using mysql-server with custom settings
- redis using redis-server with custom settings
- mongodb using mongodb
- samba using samba with custom settings
- ftp using vsftpd with custom settings
- vnc using tightvncserver
- rdp using xrdp with custom settings
- apache using apache2 with custom settings

## acknowledgement
By using this framework, you are accepting the license terms of all these packages: `OpenSSH slapd mysql-server redis-server mongodb samba vsftpd tightvncserver xrdp apache2`

## Other Projects
[![](https://github.com/qeeqbox/.github/blob/main/data/social-analyzer.png)](https://github.com/qeeqbox/social-analyzer) [![](https://github.com/qeeqbox/.github/blob/main/data/analyzer.png)](https://github.com/qeeqbox/analyzer) [![](https://github.com/qeeqbox/.github/blob/main/data/chameleon.png)](https://github.com/qeeqbox/chameleon) [![](https://github.com/qeeqbox/.github/blob/main/data/osint.png)](https://github.com/qeeqbox/osint) [![](https://github.com/qeeqbox/.github/blob/main/data/url-sandbox.png)](https://github.com/qeeqbox/url-sandbox) [![](https://github.com/qeeqbox/.github/blob/main/data/mitre-visualizer.png)](https://github.com/qeeqbox/mitre-visualizer) [![](https://github.com/qeeqbox/.github/blob/main/data/woodpecker.png)](https://github.com/qeeqbox/woodpecker) [![](https://github.com/qeeqbox/.github/blob/main/data/docker-images.png)](https://github.com/qeeqbox/docker-images) [![](https://github.com/qeeqbox/.github/blob/main/data/seahorse.png)](https://github.com/qeeqbox/seahorse) [![](https://github.com/qeeqbox/.github/blob/main/data/rhino.png)](https://github.com/qeeqbox/rhino)
