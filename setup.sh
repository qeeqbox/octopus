#!/bin/bash

#  -------------------------------------------------------------
#  author        Giga
#  project       qeeqbox/octopus
#  email         gigaqeeq@gmail.com
#  licensee      AGPL-3.0
#  -------------------------------------------------------------
#  contributors list qeeqbox/octopus/graphs/contributors
#  -------------------------------------------------------------

export DEBIAN_FRONTEND=noninteractive
ports_arr=()

req() {
    echo "[X] Setting up required packages wget zlib1g-dev build-essential libssl-dev lsof rsyslog supervisor iptables sudo apt-utils"
	DEBIAN_FRONTEND=noninteractive apt-get -yqq update && DEBIAN_FRONTEND=noninteractive apt-get -yqq install wget zlib1g-dev build-essential libssl-dev lsof rsyslog supervisor iptables sudo apt-utils 1>/dev/null
}

supervisord() {
    echo "[X] Creating /var/log/supervisor"
mkdir -p /var/log/supervisor && touch /var/log/supervisor/supervisord.log
echo "[X] Setting up supervisord global entry /etc/supervisor/conf.d/supervisord.conf"
cat >/etc/supervisor/conf.d/supervisord.conf <<EOL
[supervisord]
nodaemon=true
logfile_maxbytes=50MB

[program:rsyslog]
priority=2
command=/usr/sbin/rsyslogd -n 
autorestart=true

EOL
}

ssh () {
echo "[X] Setting up SSH server"
port_="22"
if [ ! -z "$2" -a "$2" != "default" ]; then
    port_=$2
fi
echo "[X] Downloading OpenSSH"
wget -q https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-8.3p1.tar.gz
echo "[X] Extracting OpenSSH"
tar xvfz openssh-8.3p1.tar.gz 1>/dev/null
echo "[X] Modifying auth-passwd.c"
sed '0,/struct passwd \*pw = authctxt->pw;/s//struct passwd \*pw = authctxt->pw;logit("Username %s Password %s",pw->pw_name,password);/' -i openssh-8.3p1/auth-passwd.c
echo "sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin" >> /etc/passwd
echo "[X] Making OpenSSH"
cd openssh-8.3p1 && ./configure 1>/dev/null && make 1>/dev/null && make install 1>/dev/null

if [ -x "/usr/local/sbin/sshd" ]; then
    echo "[X] Applying custom settings /usr/local/etc/sshd_config"
    sed -ri 's/^#?PermitRootLogin\s+.*/PermitRootLogin no/' /usr/local/etc/sshd_config && sed -ri 's/UsePAM yes/#UsePAM yes/g' /usr/local/etc/sshd_config && sed -ri 's/#Port 22/Port '$port_'/g' /usr/local/etc/sshd_config
    echo "AllowUsers $(head /dev/urandom | tr -dc A-Za-z0-9 | head -c50)" >> /usr/local/etc/sshd_config && echo "SyslogFacility AUTH" >> /usr/local/etc/sshd_config && echo "LogLevel VERBOSE" >> /usr/local/etc/sshd_config && echo "PasswordAuthentication yes" >> /usr/local/etc/sshd_config
    echo "[X] Applying custom settings /etc/rsyslog.conf"
    sed -i '/imklog/s/^/#/' /etc/rsyslog.conf
    rm -f $1 && echo "[X] SSHD Auth Logs" > $1 && chown syslog:adm $1
    echo "[X] Setting up supervisord entry /etc/supervisor/conf.d/supervisord.conf"
cat >>/etc/supervisor/conf.d/supervisord.conf <<EOL
[program:sshd]
command=/usr/local/sbin/sshd -D -f /usr/local/etc/sshd_config
autorestart=true

EOL
echo -e "[X] Log file location is $1\n[X] Server port is $port_"
ports_arr+=($port_)
else
   echo -e "[X] Something wrong!!" 
fi
}

ldap (){
echo "[X] Setting up LDAP server"
port_="389"
if [ ! -z "$2" -a "$2" != "default" ]; then
    port_=$2
fi
create_file "$1"
echo "[X] Preparing custom settings debconf-set-selections"
echo 'slapd/root_password password sysbackup' | debconf-set-selections && \
echo 'slapd/root_password_again password sysbackup' | debconf-set-selections && \
echo "[X] Installing slapd" && \
DEBIAN_FRONTEND=noninteractive apt-get -yqq install slapd ldap-utils 1> /dev/null
if [ -x "/usr/sbin/slapd" ]; then
    echo "slapd slapd/password1 password sysbackup" | debconf-set-selections && \
    echo "slapd slapd/password2 password sysbackup" | debconf-set-selections && \
    echo "slapd slapd/dump_database_destdir string /var/backups/slapd-VERSION" | debconf-set-selections  && \
    echo "slapd slapd/domain string back.com" | debconf-set-selections  && \
    echo "slapd shared/organization string Example" | debconf-set-selections  && \
    echo "slapd slapd/backend string MDB" | debconf-set-selections  && \
    echo "slapd slapd/purge_database boolean true" | debconf-set-selections  && \
    echo "slapd slapd/dump_database select when needed" | debconf-set-selections  && \
    echo "slapd slapd/no_configuration boolean false" | debconf-set-selections  && \
    echo "slapd slapd/allow_ldap_v2 boolean false" | debconf-set-selections  && \
    echo "slapd slapd/move_old_database boolean true" | debconf-set-selections && \
    dpkg-reconfigure -f noninteractive slapd
    echo "[X] Setting up supervisord entry /etc/supervisor/conf.d/supervisord.conf"
cat >>/etc/supervisor/conf.d/supervisord.conf <<EOL
[program:ldap]
command=/usr/sbin/slapd -h "ldap://:$port_/ ldaps:/// ldapi:///" -u openldap -g openldap -d 256
stdout_logfile=$1
stdout_logfile_maxbytes=0
redirect_stderr=true
autorestart=true

EOL
echo -e "[X] Log file location is $1\n[X] Server port is $port_"
ports_arr+=($port_)
else
   echo -e "[X] Something wrong!!" 
fi
} 

mysql () {
port_="3306"
if [ ! -z "$2" -a "$2" != "default" ]; then
    port_=$2
fi
create_file "$1"
{ \
echo mysql-community-server mysql-community-server/data-dir select ''; \
echo mysql-community-server mysql-community-server/root-pass password 'sysbackup'; \
echo mysql-community-server mysql-community-server/re-root-pass password 'sysbackup'; \
echo mysql-community-server mysql-community-server/remove-test-db select false; \
} | debconf-set-selections && \
DEBIAN_FRONTEND=noninteractive apt-get -yqq install mysql-server
usermod -d /var/lib/mysql/ mysql
service mysql start && \
mysql -u root -psysbackup -e 'ALTER USER "root"@"localhost" IDENTIFIED WITH mysql_native_password BY "sysbackup";' && \
mysql -u root -psysbackup -e 'GRANT ALL PRIVILEGES ON *.* TO "root"@"%" IDENTIFIED BY "sysbackup";' && \
service mysql stop && \
sed -e 's/^bind-address\t.*$/bind-address = 0.0.0.0/' -i /etc/mysql/mysql.conf.d/mysqld.cnf && \
sed -e 's/^#general_log_file.*/general_log_file = '$2'' -i /etc/mysql/mysql.conf.d/mysqld.cnf &&\
sed -e 's/^log_error \=.*/log_error = '$1'' -i /etc/mysql/mysql.conf.d/mysqld.cnf &&\
sed -e 's/^#general_log.*/general_log = 3/' -i /etc/mysql/mysql.conf.d/mysqld.cnf
mkdir -p /var/run/mysqld && \
chown -R mysql:mysql /var/lib/mysql /var/run/mysqld && \
chmod 777 /var/run/mysqld
cat >>/etc/supervisor/conf.d/supervisord.conf <<EOL
[program:mysql]
command=/usr/bin/pidproxy /var/run/mysqld/mysqld.pid /usr/bin/mysqld_safe
autorestart=true
user=root

EOL
}

redis () {
echo "[X] Setting up redis server"
port_="6379"
if [ ! -z "$2" -a "$2" != "default" ]; then
    port_=$2
fi
create_file "$1"
echo "[X] Installing redis-server"
DEBIAN_FRONTEND=noninteractive apt-get -yqq install redis-server 1> /dev/null
if [ -x "/usr/bin/redis-server" ]; then
    echo "[X] Applying custom settings /etc/redis/redis.conf"
    sed 's/^daemonize yes/daemonize no/' -i /etc/redis/redis.conf && \
    sed "s/^bind .*/bind 0.0.0.0/g" -i /etc/redis/redis.conf && \
    sed 's/port 6379/port '$port_'/g' -i /etc/redis/redis.conf && \
    sed 's/^# requirepass.*/requirepass sysbackup/' -i /etc/redis/redis.conf && \
    sed 's/^protected-mode yes/protected-mode no/' -i /etc/redis/redis.conf
    echo "[X] Setting up supervisord entry /etc/supervisor/conf.d/supervisord.conf"
cat >>/etc/supervisor/conf.d/supervisord.conf <<EOL
[program:redis-server]
priority=55
command=redis-server /etc/redis/redis.conf
autorestart=true

[program:redis-server-monitor]
priority=56
command=redis-cli -a sysbackup monitor
stdout_logfile=$1
stdout_logfile_maxbytes=0
autorestart=true

EOL
echo -e "[X] Log file location is $1\n[X] Server port is $port_"
ports_arr+=($port_)
else
   echo -e "[X] Something wrong!!" 
fi
}

mongodb (){
echo "[X] Setting up mongodb"
port_="27017"
if [ ! -z "$2" -a "$2" != "default" ]; then
    port_=$2
fi
echo "[X] Installing mongodb"
DEBIAN_FRONTEND=noninteractive apt-get -yqq install mongodb 1> /dev/null
if [ -x "/usr/bin/mongod" ]; then
    echo "[X] Creating /data/db"
    mkdir -p /data/db
    echo "[X] Setting up supervisord entry /etc/supervisor/conf.d/supervisord.conf"
#echo "Waiting on Mongodb to start.." && \
#service mongodb start && \
#sleep 5 && \
#mongo --eval 'db=db.getSiblingDB("admin");db.createUser({user:"root",pwd:"sysbackup",roles:["root"]})'
cat >>/etc/supervisor/conf.d/supervisord.conf <<EOL
[program:mongod]
command=/usr/bin/mongod --quiet --logpath $1 --logappend --auth --bind_ip 0.0.0.0 --port $port_
autorestart=true

EOL
echo -e "[X] Log file location is $1\n[X] Server port is $port_"
ports_arr+=($port_)
else
   echo -e "[X] Something wrong!!" 
fi
}

samba (){
echo "[X] Setting up samba server"
port_="445"
if [ ! -z "$2" -a "$2" != "default" ]; then
    port_=$2
fi
echo "[X] Installing samba"
DEBIAN_FRONTEND=noninteractive apt-get -yqq install samba-common samba 1> /dev/null
if [ -x "/usr/sbin/smbd" ]; then
    echo "[X] Setting up samba"
    groupadd -g 1000 smbtemp && \
    useradd -g smbtemp -l -M -s /bin/false -u 1000 smbtemp && \
    mkdir -p /smbtemp && \
    chown -R smbtemp:smbtemp smbtemp
    echo "[X] Applying custom settings smb.conf"
cat >>smb.conf <<EOL
[global]
    workgroup = intcorp1
    server string = SMB Internal Server
    netbios name = pc2020c1d2
    passdb backend = smbpasswd
    smb passwd file = /etc/samba/smbpasswd
    security = user
    map to guest = Bad User
    usershare path =
    usershare allow guests = no
    load printers = no
    printing = bsd
    printcap name = /dev/null
    disable spoolss = yes
    log level = 3
    log file = $1

[Shared]
    path = /smbtemp
    comment = D&R backup
    browseable = yes
    read only = yes
    write list = carol
    guest ok = no

EOL
echo "[X] Setting up samba username and password"
printf "sysbackup\nsysbackup" | smbpasswd -a -s -c smb.conf smbtemp
echo "[X] Setting up supervisord entry /etc/supervisor/conf.d/supervisord.conf"
cat >>/etc/supervisor/conf.d/supervisord.conf <<EOL
[program:smbd]
command=smbd --foreground --no-process-group --configfile /smb.conf
autorestart=true

EOL
echo -e "[X] Log file location is $1\n[X] Server port is $port_"
else
   echo -e "[X] Something wrong!!" 
fi
}

ftp (){
echo "[X] Setting up FTP server"
port_="21"
if [ ! -z "$2" -a "$2" != "default" ]; then
    port_=$2
fi
create_file "$1"
echo "[X] Installing vsftpd"
DEBIAN_FRONTEND=noninteractive apt-get -yqq install db-util vsftpd 1> /dev/null
if [ -x "/usr/sbin/vsftpd" ]; then
    echo "[X] Creating up /etc/vsftpd/"
    mkdir /etc/vsftpd/ && \
    echo "[X] Creating up /home/vsftpd/ftpbackup"
    mkdir -p /home/vsftpd/ftpbackup && \
    echo "[X] Creating up /var/run/vsftpd/empty"
    mkdir -p /var/run/vsftpd/empty && \
    chown -R ftp:ftp /home/vsftpd/ && \
    echo "[X] Setting up ftp username and password"
    echo -e "ftpbackup\nsysbackup" > /etc/vsftpd/virtual_users.txt && \
    db_load -T -t hash -f /etc/vsftpd/virtual_users.txt /etc/vsftpd/virtual_users.db
    echo "[X] Applying custom settings ftp.conf"
cat >>ftp.conf <<EOL
listen=yes
background=NO
listen_port=$port_
anonymous_enable=YES
local_enable=YES
guest_enable=YES
virtual_use_local_privs=YES
write_enable=NO
pam_service_name=vsftpdv
user_sub_token=ftpbackup
local_root=/home/vsftpd/ftpbackup
dual_log_enable=YES
log_ftp_protocol=YES
xferlog_enable=YES
xferlog_std_format=YES
xferlog_file=$1
vsftpd_log_file=$1
port_enable=YES
connect_from_port_20=YES
ftp_data_port=20
seccomp_sandbox=NO
EOL
echo '#%PAM-1.0
auth    required    pam_userdb.so   db=/etc/vsftpd/virtual_users
account required    pam_userdb.so   db=/etc/vsftpd/virtual_users
session required    pam_loginuid.so' > /etc/pam.d/vsftpdv
echo "[X] Setting up supervisord entry /etc/supervisor/conf.d/supervisord.conf"
cat >>/etc/supervisor/conf.d/supervisord.conf <<EOL
[program:vsftpd]
command=vsftpd ftp.conf
autorestart=true

EOL
ports_arr+=($port_)
echo -e "[X] Log file location is $1\n[X] Server port is $port_"
else
   echo -e "[X] Something wrong!!" 
fi
}

vnc() {
echo "[X] Setting up VNC server"
port_="5900"
if [ ! -z "$2" -a "$2" != "default" ]; then
    port_=$2
fi
echo "[X] Creating $1 directory"
mkdir -p $1
echo "[X] Installing tightvncserver"
DEBIAN_FRONTEND=noninteractive apt-get -yqq install tightvncserver 1> /dev/null
if [ -x "/usr/bin/vncserver" ]; then
    echo "[X] Setting up tightvncserver requirements"
    useradd --create-home vncbackup && \
    su -c "mkdir -p /home/vncbackup/.vnc" vncbackup && \
    su -c "echo 'sysbackup' | vncpasswd -f > /home/vncbackup/.vnc/passwd" vncbackup && \
    chmod 600 /home/vncbackup/.vnc/passwd && \
    mkdir -p /var/log/vnc/ && \
    ln -s /home/vncbackup/.vnc/ $1
    echo "[X] Setting up supervisord entry /etc/supervisor/conf.d/supervisord.conf"
cat >>/etc/supervisor/conf.d/supervisord.conf <<EOL
[program:vncd]
command=su -c "vncserver -rfbport $port_ -geometry 1280x800 :0 && sleep infinity" vncbackup

EOL
ports_arr+=($port_)
echo -e "[X] Log file location is $1\n[X] Server port is $port_"
else
   echo -e "[X] Something wrong!!" 
fi
}

xrdp() {
echo "[X] Setting up RPD server"
port_="3389"
if [ ! -z "$2" -a "$2" != "default" ]; then
    port_=$2
fi
create_file "$1"
echo "[X] Installing xrdp"
DEBIAN_FRONTEND=noninteractive apt-get -yqq install xrdp 1> /dev/null
if [ -x "/usr/sbin/xrdp" ]; then
    echo "[X] Applying custom settings /etc/xrdp/xrdp.ini"
cat >>/etc/xrdp/xrdp.ini <<EOL
[globals]
bitmap_cache=yes
bitmap_compression=yes
port=$port_
crypt_level=low
channel_code=1

[Logging]
LogFile=$1
LogLevel=DEBUG
EnableSyslog=true
SyslogLevel=DEBUG

[xrdp1]
name=R&D
lib=libvnc.so
username=sysbackup
password=sysbackup
ip=127.0.0.1
EOL
echo "[X] Setting up supervisord entry /etc/supervisor/conf.d/supervisord.conf"
cat >>/etc/supervisor/conf.d/supervisord.conf <<EOL
[program:xrdp]
command=xrdp -nodaemon

EOL
ports_arr+=($port_)
echo -e "[X] Log file location is $1\n[X] Server port is $port_"
else
   echo -e "[X] Something wrong!!" 
fi
}

apache () {
port_="80"
if [ ! -z "$2" -a "$2" != "default" ]; then
    port_=$2
fi

DEBIAN_FRONTEND=noninteractive apt-get -yqq install apache2 1> /dev/null
a2dismod mpm_event && \
a2enmod mpm_prefork ssl rewrite && \
a2ensite default-ssl
mkdir -p /var/www/html && \
echo "" > /var/www/html/index.html && \
sed s/LogFormat\ \"\%h/LogFormat\ \"\%\h:\%p/g -i etc/apache2/apache2.conf
cat >>/etc/supervisor/conf.d/supervisord.conf <<EOL
[program:apache]
command=apache2ctl -DFOREGROUND
autorestart=true

EOL
}

squid () {
echo "[X] Setting up Proxy server"
port_="8080"
if [ ! -z "$2" -a "$2" != "default" ]; then
    port_=$2
fi
echo "[X] Installing squid"
DEBIAN_FRONTEND=noninteractive apt-get -yqq install squid apache2-utils 1> /dev/null
#access_log $2
if [ -x "/usr/sbin/squid" ]; then
    echo "[X] Applying custom settings /etc/squid/squid.conf"
cat >> /etc/squid/squid.conf <<EOL
http_port $port_
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic children 5
auth_param basic realm Proxy Authentication Required
auth_param basic credentialsttl 2 hours
auth_param basic casesensitive off
acl auth proxy_auth REQUIRED
http_access allow auth
EOL
echo "[X] Setting squid username and password"
htpasswd -cb /etc/squid/passwd "sysbackup" "sysbackup" 1> /dev/null
echo "[X] Setting up supervisord entry /etc/supervisor/conf.d/supervisord.conf"
cat >>/etc/supervisor/conf.d/supervisord.conf <<EOL
[program:squid]
command=squid -NsYd 1
autorestart=true

EOL
ports_arr+=($port_)
echo -e "[X] Log file location is $1\n[X] Server port is $port_"
else
   echo -e "[X] Something wrong!!" 
fi
}

create_file () {
    echo "[X] Creating $1 file"
    mkdir -p $( dirname $1 )
    touch $1
}

config_iptables () {
    echo "Closing all ports"
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    for i in "${ports_arr[@]}"
    do
        echo "Allowing port $i"
        iptables -A INPUT -p tcp --dport $i -j ACCEPT
    done
    if [[ -n "$1" ]]; then
        excluded_ports=($(echo "$1" | tr ',' '\n'))
        for i in "${excluded_ports[@]}"
        do
            echo "Allowing port $i"
            iptables -A INPUT -p tcp --dport $i -j ACCEPT
        done
    fi
}

setup_server_with_port() {
    case $1 in
    "ssh"|"all") ssh "/var/log/ssh.log" $2;;&
    "rdp"|"all") xrdp "/var/log/xrdp.log" $2;;&
    "ldap"|"all") ldap "/var/log/ldap.log" $2;;&
    "ftp"|"all") ftp "/var/log/vsftpd.log" $2;;&
    "samba"|"all") samba "/var/log/smb.log" $2;;&
    "mongodb"|"all") mongodb "/var/log/mongodb/mongod.log" $2;;&
    #"mysql"|"all") mysql "/var/log/mysql/mysql.log" $2;;&
    "redis"|"all") redis "/var/log/redis-monitor.log" $2;;&
    "vnc"|"all") vnc "/var/log/vnc" $2;;&
    "proxy"|"all") squid "/var/log/squid/access.log" $2;;&
    esac
}

parse_input () {
    servers=($(echo "$1" | tr ',' '\n'))
    for server in "${servers[@]}"
    do
        servers_port=($(echo "$server" | tr ':' '\n'))
        if [ "${#servers_port[@]}" -eq 1 ]; then
            setup_server_with_port ${servers_port[0]} "default"
        elif [ "${#servers_port[@]}" -eq 2 ]; then 
            setup_server_with_port ${servers_port[0]} ${servers_port[1]}
        fi
    done
}

req
supervisord
parse_input $1
