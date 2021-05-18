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
	apt-get -y update && apt-get -y install wget zlib1g-dev build-essential libssl-dev lsof rsyslog supervisor iptables sudo
}

supervisord() {
mkdir -p /var/log/supervisor && touch /var/log/supervisor/supervisord.log
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
wget https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-8.3p1.tar.gz && tar xvfz openssh-8.3p1.tar.gz 1>/dev/null
sed '0,/struct passwd \*pw = authctxt->pw;/s//struct passwd \*pw = authctxt->pw;logit("Username %s Password %s",pw->pw_name,password);/' -i openssh-8.3p1/auth-passwd.c
echo "sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin" >> /etc/passwd
cd openssh-8.3p1 && ./configure 1>/dev/null && make 1>/dev/null && make install 1>/dev/null 
sed -ri 's/^#?PermitRootLogin\s+.*/PermitRootLogin no/' /usr/local/etc/sshd_config && sed -ri 's/UsePAM yes/#UsePAM yes/g' /usr/local/etc/sshd_config && sed -ri 's/#Port 22/Port '$2'/g' /usr/local/etc/sshd_config
echo "AllowUsers $(head /dev/urandom | tr -dc A-Za-z0-9 | head -c50)" >> /usr/local/etc/sshd_config && echo "SyslogFacility AUTH" >> /usr/local/etc/sshd_config && echo "LogLevel VERBOSE" >> /usr/local/etc/sshd_config && echo "PasswordAuthentication yes" >> /usr/local/etc/sshd_config
sed -i '/imklog/s/^/#/' /etc/rsyslog.conf
rm -f $1 && echo "[X] SSHD Auth Logs" > $1 && chown syslog:adm $1
cat >>/etc/supervisor/conf.d/supervisord.conf <<EOL
[program:sshd]
command=/usr/local/sbin/sshd -D -f /usr/local/etc/sshd_config
autorestart=true

EOL
echo -e "\n---------Settings---------\nLog file location is $1\nSSH Server port is $2\n--------------------------\n"
ports_arr+=($2)
}

ldap (){
create_file $1
echo 'slapd/root_password password sysbackup' | debconf-set-selections && \
echo 'slapd/root_password_again password sysbackup' | debconf-set-selections && \
DEBIAN_FRONTEND=noninteractive apt-get -yqq install slapd ldap-utils
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
cat >>/etc/supervisor/conf.d/supervisord.conf <<EOL
[program:ldap]
command=/usr/sbin/slapd -h "ldap://:$2/ ldaps:/// ldapi:///" -u openldap -g openldap -d 256
stdout_logfile=$1
stdout_logfile_maxbytes=0
redirect_stderr=true
autorestart=true

EOL
echo -e "\n---------Settings---------\nLog file location is $1\nLDAP Server port is $2\n--------------------------\n"
ports_arr+=($2)
} 

mysql () {
create_file $1
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
sed -e 's/^#general_log_file.*/general_log_file = \/var\/log\/mysql\/mysql.log/' -i /etc/mysql/mysql.conf.d/mysqld.cnf &&\
sed -e 's/^log_error \=.*/log_error = \/var\/log\/mysql\/mysql.log/' -i /etc/mysql/mysql.conf.d/mysqld.cnf &&\
sed -e 's/^#general_log.*/general_log = 3/' -i /etc/mysql/mysql.conf.d/mysqld.cnf
mkdir -p /var/run/mysqld && \
chown -R mysql:mysql /var/lib/mysql /var/run/mysqld && \
chmod 777 /var/run/mysqld
cat >>/etc/supervisor/conf.d/supervisord.conf <<EOL
[program:mysql]
command=/usr/bin/pidproxy /var/run/mysqld/mysqld.pid /usr/bin/mysqld_safe
autorestart=true

EOL
}

redis () {
create_file $1
DEBIAN_FRONTEND=noninteractive apt-get -yqq install redis-server && \
sed 's/^daemonize yes/daemonize no/' -i /etc/redis/redis.conf && \
sed "s/^bind .*/bind 0.0.0.0/g" -i /etc/redis/redis.conf && \
sed 's/port 6379/port '$2'/g' -i /etc/redis/redis.conf && \
sed 's/^# requirepass.*/requirepass sysbackup/' -i /etc/redis/redis.conf && \
sed 's/^protected-mode yes/protected-mode no/' -i /etc/redis/redis.conf
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
echo -e "\n---------Settings---------\nLog file location is $1\nREDIS Server port is $2\n--------------------------\n"
ports_arr+=($2)
}

mongodb (){
DEBIAN_FRONTEND=noninteractive apt-get -yqq install mongodb && \
mkdir -p /data/db
#echo "Waiting on Mongodb to start.." && \
#service mongodb start && \
#sleep 5 && \
#mongo --eval 'db=db.getSiblingDB("admin");db.createUser({user:"root",pwd:"sysbackup",roles:["root"]})'
cat >>/etc/supervisor/conf.d/supervisord.conf <<EOL
[program:mongod]
command=/usr/bin/mongod --quiet --logpath $1 --logappend --auth --bind_ip 0.0.0.0 --port $2
autorestart=true

EOL
echo -e "\n---------Settings---------\nLog file location is $1\nMONGODB Server port is $2\n--------------------------\n"
ports_arr+=($2)
}

samba (){
DEBIAN_FRONTEND=noninteractive apt-get -yqq install samba-common samba 
groupadd -g 1000 smbtemp && \
useradd -g smbtemp -l -M -s /bin/false -u 1000 smbtemp && \
mkdir -p /smbtemp && \
chown -R smbtemp:smbtemp smbtemp
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
printf "sysbackup\nsysbackup" | smbpasswd -a -s -c smb.conf smbtemp
cat >>/etc/supervisor/conf.d/supervisord.conf <<EOL
[program:smbd]
command=smbd --foreground --no-process-group --configfile /smb.conf
autorestart=true

EOL
}

ftp (){
create_file $1
DEBIAN_FRONTEND=noninteractive apt-get -yqq install db-util vsftpd
mkdir /etc/vsftpd/ && \
mkdir -p /home/vsftpd/ftpbackup && \
mkdir -p /var/run/vsftpd/empty && \
chown -R ftp:ftp /home/vsftpd/ && \
echo -e "ftpbackup\nsysbackup" > /etc/vsftpd/virtual_users.txt && \
db_load -T -t hash -f /etc/vsftpd/virtual_users.txt /etc/vsftpd/virtual_users.db
cat >>ftp.conf <<EOL
listen=yes
background=NO
listen_port=$2
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
cat >>/etc/supervisor/conf.d/supervisord.conf <<EOL
[program:vsftpd]
command=vsftpd ftp.conf
autorestart=true

EOL
echo -e "\n---------Settings---------\nLog file location is $1\nFTP Server port is $2\n--------------------------\n"
ports_arr+=($2)
}

vnc() {
echo "[X] Creating $1 directory"
mkdir -p $1
DEBIAN_FRONTEND=noninteractive apt-get -yqq install tightvncserver
useradd --create-home vncbackup && \
su -c "mkdir -p /home/vncbackup/.vnc" vncbackup && \
su -c "echo 'sysbackup' | vncpasswd -f > /home/vncbackup/.vnc/passwd" vncbackup && \
chmod 600 /home/vncbackup/.vnc/passwd && \
mkdir -p /var/log/vnc/ && \
ln -s /home/vncbackup/.vnc/ $1
cat >>/etc/supervisor/conf.d/supervisord.conf <<EOL
[program:vncd]
command=su -c "vncserver -rfbport $2 -geometry 1280x800 :0 && sleep infinity" vncbackup

EOL
echo -e "\n---------Settings---------\nLog folder location is $1\nVNC Server port is $2\n--------------------------\n"
ports_arr+=($2)
}

xrdp() {
create_file $1
DEBIAN_FRONTEND=noninteractive apt-get -yqq install xrdp
cat >>/etc/xrdp/xrdp.ini <<EOL
[globals]
bitmap_cache=yes
bitmap_compression=yes
port=$2
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
cat >>/etc/supervisor/conf.d/supervisord.conf <<EOL
[program:xrdp]
command=xrdp -nodaemon

EOL
echo -e "\n---------Settings---------\nLog file location is $1\nRDP Server port is $2\n--------------------------\n"
ports_arr+=($2)
}

apache () {
DEBIAN_FRONTEND=noninteractive apt-get -yqq install apache2
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

setup_server() {
    case $1 in
    "ssh") ssh "/var/log/ssh.log" "22";;
    "rdp") xrdp "/var/log/xrdp.log" "3389";;
    "ldap") ldap "/var/log/ldap.log" "389";;
    "ftp") ftp "/var/log/vsftpd.log" "21";;
    "samba") samba "/var/log/smb.log" "445";;
    "mongodb") mongodb "/var/log/mongodb/mongod.log" "27017";;
    "redis") redis "/var/log/redis-monitor.log" "6379";;
    "vnc") vnc "/var/log/vnc" "5900";;
    *) echo "Invalid option";;
    esac
}

setup_server_with_port() {
    case $1 in
    "ssh") ssh "/var/log/ssh.log" $2;;
    "rdp") xrdp "/var/log/xrdp.log" $2;;
    "ldap") ldap "/var/log/ldap.log" $2;;
    "ftp") ftp "/var/log/vsftpd.log" $2;;
    "samba") samba "/var/log/smb.log" $2;;
    "mongodb") mongodb "/var/log/mongodb/mongod.log" $2;;
    "redis") redis "/var/log/redis-monitor.log" $2;;
    "vnc") vnc "/var/log/vnc" $2;;
    *) echo "Invalid option";;
    esac
}

parse_input () {
    servers=($(echo "$1" | tr ',' '\n'))
    for server in "${servers[@]}"
    do
        servers_port=($(echo "$server" | tr ':' '\n'))
        if [ "${#servers_port[@]}" -eq 1 ]; then
            setup_server ${servers_port[0]}
        elif [ "${#servers_port[@]}" -eq 2 ]; then 
            setup_server_with_port ${servers_port[0]} ${servers_port[1]}
        fi
    done
}

req
supervisord
parse_input $1