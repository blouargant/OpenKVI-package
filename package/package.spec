Summary: OpenKVI application
Name: openkvi
Version:
Release:
Distribution:
Packager: b.louargant <bertrand.louargant@comverse.com>
License: GPL 
BuildArch: noarch
Source0:
Requires: bash, python, python-paramiko, libvirt-python, python-xmltodict
Requires: tomcat, nginx, onectl
BuildRoot:  %{_tmppath}/%{name}-%{version}-buildroot
Provides: openkvi, nodemanager = %{version}

%description
OpenKVI, Open Virtualization Infrastructure Interface, is a Web application
designed to control virtualization servers based on Libvirt. 
Nodemanger is a libvirt interface to communicate with virtualisation nodes.

%prep
%setup

%build

%install
rm -rf $RPM_BUILD_ROOT
# OpenKVI files
#mkdir -p $RPM_BUILD_ROOT/var/lib/tomcat/webapps/
mkdir -p $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}
mkdir -p $RPM_BUILD_ROOT/usr/local/%{name}
mkdir -p $RPM_BUILD_ROOT/etc/nginx/conf.d
install -m 0644 openkvi.war $RPM_BUILD_ROOT/usr/local/%{name}/%{name}-%{version}.war
install -m 0644 favicon.ico $RPM_BUILD_ROOT/usr/local/%{name}/
install -m 0644 server.xml $RPM_BUILD_ROOT/usr/local/%{name}/
install -m 0644 index.html $RPM_BUILD_ROOT/usr/local/%{name}/
install -m 0644 collectd.conf $RPM_BUILD_ROOT/usr/local/%{name}/
install -m 0644 releasenote-%{name}-%{version}.txt $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}
# Nodemanager files
mkdir -p $RPM_BUILD_ROOT/usr/bin/nodemanager
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
mkdir -p $RPM_BUILD_ROOT/etc/nodemanager/nginx
mkdir -p $RPM_BUILD_ROOT/etc/nodemanager/iptables
install -m 0755 *.py $RPM_BUILD_ROOT/usr/bin/nodemanager/
install -m 0755 monitor_nodemanagerd.sh $RPM_BUILD_ROOT/usr/bin/nodemanager/
install -m 0755 nodemanagerd $RPM_BUILD_ROOT/etc/rc.d/init.d/
install -m 0644 nodemanager.conf $RPM_BUILD_ROOT/etc/nodemanager/
# Nginx files
install -m 0644 nginx.conf $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}
install -m 0644 openkvi_nginx_ssl.conf $RPM_BUILD_ROOT/etc/nodemanager/nginx/
install -m 0644 authenticate.lua $RPM_BUILD_ROOT/etc/nginx/conf.d/
install -m 0644 openkvi_nginx_unsecure.conf $RPM_BUILD_ROOT/etc/nodemanager/nginx/
install -m 0644 openkvi_nginx_secure.conf $RPM_BUILD_ROOT/etc/nodemanager/nginx/
install -m 0644 openkvi_server.key $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}
install -m 0644 openkvi_server.crt $RPM_BUILD_ROOT/usr/share/doc/%{name}-%{version}
# iptables files
install -m 0744 set-firewall.sh $RPM_BUILD_ROOT/etc/nodemanager/iptables/
install -m 0755 unset-firewall.sh $RPM_BUILD_ROOT/etc/nodemanager/iptables/


%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
/usr/bin/nodemanager/*.py
/usr/bin/nodemanager/monitor_nodemanagerd.sh
/etc/rc.d/init.d/nodemanagerd
%config(noreplace) /etc/nodemanager/nodemanager.conf
/usr/local/%{name}/%{name}-%{version}.war
/usr/local/%{name}/favicon.ico
/usr/local/%{name}/server.xml
/usr/local/%{name}/index.html
/usr/local/%{name}/collectd.conf
/etc/nodemanager/nginx/openkvi_nginx_unsecure.conf
/etc/nodemanager/nginx/openkvi_nginx_secure.conf
/etc/nodemanager/nginx/openkvi_nginx_ssl.conf
/etc/nginx/conf.d/authenticate.lua
/etc/nodemanager/iptables/set-firewall.sh
/etc/nodemanager/iptables/unset-firewall.sh
%doc releasenote-%{name}-%{version}.txt
%doc nginx.conf
%doc openkvi_server.key
%doc openkvi_server.crt

%pre
rm -f /tmp/openkvi-data.tgz
TOMCAT_PATH="/usr/share/tomcat"
if [ -d "/usr/share/tomcat6" ]; then
	TOMCAT_PATH="/usr/share/tomcat6"
fi
if [ -d "$TOMCAT_PATH/webapps/openkvi/resources/data" ]; then
	service tomcat stop
	tar czf /tmp/openkvi-data.%{version}.tgz $TOMCAT_PATH/webapps/openkvi/resources/data 1>/dev/null 2>&1
	cp $TOMCAT_PATH/webapps/openkvi/WEB-INF/web.xml /tmp/openkvi-%{version}-web.xml
	rm -rf $TOMCAT_PATH/webapps/openkvi*
fi
#rm -f /etc/httpd/conf.d/ssl.conf 2>/dev/null

%post
TOMCAT_PATH="/usr/share/tomcat"
if [ -d "/usr/share/tomcat6" ]; then
	TOMCAT_PATH="/usr/share/tomcat6"
fi
# Nodemanager post install
chkconfig --add nodemanagerd
chkconfig --level 345 nodemanagerd on
chkconfig --level 345 nginx on
rm /etc/nginx/nginx.conf 2>/dev/null
cp /usr/share/doc/%{name}-%{version}/nginx.conf /etc/nginx/
rm /etc/nginx/conf.d/default.conf 2>/dev/null
rm /etc/nginx/conf.d/ssl.conf 2>/dev/null
service nginx restart 2>/dev/null


# Make OpenVII default application
mkdir -p $TOMCAT_PATH/webapps/ROOT
cp -f /usr/local/%{name}/index.html $TOMCAT_PATH/webapps/ROOT/


## OpenKVI post install
rm -f $TOMCAT_PATH/webapps/openkvi.war 2>/dev/null
cp -a /usr/local/%{name}/%{name}-%{version}.war $TOMCAT_PATH/webapps/openkvi.war

service tomcat start
echo "Waiting for war file to be deployed ..."
sleep 15

#echo "Checking Database tables ..."
## Check Database Tables:
#TABLES=`psql -U openkvi openkviDB -c "\dt" | grep public | sed -e "s/ public | //" | sed -e "s/|.*//" | sed -e "s/ *//"`
#NO_NODES=`echo $TABLES | grep -v "nodes"`
#NO_VMS=`echo $TABLES | grep -v "vms"`
#NO_USERS=`echo $TABLES | grep -v "users"`
#NO_GROUPS=`echo $TABLES | grep -v "groups"`
#NO_AUTH=`echo $TABLES | grep -v "authentication"`
#if [ "$NO_NODES" ]; then
#	psql -U openkvi openkviDB -c "CREATE TABLE nodes (id SERIAL PRIMARY KEY, name VARCHAR(50) NOT NULL, ip VARCHAR(50) NOT NULL, hypervisor VARCHAR(50) NOT NULL, description VARCHAR(50));"
#fi
#
#if [ "$NO_VMS" ]; then
#	psql -U openkvi openkviDB -c "CREATE TABLE vms (id SERIAL PRIMARY KEY, memory INT, nbcpu INT, freqcpu VARCHAR(50), arch VARCHAR(50), network VARCHAR(50), cdrom VARCHAR(50), name VARCHAR(50) NOT NULL, server VARCHAR(50) NOT NULL, disks VARCHAR(50), displayedname VARCHAR(50) NOT NULL);"
#fi
#
#if [ "$NO_USERS" ]; then
#	psql -U openkvi openkviDB -c "CREATE TABLE users (id SERIAL PRIMARY KEY, login VARCHAR(50) UNIQUE NOT NULL, password VARCHAR(50) NOT NULL, role VARCHAR(50) NOT NULL, lastName VARCHAR(50), firstName VARCHAR(50), mail VARCHAR(50), groupId VARCHAR(50));"
#	psql -U openkvi openkviDB -c "insert into users (login, password, role) values ('admin', 'admin', 'Administrator');"
#fi
#
#if [ "$NO_GROUPS" ]; then
#	psql -U openkvi openkviDB -c "CREATE TABLE groups (id SERIAL PRIMARY KEY, name VARCHAR(50) UNIQUE NOT NULL);"
#	psql -U openkvi openkviDB -c "insert into groups (name) values ('Administrator');"
#	psql -U openkvi openkviDB -c "insert into groups (name) values ('User');"
#	psql -U openkvi openkviDB -c "insert into groups (name) values ('PowerUser');"
#else 
#	CONTENT=`psql -U openkvi openkviDB -c "SELECT * FROM groups;" | grep "[1-9]"`
#	if [ -z "$CONTENT" ]; then
#		psql -U openkvi openkviDB -c "insert into groups (name) values ('Administrator');"
#		psql -U openkvi openkviDB -c "insert into groups (name) values ('User');"
#		psql -U openkvi openkviDB -c "insert into groups (name) values ('PowerUser');"
#	fi
#fi
#
## Update Roles for all users
#psql -U openkvi openkviDB -c "UPDATE users SET role='Administrator' WHERE role='admin' ;" 1>/dev/null 2>&1
#psql -U openkvi openkviDB -c "UPDATE users SET role='Administrator' WHERE role='administrator' ;"  1>/dev/null 2>&1
#psql -U openkvi openkviDB -c "UPDATE users SET role='User' WHERE role='user' ;"  1>/dev/null 2>&1
#psql -U openkvi openkviDB -c "UPDATE users SET role='PowerUser' WHERE role='Power User' ;"  1>/dev/null 2>&1
#
#if [ "$NO_AUTH" ]; then
#	psql -U openkvi openkviDB -c "CREATE TABLE authentication (id SERIAL PRIMARY KEY, mode character varying(32) NOT NULL, ldaphost character varying(255), ldapport character varying(16), ldapadminlogin character varying(64), ldapadminpassword character varying(255), ldapbasedn character varying(255), ldapcreationmode character varying(32) NOT NULL, ldapdefaultrole character varying(50), ldapidentifierfield character varying(64), ldapfirstnamefield character varying(64), ldaplastnamefield character varying(64), ldapmailfield character varying(64), CONSTRAINT authentication_creationmode CHECK (((((ldapcreationmode)::text = ('AutoSubscription'::character varying)::text) OR ((ldapcreationmode)::text = ('AdminValidation'::character varying)::text)) OR ((ldapcreationmode)::text = ('AdminAdd'::character varying)::text))));"
#	psql -U openkvi openkviDB -c "insert into authentication (mode, ldapcreationmode, ldapdefaultrole) values ('SQL', 'AutoSubscription', 'user');"
#else 
#	psql -U openkvi openkviDB -c "ALTER TABLE authentication DROP CONSTRAINT authentication_mode;" 2>/dev/null
#fi
#
## Restart postgresql
#service postgresql restart 1>>/tmp/openkvi-install.log 2>&1


if [ -e "/tmp/openkvi-data.%{version}.tgz" ]; then
	echo "Restoring data ..."
	rm -rf $TOMCAT_PATH/webapps/openkvi/resources/data
	tar xzf /tmp/openkvi-data.%{version}.tgz -C /
	rm -f $TOMCAT_PATH/webapps/openkvi/WEB-INF/web.xml
	cp /tmp/openkvi-%{version}-web.xml $TOMCAT_PATH/webapps/openkvi/WEB-INF/web.xml
	chown tomcat.tomcat $TOMCAT_PATH/webapps/openkvi/WEB-INF/web.xml

fi
chown -R tomcat.tomcat $TOMCAT_PATH/webapps/openkvi/resources 1>/dev/null 2>&1
chown tomcat.tomcat $TOMCAT_PATH/.ssh/id_dsa

# start iptables service
echo "Setting firewalling options ..."
chkconfig --level 345 iptables on
SECLEVEL=`grep "^ *security *= *" /etc/nodemanager/nodemanager.conf | sed -e "s/.*= *//"`
if [ "$SECLEVEL" ]; then
	if [ "$SECLEVEL" == "low" ]; then
		sh /etc/nodemanager/iptables/unset-firewall.sh
	elif [ "$SECLEVEL" == "high" ]; then
		sh /etc/nodemanager/iptables/set-firewall.sh
	fi
else
	echo "security=low" >> /etc/nodemanager/nodemanager.conf
	sh /etc/nodemanager/iptables/unset-firewall.sh
fi


# Finally re-start nodemanagerd
service nodemanagerd restart


%preun

%postun
# Nodemanager post-uninstall
NODEMANAGER_FILES=`ls /usr/share/doc/%{name}-* 2>/dev/null`
if [ ! "$NODEMANAGER_FILES" ]; then
	echo "Removing nodemanagerd service ..."
	service nodemanagerd stop
	killall monitor_nodemanagerd.sh 2>/dev/null
	chkconfig --del nodemanagerd
fi
# OpenKVI post-uninstall
WAR_FILES=`ls $TOMCAT_PATH/webapps/openkvi-* 2>/dev/null`
if [ ! "$WAR_FILES" ]; then
	echo "Removing openkvi webapp's folder ..."
	rm -rf $TOMCAT_PATH/webapps/openkvi*
fi

%changelog
