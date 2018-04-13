#!/bin/sh
yum install -y perl gcc autoconf automake make gcc-c++ libxml2-devel libcap-devel libtool libtool-ltdl-devel openssl openssl-devel python-devel openldap-devel
pip install boto3
pip install python-ldap
cd /tmp
wget ftp://ftp.csx.cam.ac.uk/pub/software/programming/pcre/pcre-8.41.tar.gz
tar -zxf pcre-8.41.tar.gz
cd pcre-8.41
./configure
make
make install
cd /tmp
wget http://zlib.net/zlib-1.2.11.tar.gz
tar -zxf zlib-1.2.11.tar.gz
cd zlib-1.2.11
./configure
make
make install
cd /tmp
wget http://nginx.org/download/nginx-1.13.5.tar.gz
tar zxf nginx-1.13.5.tar.gz
cd nginx-1.13.5
./configure --sbin-path=/etc/nginx/nginx --conf-path=/etc/nginx/nginx.conf --pid-path=/etc/nginx/nginx.pid --with-http_ssl_module --with-stream --with-pcre=../pcre-8.41 --with-zlib=../zlib-1.2.11 --with-http_auth_request_module --with-http_auth_request_module --without-http_empty_gif_module
make
make install
cd /tmp
wget https://github.com/aws-samples/amazon-elasticsearch-service-with-authentication/raw/master/nginx-elasticsearch.conf
yes |  cp -rf nginx-elasticsearch.conf /etc/nginx/nginx.conf
sed -ie "s/ELASTICSEARCHURL/$1/g" /etc/nginx/nginx.conf
sed -ie "s/BASEDN/$2/g" /etc/nginx/nginx.conf
sed -ie "s@SERVERNAME@$3@g" /etc/nginx/nginx.conf
sed -ie "s/BINDDN/$4/g" /etc/nginx/nginx.conf
sed -ie "s/PASSWORD/$5/g" /etc/nginx/nginx.conf
sed -ie "s/LISTENER_SERVER_PORT_1/$6/g" /etc/nginx/nginx.conf
sed -ie "s/LISTENER_SERVER_PORT_2/$7/g" /etc/nginx/nginx.conf
sed -ie "s@ELASTICSEARCHARN@$8@g" /etc/nginx/nginx.conf
sed -ie "s/ADGROUPPREFIX/$9/g" /etc/nginx/nginx.conf
wget https://github.com/aws-samples/amazon-elasticsearch-service-with-authentication/raw/master/nginx.sh -O /etc/init.d/nginx
wget https://github.com/aws-samples/amazon-elasticsearch-service-with-authentication/raw/master/nginx-ldap-auth-daemon.py -P /etc/nginx/nginx-ldap-auth/
wget https://github.com/aws-samples/amazon-elasticsearch-service-with-authentication/raw/master/nginx-ldap-auth-daemon.sh -O /etc/init.d/nginx-ldap-auth-daemon
chmod +x /etc/init.d/nginx
chmod +x /etc/init.d/nginx-ldap-auth-daemon
chkconfig nginx-ldap-auth-daemon on
chkconfig nginx on
mkdir /etc/nginx/ssl
cd /etc/nginx/ssl
openssl genrsa -out nginx.key 2048
openssl req -new -key nginx.key -out nginx.csr -subj "/C=XX/ST=XX/L=nginx/O=nginx/CN=nginx"
openssl x509 -req -days 365 -in nginx.csr -signkey nginx.key -out nginx.crt
cat nginx.key nginx.crt | tee nginx.pem
service nginx start
service nginx-ldap-auth-daemon start
