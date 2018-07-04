#!/bin/sh
# chkconfig: - 90 25
echo -n 'nginx service '

case "$1" in
start)
    /etc/nginx/nginx
;;

stop)
    /etc/nginx/nginx -s stop
;;

reload)
    /etc/nginx/nginx -s reload
;;

*)
echo "Usage: `basename $0` {start|stop|reload}"

;;
esac
