#!/bin/bash
# chkconfig: - 90 25
echo -n 'nginx-ldap-auth-daemon service '
# Description: Bash Script to Start the process with NOHUP and & - in background, pretend to be a Daemon

# For debugging purposes uncomment next line
#set -x

# Configuration
APP_NAME="nginx-ldap-auth-daemon"
APP_FILENAME="nginx-ldap-auth-daemon"
APP_PID="/var/run/$APP_NAME.pid"
APP_PATH="/etc/nginx/nginx-ldap-auth"
APP_FILE=$APP_FILENAME".py"
APP_LOGS="/var/log"
#for example: APP_PRE_OPTION="java -jar"
APP_PRE_OPTION="python"
APP_POST_OPTION=""

# Should Not Be altered
TMP_FILE="/tmp/status_$APP_NAME"
### For internal usage
STATUS_CODE[0]="Is Running"
STATUS_CODE[1]="Not Running"
STATUS_CODE[2]="Stopped incorrectly"
STATUS_CODE[9]="Default Status, should not be seen"

start() {

    checkpid
	STATUS=$?
	if [ $STATUS -ne 0 ] ;
    then
		echo "Starting $APP_NAME..."
		## java –jar $APP_PATH/ghost.jar
		nohup $APP_PRE_OPTION $APP_PATH/$APP_FILE $APP_POST_OPTION > $APP_LOGS/$APP_FILENAME.out 2> $APP_LOGS/$APP_FILENAME.err < /dev/null &
		echo PID $!
		echo $! > $APP_PID

		statusit
		#echo "Done"
    else
		echo "$APP_NAME Already Running"
    fi
}

stop() {
  checkpid
	STATUS=$?
	if [ $STATUS -eq 0 ] ;
	then
		echo "Stopping $APP_NAME..."
		kill `cat $APP_PID`
		rm $APP_PID
		statusit
		#echo "Done"
	else
		echo "$APP_NAME - Already killed"
	fi
}

checkpid(){
    STATUS=9

    if [ -f $APP_PID ] ;
	then
		#echo "Is Running if you can see next line with $APP_NAME"
		ps -Fp `cat $APP_PID` | grep $APP_FILE > $TMP_FILE
		if [ -f $TMP_FILE -a -s $TMP_FILE ] ;
			then
				STATUS=0
				#"Is Running (PID `cat $APP_PID`)"
			else
				STATUS=2
				#"Stopped incorrectly"
			fi

		## Clean after yourself
		rm -f $TMP_FILE
	else
		STATUS=1
		#"Not Running"
	fi

	return $STATUS
}

statusit() {
	#TODO
    #status -p $APP_PID ghost
    checkpid
    #GET return value from previous function
	STATUS=$?
	#echo $?

	EXITSTATUS=${STATUS_CODE[STATUS]}

	if [ $STATUS -eq 0 ] ;
	then
		EXITSTATUS=${STATUS_CODE[STATUS]}" (PID `cat $APP_PID`)"
	fi

	#echo "First Index: ${NAME[0]}"
	#echo "Second Index: ${NAME[1]}"

    echo $APP_NAME - $EXITSTATUS
    #${STATUS_CODE[STATUS]}

}



case "$1" in

    'start')
        start
        ;;

    'stop')
        stop
        ;;

    'restart')
        stop
        start
        ;;

    'status')
        statusit
        ;;

    *)
        echo "Usage: $0 { start | stop | restart | status }"
        exit 1
        ;;
esac

exit 0
