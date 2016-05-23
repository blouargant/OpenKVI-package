#/bin/sh

declare -i COUNT
COUNT=0
while true ; do
	STATUS=`service nodemanagerd status`
	if [ "$STATUS" == "nodemanagerd dead but pid file exists" ]; then
		echo "nodemanagerd is dead, automatic restart"
		service nodemanagerd restart
		COUNT=0
		sleep 5
		STATUS=`service nodemanagerd status | grep "nodemanagerd .* is running"`
		while [ -z "$STATUS" ]; do
			if [ $COUNT -eq 3 ]; then
				exit 1
			else
				service nodemanagerd restart
				sleep 5
				STATUS=`service nodemanagerd status | grep "nodemanagerd .* is running"`
				COUNT=$(( COUNT + 1 ))
			fi
		done
		COUNT=0
	fi
	sleep 3
done
