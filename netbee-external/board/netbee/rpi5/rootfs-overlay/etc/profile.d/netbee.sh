# NetBee OS - Interactive Login Helper & First-Boot Security Reminder
case "$-" in
	*i*)
		echo "NetBee OS | Commands: netbee-status, netbee-sqm, netbee-backup"
		echo "Web API / UI : https://192.168.10.1  |  AdGuardHome: http://192.168.10.1:3000 (admin / netbee)"
		if [ "$(id -u)" -eq 0 ] && [ -r /etc/shadow ]; then
			_lastchg=$(awk -F: '$1=="root"{print $3}' /etc/shadow 2>/dev/null)
			if [ -z "$_lastchg" ]; then
				echo "WARNING: Default root password is still active. Run 'passwd' to change it."
			fi
			unset _lastchg
		fi
		;;
esac
