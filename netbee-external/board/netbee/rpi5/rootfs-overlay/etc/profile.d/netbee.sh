# NetBee OS - Interactive Shell Profile, Router Aliases & Login Summary
export PATH="/bin:/sbin:/usr/bin:/usr/sbin"

case "$-" in
	*i*)
		export HISTSIZE=1000
		export HISTFILESIZE=2000
		export EDITOR="/bin/vi"
		[ -r /etc/inputrc ] && export INPUTRC="/etc/inputrc"
		if command -v less >/dev/null 2>&1; then
			export PAGER="less"
		fi

		case "${TERM:-}" in
			xterm*|vt*|linux|screen*|tmux*|rxvt*)
				if [ "$(id -u)" -eq 0 ]; then
					export PS1='\[\033[1;31m\][\u@\h:\w]#\[\033[0m\] '
				else
					export PS1='\[\033[1;32m\][\u@\h:\w]$\[\033[0m\] '
				fi
				;;
			*)
				if [ "$(id -u)" -eq 0 ]; then
					export PS1='[\u@\h:\w]# '
				else
					export PS1='[\u@\h:\w]$ '
				fi
				;;
		esac

		alias ll='ls -la'
		alias la='ls -A'
		alias status='netbee-status'
		alias cli='netbee-cli'
		alias logs='tail -n 50 /var/log/messages'
		alias follow='tail -f /var/log/messages'
		alias ports='netstat -tulnp 2>/dev/null'
		alias fw='nft list ruleset'
		alias conns='conntrack -L 2>/dev/null | head -n 50'

		if [ -z "${NETBEE_WELCOME_SHOWN:-}" ]; then
			export NETBEE_WELCOME_SHOWN=1
			_nb_lan_if="eth0"
			_nb_wan_if="eth1"
			if [ -r /etc/netbee/netif.env ]; then
				# shellcheck disable=SC1091
				. /etc/netbee/netif.env
				[ -n "${LAN_IF:-}" ] && _nb_lan_if="$LAN_IF"
				[ -n "${WAN_IF:-}" ] && _nb_wan_if="$WAN_IF"
			fi
			_nb_lan_ip="$(ip -4 -o addr show dev "$_nb_lan_if" 2>/dev/null | awk '{print $4; exit}')"
			_nb_wan_ip="$(ip -4 -o addr show dev ppp0 2>/dev/null | awk '{print $4; exit}')"
			[ -z "$_nb_wan_ip" ] && _nb_wan_ip="$(ip -4 -o addr show dev "$_nb_wan_if" 2>/dev/null | awk '{print $4; exit}')"
			_nb_ver="NetBee OS"
			if [ -r /etc/os-release ]; then
				_nb_ver="$(awk -F= '$1=="PRETTY_NAME"{gsub(/"/,"",$2); print $2}' /etc/os-release)"
			fi

			echo "------------------------------------------------------------"
			echo " ${_nb_ver}"
			echo " LAN (${_nb_lan_if}) : ${_nb_lan_ip:-unassigned}  |  WAN : ${_nb_wan_ip:-disconnected}"
			echo " Web UI/API : https://${_nb_lan_ip%/*}  |  DNS/DHCP : http://${_nb_lan_ip%/*}:3000"
			echo " CLI Tools  : netbee-cli, netbee-status, netbee-passwd, netbee-user, netbee-backup"
			if [ "$(id -u)" -ne 0 ]; then
				echo " Privileges : Logged in as '$(id -un)' — run 'su -' for root shell"
			elif [ ! -f /etc/netbee/auth.json ] || grep -q '"must_change_password":[[:space:]]*true' /etc/netbee/auth.json 2>/dev/null; then
				echo " WARNING    : Default password is active! Run 'netbee-passwd' to change it."
			fi
			echo "------------------------------------------------------------"
			unset _nb_lan_if _nb_wan_if _nb_lan_ip _nb_wan_ip _nb_ver
		fi
		;;
esac
