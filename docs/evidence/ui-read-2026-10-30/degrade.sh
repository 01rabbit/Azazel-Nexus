#!/bin/bash
bash /share/write_all.sh 600 >/dev/null
systemctl disable --now azazel-noc-observe.timer
rm -f /var/lib/azazel/run/noc-status/status.json /var/lib/azazel/run/ui-read/noc/status.json
ls /var/lib/azazel/run/ui-read/noc/ ; ls /etc/systemd/system/timers.target.wants/ | grep azazel
