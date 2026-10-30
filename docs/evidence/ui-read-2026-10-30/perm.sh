#!/bin/bash
# A UI leaf whose group is not azui (a hand-changed or mis-installed leaf):
# azui must see permission denied, never absent or healthy.
systemctl enable --now azazel-noc-observe.timer
systemctl start azazel-noc-observe.service
bash /share/write_all.sh 0 >/dev/null
chgrp azazel-operator /var/lib/azazel/run/ui-read/incident-explain /var/lib/azazel/run/ui-read/incident-explain/*
chgrp azazel-operator /var/lib/azazel/run/ui-read/noc /var/lib/azazel/run/ui-read/noc/*
ls -l /var/lib/azazel/run/ui-read/ | grep -v total
