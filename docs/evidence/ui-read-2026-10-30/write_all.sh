#!/bin/bash
# Each snapshot as its own writer account (installer accounts and modes).
AGE=${1:-0}
PY=/opt/azazel-nexus/venv/bin/python
for pair in audit_status:azaudit edge_intake_status:azintake incident_explain_status:azexplain incident_recent:azexplain knowledge_status:azknowledge mio_status:azmioentry; do
  name=${pair%%:*}; user=${pair#*:}
  runuser -u "$user" -- env -u PYTHONPATH $PY /share/write_as.py "$name" --age "$AGE"
done
