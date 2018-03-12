#!/usr/bin/env sh
python -c "import re;f=open('/etc/resolv.conf','r');t=f.read();t=re.sub(r'ndots:\d+',r'ndots:1',t);open('/etc/resolv.conf','w').write(t)"

exec python /app/run.py