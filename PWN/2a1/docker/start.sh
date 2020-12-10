#!/bin/sh
# Add your startup script

chown root:ctf /home/ctf/flag
chmod 640 /home/ctf/flag 

# start ctf-xinetd
/etc/init.d/xinetd start; 
trap : TERM INT; 
sleep infinity & wait\

