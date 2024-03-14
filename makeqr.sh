#!/bin/bash
IFS=$(echo -en "\n\b")
#for x in /opt/wireguard/clientconfigdir/* ; do
#avoiding spaces in usernames
for  x in `find /opt/wireguard/clientconfigdir -maxdepth 1 -mindepth 1 -type d` ; do
	cat "$x/office_vpn.conf"| qrencode -o "$x/qr.png"
done
