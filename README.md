# pptp-route-helper

Linux PPTP route helper for automatic DHCP classless routes ( Classless-Static-Route, rfc3442-classless-static-routes, Option 121, Classless-Static-Route-Microsoft, ms-classless-static-routes, Option 249 )

This scripts is useful if you have MacOS/FreeBSD or Linux clients in your network and they are using PPTP VPN. You do not have to hardcode routing for them, you can just use this script to receive and add routes automatically. And you only have to modify your route settings in your DHCP server after that.

(For the server part: http://www.janoszen.com/2012/08/07/in-search-of-the-perfect-vpn-solution/)

### perl module dependency
- Getopt::Std
- IO::Socket::INET
- IO::Select
- Socket
- Net::DHCP::Packet
- Net::DHCP::Constants
- POSIX
- Sys::Hostname
- require 'sys/ioctl.ph'

If your are using debian, you need the following packages: ```perl perl-base perl-modules libnet-dhcp-perl```

### options
```
# perl pptp-route-helper.pl -h
Usage:
	pptp-route-helper.pl -i <interface> [OPTION...]


DHCP route helper for PPTP VPN
Help options:
-h                      Show help options

Application options:
	-i <interface>        Set interface to send and receive DHCP requests - mandatory
	-t <timeout>          Set soft timeout for receive dhcp messages - default 3 seconds
	-x <timeout>          Set hard timeout for receiving dhcp messages (SIGALARM) - default: soft*3 seconds
	-a <ip address>       Source IP address for packets and listening - default: automatic
	-m <dhcp hostname>    Override DHCP client hostname
	-r <type>             Route command type. Valid options: bsd, iproute2, route - default: iproute2
	-s                    Add DHCP server pool subnet to routemap also. (DHCP subnet option) - disabled by default
	-d                    Debug mode - disabled by default
	-n                    dry run - dont add route, just print them
```
## example

### manual run 
```
root@asd:/home/macskas# perl pptp-route-helper.pl -i ppp1 -s -r bsd -n
[15/Apr/2016:14:39:53] INFO  > Send DHCP inform broadcast message from 10.1.2.83
[15/Apr/2016:14:39:53] INFO  > Receive DHCP reply. (timeout_soft=3, timeout_hard=9)
[15/Apr/2016:14:39:53] INFO  > I would run: route add 10.0.0.0/9 -interface ppp1
[15/Apr/2016:14:39:53] INFO  > I would run: route add 192.168.0.0/21 -interface ppp1
```
### automatic
First copy pptp-route-helper.pl to /usr/local/sbin/ directory.
Then you have to create a shell script and place it in the /etc/ppp/ip-up.d/ directory.
```
root@asd:/etc/ppp/ip-up.d# cat asd.sh 
#!/bin/bash

export PATH="/sbin:/bin:/usr/sbin:/usr/bin"

if [ $# -eq 0 ]; then
    echo "error: $0 <devname>";
    exit 1
fi

DEVNAME="$1"
IP="$4"

/usr/bin/perl /usr/local/sbin/pptp-route-helper.pl -i "$DEVNAME" -a "$IP" -s -r iproute2 -t 3 -m fakeclienthostname
```
