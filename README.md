# Linux NAT Gateway

### Step 1. Add USB ethernet to your workstation

Note we are using the *persistent* names for the ethernet interfaces, not the eth0, eth1 etc. which can change on reboot.

```
$ lsusb | grep thernet
Bus 002 Device 003: ID 0b95:1790 ASIX Electronics Corp. AX88179 Gigabit Ethernet
$
```

```
$ dmesg | grep 0b95
[    8.102003] usb 2-5: new SuperSpeed Gen 1 USB device number 3 using xhci_hcd
[    8.384688] usb 2-5: New USB device found, idVendor=0b95, idProduct=1790, bcdDevice= 1.00
[    8.742725] usb 2-5: New USB device strings: Mfr=1, Product=2, SerialNumber=3
[    9.123841] usb 2-5: Product: AX88179
[   11.027242] usb 2-5: Manufacturer: ASIX Elec. Corp.
[   11.027243] usb 2-5: SerialNumber: 000000000001?7
[   82.432298] ax88179_178a 2-5:1.0 eth0: register 'ax88179_178a' at usb-0000:00:14.0-5, ASIX AX88179 USB 3.0 Gigabit Ethernet, a0:ce:c8:c2:34:c7
[   82.434673] ax88179_178a 2-5:1.0 enxa0cec8c234c7: renamed from eth0
[   89.982217] ax88179_178a 2-5:1.0 enxa0cec8c234c7: ax88179 - Link status is: 1
$
```
You can see the interface names with `ip a`:
```
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: enp0s31f6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether a4:bb:6d:93:78:f8 brd ff:ff:ff:ff:ff:ff
    inet 128.232.110.18/24 brd 128.232.110.255 scope global noprefixroute enp0s31f6
       valid_lft forever preferred_lft forever
    inet6 fe80::25c3:aa3:62dc:53ac/64 scope link noprefixroute
       valid_lft forever preferred_lft forever
4: wlp0s20f3: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 70:a6:cc:85:83:e2 brd ff:ff:ff:ff:ff:ff
5: enxa0cec8c234c7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether a0:ce:c8:c2:34:c7 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.1/24 brd 192.168.1.255 scope global enxa0cec8c234c7
       valid_lft forever preferred_lft forever
    inet6 fe80::a2ce:c8ff:fec2:34c7/64 scope link
       valid_lft forever preferred_lft forever
    inet6 fe80::ceac:5af1:49f8:65d9/64 scope link noprefixroute
       valid_lft forever preferred_lft forever
```

Note `enp0s31f6` is the workstation original main ethernet connection to the enterprise LAN, `enxa0cec8c234c7` is the persistent
name of the USB ethernet port used to serve the downstream NAT subnet.
```
$ cat /etc/network/interfaces
# interfaces(5) file used by ifup(8) and ifdown(8)
auto lo
iface lo inet loopback

auto enp0s31f6
iface enp0s31f6 inet dhcp
iface enp0s31f6 inet6 auto

auto enxa0cec8c234c7
iface enxa0cec8c234c7 inet static
    address 192.168.1.1
    netmask 255.255.255.0drwxr-xr-x   2 root root 4.0K Nov 15 09:56 .
    post-up /etc/init.d/isc-dhcp-server start
    post-down /etc/init.d/isc-dhcp-server stop
$
```
# Setting static IP via netplan
```
ll /etc/netplan

drwxr-xr-x 151 root root  12K Nov 15 08:57 ..
-rw-------   1 root root  151 Nov 15 09:56 01-network-manager-all.yaml
-rw-------   1 root root  832 Nov 15 08:51 90-NM-4cd65327-af89-38d2-8d7a-505eaf99afb2.yaml
```
01-network-manager-all.yaml
```
# NAT gateway configuration
---
network:
  version: 2
  renderer: networkd
  ethernets:
    enxa0cec8c234c7:
      addresses:
        - 192.168.1.1/24
```

90-NM-4cd65327-af89-38d2-8d7a-505eaf99afb2.yaml
```
network:
  version: 2
  ethernets:
    NM-4cd65327-af89-38d2-8d7a-505eaf99afb2:
      renderer: NetworkManager
      match:
        name: "enp0s31f6"
      addresses:
      - "128.232.110.18/24"
      nameservers:
        addresses:
        - 131.111.8.42
        - 131.111.12.20
        - 8.8.8.8
      dhcp6: true
      ipv6-address-generation: "stable-privacy"
      wakeonlan: true
      networkmanager:
        uuid: "4cd65327-af89-38d2-8d7a-505eaf99afb2"
        name: "Wired connection 1"
        passthrough:
          connection.autoconnect-priority: "-999"
          connection.permissions: "user:ijl20:;"
          connection.timestamp: "1643823927"
          ethernet._: ""
          ipv4.address1: "128.232.110.18/24,128.232.110.1"
          ipv4.method: "manual"
          ipv6.ip6-privacy: "-1"
          proxy._: ""
```

```
sudo apt install yamllint

sudo yamllint /etc/netplan/01-network-manager-all.yaml
```

```
sudo netplan apply
(ignore Cannot call Open vSwitch: ovsdb-server.service is not running.)
```

```
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: enp0s31f6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether a4:bb:6d:93:78:f8 brd ff:ff:ff:ff:ff:ff
    inet 128.232.110.18/24 brd 128.232.110.255 scope global noprefixroute enp0s31f6
       valid_lft forever preferred_lft forever
    inet6 fe80::25c3:aa3:62dc:53ac/64 scope link noprefixroute
       valid_lft forever preferred_lft forever
4: wlp0s20f3: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 70:a6:cc:85:83:e2 brd ff:ff:ff:ff:ff:ff
5: enxa0cec8c234c7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether a0:ce:c8:c2:34:c7 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.1/24 brd 192.168.1.255 scope global enxa0cec8c234c7
       valid_lft forever preferred_lft forever
    inet6 fe80::a2ce:c8ff:fec2:34c7/64 scope link
       valid_lft forever preferred_lft forever
    inet6 fe80::ceac:5af1:49f8:65d9/64 scope link noprefixroute
       valid_lft forever preferred_lft forever
```

```ping 192.168.1.1
PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=0.044 ms
64 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=0.063 ms
^C
--- 192.168.1.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1022ms
rtt min/avg/max/mdev = 0.044/0.053/0.063/0.009 ms
```

### Step 2. DHCP server installation.
On the next step we need to install DHCP server and make it run on NIC2
Start with the installation, see if isc-dhcp-server is already installed:
```
$ dpkg --list | grep dhcp
ii  isc-dhcp-client             4.4.1-2.1ubuntu5.20.04.2  amd64        DHCP client for automatically obtaining an IP address
ii  isc-dhcp-common             4.4.1-2.1ubuntu5.20.04.2  amd64        common manpages relevant to all of the isc-dhcp packages
ii  isc-dhcp-server             4.4.1-2.1ubuntu5.20.04.2  amd64        ISC DHCP server for automatic IP address assignment
$
```
If not:
```
sudo apt update
sudo apt install isc-dhcp-server
```
Next edit the configuration file:
```
sudo vim /etc/default/isc-dhcp-server
```
Find the line `INTERFACESv4=...` and add the value for the USB ethernet. Save and exit.
After that lets edit the configuration file by opening the file:
```
sudo vim /etc/dhcp/dhcpd.conf
```

```
$ cat /etc/default/isc-dhcp-server
# Defaults for isc-dhcp-server (sourced by /etc/init.d/isc-dhcp-server)

# Path to dhcpd's config file (default: /etc/dhcp/dhcpd.conf).
#DHCPDv4_CONF=/etc/dhcp/dhcpd.conf
#DHCPDv6_CONF=/etc/dhcp/dhcpd6.conf

# Path to dhcpd's PID file (default: /var/run/dhcpd.pid).
#DHCPDv4_PID=/var/run/dhcpd.pid
#DHCPDv6_PID=/var/run/dhcpd6.pid

# Additional options to start dhcpd with.
#	Don't use options -cf or -pf here; use DHCPD_CONF/ DHCPD_PID instead
#OPTIONS=""

# On what interfaces should the DHCP server (dhcpd) serve DHCP requests?
#	Separate multiple interfaces with spaces, e.g. "eth0 eth1".
INTERFACESv4="enxa0cec8c234c7"
INTERFACESv6=""
(venv) ijl20@ijl20-dell7040:~/src/linux_nat_gateway$ cat /etc/dhcp/dhcpd.conf
# dhcpd.conf
#
# Sample configuration file for ISC dhcpd
#
# Attention: If /etc/ltsp/dhcpd.conf exists, that will be used as
# configuration file instead of this file.
#

# option definitions common to all supported networks...
option domain-name "cl.cam.ac.uk";
option domain-name-servers 128.232.1.1, 128.232.1.2, 128.232.1.3;

default-lease-time 600;
max-lease-time 7200;

# The ddns-updates-style parameter controls whether or not the server will
# attempt to do a DNS update when a lease is confirmed. We default to the
# behavior of the version 2 packages ('none', since DHCP v2 didn't
# have support for DDNS.)
ddns-update-style none;

# If this DHCP server is the official DHCP server for the local
# network, the authoritative directive should be uncommented.
#authoritative;

# Use this to send dhcp log messages to a different log file (you also
# have to hack syslog.conf to complete the redirection).
#log-facility local7;

# No service will be given on this subnet, but declaring it helps the
# DHCP server to understand the network topology.

#subnet 10.152.187.0 netmask 255.255.255.0 {
#}

# This is a very basic subnet declaration.

#subnet 10.254.239.0 netmask 255.255.255.224 {
#  range 10.254.239.10 10.254.239.20;
#  option routers rtr-239-0-1.example.org, rtr-239-0-2.example.org;
#}

# This declaration allows BOOTP clients to get dynamic addresses,
# which we don't really recommend.

#subnet 10.254.239.32 netmask 255.255.255.224 {
#  range dynamic-bootp 10.254.239.40 10.254.239.60;
#  option broadcast-address 10.254.239.31;
#  option routers rtr-239-32-1.example.org;
#}

# A slightly different configuration for an internal subnet.
#subnet 10.5.5.0 netmask 255.255.255.224 {
#  range 10.5.5.26 10.5.5.30;
#  option domain-name-servers ns1.internal.example.org;
#  option domain-name "internal.example.org";
#  option subnet-mask 255.255.255.224;
#  option routers 10.5.5.1;
#  option broadcast-address 10.5.5.31;
#  default-lease-time 600;
#  max-lease-time 7200;
#}

# Hosts which require special configuration options can be listed in
# host statements.   If no address is specified, the address will be
# allocated dynamically (if possible), but the host-specific information
# will still come from the host declaration.

#host passacaglia {
#  hardware ethernet 0:0:c0:5d:bd:95;
#  filename "vmunix.passacaglia";
#  server-name "toccata.example.com";
#}

# Fixed IP addresses can also be specified for hosts.   These addresses
# should not also be listed as being available for dynamic assignment.
# Hosts for which fixed IP addresses have been specified can boot using
# BOOTP or DHCP.   Hosts for which no fixed address is specified can only
# be booted with DHCP, unless there is an address range on the subnet
# to which a BOOTP client is connected which has the dynamic-bootp flag
# set.
#host fantasia {
#  hardware ethernet 08:00:07:26:c0:a5;
#  fixed-address fantasia.example.com;
#}

# You can declare a class of clients and then do address allocation
# based on that.   The example below shows a case where all clients
# in a certain class get addresses on the 10.17.224/24 subnet, and all
# other clients get addresses on the 10.0.29/24 subnet.

#class "foo" {
#  match if substring (option vendor-class-identifier, 0, 4) = "SUNW";
#}

#shared-network 224-29 {
#  subnet 10.17.224.0 netmask 255.255.255.0 {
#    option routers rtr-224.example.org;
#  }
#  subnet 10.0.29.0 netmask 255.255.255.0 {
#    option routers rtr-29.example.org;
#  }
#  pool {
#    allow members of "foo";
#    range 10.17.224.10 10.17.224.250;
#  }
#  pool {
#    deny members of "foo";
#    range 10.0.29.10 10.0.29.230;
#  }
#}
#
option subnet-mask 255.255.255.0;

option broadcast-address 192.168.1.255;

subnet 192.168.1.0 netmask 255.255.255.0 {
    range 192.168.1.100 192.168.1.200;
    option routers 192.168.1.1;
}
$
```

```
sudo service isc-dhcp-server restart
```

`/etc/sysctl.conf` Find and uncomment the following line:
```
net.ipv4.ip_forward=1
```

```
$ cat /etc/sysctl.conf
#
# /etc/sysctl.conf - Configuration file for setting system variables
# See /etc/sysctl.d/ for additional system variables.
# See sysctl.conf (5) for information.
#

#kernel.domainname = example.com

# Uncomment the following to stop low-level messages on console
#kernel.printk = 3 4 1 3

##############################################################3
# Functions previously found in netbase
#

# Uncomment the next two lines to enable Spoof protection (reverse-path filter)
# Turn on Source Address Verification in all interfaces to
# prevent some spoofing attacks
#net.ipv4.conf.default.rp_filter=1
#net.ipv4.conf.all.rp_filter=1

# Uncomment the next line to enable TCP/IP SYN cookies
# See http://lwn.net/Articles/277146/
# Note: This may impact IPv6 TCP sessions too
#net.ipv4.tcp_syncookies=1

# Uncomment the next line to enable packet forwarding for IPv4
net.ipv4.ip_forward=1

# Uncomment the next line to enable packet forwarding for IPv6
#  Enabling this option disables Stateless Address Autoconfiguration
#  based on Router Advertisements for this host
#net.ipv6.conf.all.forwarding=1


###################################################################
# Additional settings - these settings can improve the network
# security of the host and prevent against some network attacks
# including spoofing attacks and man in the middle attacks through
# redirection. Some network environments, however, require that these
# settings are disabled so review and enable them as needed.
#
# Do not accept ICMP redirects (prevent MITM attacks)
#net.ipv4.conf.all.accept_redirects = 0
#net.ipv6.conf.all.accept_redirects = 0
# _or_
# Accept ICMP redirects only for gateways listed in our default
# gateway list (enabled by default)
# net.ipv4.conf.all.secure_redirects = 1
#
# Do not send ICMP redirects (we are not a router)
#net.ipv4.conf.all.send_redirects = 0
#
# Do not accept IP source route packets (we are not a router)
#net.ipv4.conf.all.accept_source_route = 0
#net.ipv6.conf.all.accept_source_route = 0
#
# Log Martian Packets
#net.ipv4.conf.all.log_martians = 1
#

###################################################################
# Magic system request Key
# 0=disable, 1=enable all
# Debian kernels have this set to 0 (disable the key)
# See https://www.kernel.org/doc/Documentation/sysrq.txt
# for what other values do
#kernel.sysrq=1

###################################################################
# Protected links
#
# Protects against creating or following links under certain conditions
# Debian kernels have both set to 1 (restricted)
# See https://www.kernel.org/doc/Documentation/sysctl/fs.txt
#fs.protected_hardlinks=0
#fs.protected_symlinks=0
#

# Disable IPV6
#net.ipv6.conf.all.disable_ipv6 = 1

#net.ipv6.conf.default.disable_ipv6 = 1

#net.ipv6.conf.lo.disable_ipv6 = 1
$
```

Reboot. Check with:
```
$ sysctl net.ipv4.ip_forward
net.ipv4.ip_forward = 1
$
```

### Step 3. NAT routing via iptables configuration.
Add a NAT forwarding rule to iptables. Note this is for the workstation enterprise LAN ethernet port, NOT the downstream
USB NAT ethernet. Check the ethernet i/f name with:
```
ip a
```

the set these `iptables` rules:
```
sudo iptables -t nat -A POSTROUTING -o enp0s31f6 -j MASQUERADE
```
Save settings to iptables by installing iptables-persistent:
```
sudo apt-get install iptables-persistent
```
Or if it was already installed please update setting by running:
```
sudo dpkg-reconfigure iptables-persistent
```

# Fixing netplan-based networking after an update

An Ubuntu update requiring a restart seems to regularly break the netplan config for the 192.168.1.1 port and the `ip a` command
will show the 2nd ethernet port with no IP address

```
~$ ip a

1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute
       valid_lft forever preferred_lft forever
2: enp0s31f6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether a4:bb:6d:93:78:f8 brd ff:ff:ff:ff:ff:ff
    inet 128.232.110.18/24 brd 128.232.110.255 scope global noprefixroute enp0s31f6
       valid_lft forever preferred_lft forever
    inet6 fe80::25c3:aa3:62dc:53ac/64 scope link noprefixroute
       valid_lft forever preferred_lft forever
3: enxa0cec8c234c7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether a0:ce:c8:c2:34:c7 brd ff:ff:ff:ff:ff:ff
4: wlp0s20f3: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 70:a6:cc:85:83:e2 brd ff:ff:ff:ff:ff:ff
```

And the dhcp service `sudo service isc-dhcp-server status` will be 'failed':
```
~$ sudo service isc-dhcp-server status
[sudo] password for ijl20:
× isc-dhcp-server.service - ISC DHCP IPv4 server
     Loaded: loaded (/usr/lib/systemd/system/isc-dhcp-server.service; enabled; preset: enabled)
     Active: failed (Result: exit-code) since Tue 2024-09-03 14:06:44 BST; 5s ago
   Duration: 22ms
       Docs: man:dhcpd(8)
    Process: 6075 ExecStart=/bin/sh -ec      CONFIG_FILE=/etc/dhcp/dhcpd.conf;      if [ -f /etc/ltsp/dhcpd.conf ]; then CONFIG_FIL>
   Main PID: 6075 (code=exited, status=1/FAILURE)
        CPU: 15ms

Sep 03 14:06:44 adacity-i1 dhcpd[6075]: Not configured to listen on any interfaces!
Sep 03 14:06:44 adacity-i1 systemd[1]: isc-dhcp-server.service: Failed with result 'exit-code'.
Sep 03 14:06:44 adacity-i1 dhcpd[6075]:
Sep 03 14:06:44 adacity-i1 dhcpd[6075]: If you think you have received this message due to a bug rather
Sep 03 14:06:44 adacity-i1 dhcpd[6075]: than a configuration issue please read the section on submitting
Sep 03 14:06:44 adacity-i1 dhcpd[6075]: bugs on either our web page at www.isc.org or in the README file
Sep 03 14:06:44 adacity-i1 dhcpd[6075]: before submitting a bug.  These pages explain the proper
Sep 03 14:06:44 adacity-i1 dhcpd[6075]: process and the information we find helpful for debugging.
Sep 03 14:06:44 adacity-i1 dhcpd[6075]:
Sep 03 14:06:44 adacity-i1 dhcpd[6075]: exiting.
...skipping...
× isc-dhcp-server.service - ISC DHCP IPv4 server
     Loaded: loaded (/usr/lib/systemd/system/isc-dhcp-server.service; enabled; preset: enabled)
     Active: failed (Result: exit-code) since Tue 2024-09-03 14:06:44 BST; 5s ago
   Duration: 22ms
       Docs: man:dhcpd(8)
    Process: 6075 ExecStart=/bin/sh -ec      CONFIG_FILE=/etc/dhcp/dhcpd.conf;      if [ -f /etc/ltsp/dhcpd.conf ]; then CONFIG_FIL>
   Main PID: 6075 (code=exited, status=1/FAILURE)
        CPU: 15ms

```

The `/etc/netplan` directory will show the required files moved to `*_backup` and the Ubuntu upgrade will only have
built the `90-NM...`file for the main ethernet port.

```
~$ ll /etc/netplan/
total 32K
drwxr-xr-x   2 root root 4.0K Aug 27 08:01 .
drwxr-xr-x 152 root root  12K Sep  3 11:26 ..
-rw-------   1 root root  404 Nov 15  2023 01-network-manager-all.yaml_backup
-rw-------   1 root root  235 Jul 17 10:44 01-network-manager-all.yaml.dpkg-backup
-rw-------   1 root root  832 Nov 15  2023 90-NM-4cd65327-af89-38d2-8d7a-505eaf99afb2.yaml
-rw-------   1 root root  528 Jun 13 11:09 90-NM-c2edbcda-a96b-3dc7-857f-2043af16c030.yaml_backup
```

The solution is to:

```
sudo mv /etc/netplan/01-network-manager-all.yaml{_backup,}
sudo netplan apply
ip a
ping 192.168.1.1
sudo service isc-dhcp-server status
```

The `ip a` command should show the 192.168.1.1 address, and the `ping` should succeed, and the dhcp server should be active.

If necesssary to restart the DHCP server:
```
sudo service isc-dhcp-server restart
```

