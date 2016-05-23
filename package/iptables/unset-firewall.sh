#!/bin/bash
#
# Set iptables for secure mode
#
# Flush all current rules from iptables
#
iptables -F
# Allow all 
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
#
# Save settings
#
/sbin/service iptables save
