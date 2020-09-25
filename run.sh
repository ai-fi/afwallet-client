#!/bin/sh

sudo iptables -A INPUT -p tcp --dport 8000 -j ACCEPT
./counterseal

