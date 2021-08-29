# UFWlogreader
Parse the UFW log file for some simple statistics 

## UFW
UFW is a basic firewall service on Ubuntu that can be enabled to block unwanted inbound traffic. 

Logs are kept in /var/log/ufw.log, containing details of blocked traffic. 

## Stats from the logs 
This program is a simple exercise to parse out the fields in the ufw.log and give some 
basic stats on what's being blocked. 

## Defaults: 
By default, the program reads /var/log/ufw.log. Adjust the code to look at other files. 
