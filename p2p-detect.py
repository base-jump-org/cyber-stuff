#!/usr/bin/python2.6
#
# Analyse des logs de connexion
# Recherche de connexions P2P
# 
# SPORT>xxxx && DPORT>xxxx
# IP DEST Multiples
#
# jm@base-jump.org 2015
# Log format
# Feb 22 23:59:59 192.168.10.1 kernel: firewall: Feb 23 2015 00:03:44 : Create connection src=192.168.20.163 dst=8.8.8.8 proto=udp 
#    sport=55811 dport=53 gw=10.0.4.138 ewan=4 invert src=8.8.8.8 dst=10.0.4.1 
######################
## Import common libs
import re
import sys, getopt
from collections import defaultdict
import time
## Import the email modules we'll need
from email.mime.text import MIMEText
import smtplib



##############
# Set defaults
admin_mail = "jm@base-jump.org" # sendmail [To]
seuil_detection = 150		# default = 150 differents IP
day = time.strftime("%d")       # default = today
month = time.strftime("%m")     # default = today
year = time.strftime("%Y")	# default = today
sendmail = 0 			# default = do not send mail
safe_ports=(5523,5228,23389) 	# allowed ports above 1024 (Ex: ESF connection on 23389)
min_port_value = 1024		# port > min_port_value are detected



#################
# get script args
argv = sys.argv[1:]
try:
	opts, args = getopt.getopt(argv,"hed:m:y:s:",["day=","month=","year=","seuil=","email"])
except getopt.GetoptError:
	print 'p2p-detect.py -d <dd> -m <mm> -y <yyyy> -s <seuil> -e'
	sys.exit(2)
for opt, arg in opts:
	if opt in ('-e', "--email"):
		sendmail = 2
	if opt == '-h':
		print "Usage :"
		print 'p2p-detect.py -d <dd> -m <mm> -y <yyyy> -s <seuil> -e'
		print "-d (--day)	2 digit day"
		print "-m (--month)	2 digit month"
		print "-y (--year)	4 digit year"
		print "-s (--seuil)	max connection before alert"
		print "-e (--email)	send an email to admin"
		print "jm@base-jump.org 2015"
		sys.exit()
	elif opt in ("-d", "--day"):
		day = arg
	elif opt in ("-m", "--month"):
		month = arg
	elif opt in ("-y", "--year"):
		year = arg
	elif opt in ("-s", "--seuil"):
		seuil_detection = int(arg)







####################
## Get mac addresses
## DHCP Log File Format :
## Feb 23 20:33:00 192.168.10.1 dhcpd: DHCPACK on 192.168.20.99 to 60:03:08:95:b8:d2 via lan
## ip = ip to search
## dhcp_url = path to dhcp log file
def mac_address(ip, dhcp_url):
	mac_dict = {}
	with open(dhcp_url) as dhcp_file:
        	# Parse log file lines
        	for line in dhcp_file:
                	search = re.search('DHCPACK on ' + ip + ' to ([0-9a-f:]{17})', line)
	                if search:
        	                regs_mac = search.groups()
				# create a mac_dictionnary
				# with mac address and number of occurences
				# the more we find it, the more suspect he is ;-)
				if regs_mac[0] in mac_dict:
					mac_dict[regs_mac[0]] += 1
				else:
					mac_dict[regs_mac[0]] = 1

		dhcp_file.close()
	return mac_dict




###################
## send mail alert
## email = [To] mail
## text = body text
def send_mail(email, text):
	mail = 'p2p@lescontamines.org'
	# Create a text/plain message
	msg = MIMEText(text)

	# no coment ...
	msg['Subject'] = 'Peer 2 peer Alert - ' + time.strftime("%d/%m/%Y")
	msg['From'] = 'p2p@lescontamines.org'
	msg['To'] = email

	# Send the message via our own SMTP server, but don't include the
	# envelope header.
	s = smtplib.SMTP('localhost')
	s.sendmail(mail, email, msg.as_string())
	s.quit()










##############
# get log file
log_url = "/data/pfsense/" + year + "/" + month + "/" + day + "/gateway.log"
dhcp_url = "/data/pfsense/" + year + "/" + month + "/" + day + "/dhcp.log"

print "LOG File ", log_url
print "DHCP File ", dhcp_url


## open log file
with open(log_url) as log_file:

	# init array
	tree = lambda: defaultdict(tree)
	src_dict = tree()
	lines = 0

	# Parse log file lines
	for line in log_file:
		lines += 1
		# search ereg for IP & PORTS	
		search = re.search('Create connection src=192\.168\.20\.([0-9]{1,3}) dst=([0-9\.]{7,15}) proto=([a-z]*) sport=([0-9]*) dport=([0-9]*)', line)
		if search:
			regs = search.groups()
			ip_src = '192.168.20.{0}'.format(regs[0])
			ip_dst = regs[1]
			proto = regs[2]
			port_src = regs[3]
			port_dst = regs[4]

			# filter on both ports > 1024 and not in safe_ports range
			if (int(port_src) > min_port_value and int(port_dst) > min_port_value and int(port_src) not in safe_ports and int(port_dst) not in safe_ports):
				# add this IP
				if ip_src in src_dict:
					if ip_dst in src_dict[ip_src]:
						src_dict[ip_src][ip_dst] += 1
					else:
						src_dict[ip_src][ip_dst] = 1
				else :
					src_dict[ip_src][ip_dst] = 1

	log_file.close()

nbtotal = 0
alert_text = ""
for key in sorted(src_dict):
	nb = len(src_dict[key])
	nbtotal += nb
	if nb > seuil_detection:
		alert_text += key + "\t" + str(nb) + "\t" 
		macs = mac_address(key, dhcp_url)
		for key in macs:
			alert_text += key + "(" + str(macs[key]) + ") "
		alert_text += "\n"

print alert_text
print lines, " lignes dans le log"
print nbtotal, " detections (seuil ",str(seuil_detection) + ")"

if sendmail > 0:
	send_mail(admin_mail, alert_text)
