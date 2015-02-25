#!/usr/bin/python2.6
#
# Track mac address
# in DHCP logs
#
# jm@base-jump.org 2015
#######################
## Import common libs
import re
import sys, getopt
from collections import defaultdict
import time



##############
# Set defaults
admin_mail = "jm@base-jump.org" # sendmail [To]
day = "*"			# default = today
month = "*"			# default = today
year = time.strftime("%Y")      # default = today



#################
# get script args
argv = sys.argv[1:]
try:
        opts, args = getopt.getopt(argv,"had:m:y:s:",["day=","month=","year=","address="])
except getopt.GetoptError:
        print 'p2p-track-mac.py -d <dd> -m <mm> -y <yyyy>'
        sys.exit(2)
for opt, arg in opts:
        if opt in ('-e', "--email"):
                sendmail = 2
        if opt == '-h':
                print "Usage :"
                print 'p2p-track-mac.py -d <dd> -m <mm> -y <yyyy>'
                print "-d (--day)       2 digit day default *"
                print "-m (--month)     2 digit month default *"
                print "-y (--year)      4 digit year default current Year"
                print "jm@base-jump.org 2015"
                sys.exit()
        elif opt in ("-d", "--day"):
                day = arg
        elif opt in ("-m", "--month"):
                month = arg
        elif opt in ("-y", "--year"):
                year = arg
        elif opt in ("-a", "--year"):
                mac_address = arg

