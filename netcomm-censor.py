#!/usr/bin/python  
import sys, os
import configparser

import time
import requests
import zlib

from baseconv import base16, base62
from etaprogress.progress import ProgressBar

from base64 import b64encode #easier to operate in this case

import hashlib
import ast

import ipaddress

# from my img2.py
PROGRAM_NAME = "netcomm-censor"
PROGRAM_NAME_SHORT = "nccensor"

CONFIG_FILE_NAME = "censor.ini"
CONFIG_SECTION_DEFAULT = "DEFAULT"
CONFIG_SECTION_CURRENT = "IN_USE"
# short
C = CONFIG_SECTION_CURRENT

CONFIG_DEFTUPLE = "host"

PORTS_ALL = "1:65535"
PORTS_1000 = "1:1000" #unused but justincase

def time_salt():
	return str(int(time.time()))

def toHexCustom(dec): 
	return str(hex(dec).split('x')[-1])	

def kwikHash(txt):
	return toHexCustom(zlib.adler32(txt.encode('utf-8')))
	
def config_write(c, f):
	with open(f, 'w+') as configfile:
		c.write(configfile)
	
def config_default(c):
	c['DEFAULT']['host'] = "192.168.20.1" # router host
	c['DEFAULT']['local'] = "192.168.20.0/24" # local subnet
	c['DEFAULT']['login'] = "admin" # router login 
	c['DEFAULT']['pass'] = "admin" # router password
	# ports to block. Port 0 is not blockable
	# also see: https://www.grc.com/port_0.htm
	c['DEFAULT']['ports'] = PORTS_ALL
	
	c['DEFAULT']['header'] = """{
'User-Agent' : 'Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0',
'Accept-Language' : 'en-GB,en;q=0.5',
'Accept-Encoding' : 'gzip, deflate',
'DNT': '1',
'Upgrade-Insecure-Requests': '1'
}
"""
	
	c['DEFAULT']['url_view'] = '/scoutflt.cmd?action=view' # might not be via scoutflt.cmd
	c['DEFAULT']['url_add'] = '/scoutflt.html'
	c['DEFAULT']['url_doAdd'] = '/scoutflt.cmd' #action will be defined later
	c['DEFAULT']['url_doAdd_action'] = 'add'
	
def config_section_exists(c, section, default_tuple):
	buf = ""
	
	# https://stackoverflow.com/a/24899624
	try:
		buf = c.get(section, default_tuple)
	except:
		return False
		
	if (buf == ""): # still
		return False
	else:
		return True


def config_validate(c):
	changed = False

	if not(config_section_exists(c, CONFIG_SECTION_DEFAULT, CONFIG_DEFTUPLE)):
		changed = True
		config_default(c)

	if not(config_section_exists(c, CONFIG_SECTION_CURRENT, CONFIG_DEFTUPLE)):
		changed = True
		c[CONFIG_SECTION_CURRENT] = c.defaults()
		
	if(changed):
		config_write(c, CONFIG_FILE_NAME)
		print(CONFIG_FILE_NAME+" "+"was validated")

# not so fast but very collisionless hash algo based on Keccak approach
def keccakmod(s):
	rawhash = hashlib.sha3_224(s.encode).hexdigest()
	modhash = base62.encode(base16.decode(rawhash))
	
	return modhash
	
def gen_basicAuth(login, password):
	# Reference: https://stackoverflow.com/a/7000784
	s = login+":"+password
	buf = b64encode(s.encode).decode("ascii")
	return "Basic "+buf

# https://stackoverflow.com/a/3368991
def find_between( s, first, last ):
    try:
        start = s.index( first ) + len( first )
        end = s.index( last, start )
        return s[start:end]
    except ValueError:
        return ""

def find_between_r( s, first, last ):
    try:
        start = s.rindex( first ) + len( first )
        end = s.rindex( last, start )
        return s[start:end]
    except ValueError:
        return ""

def find_hiddenjs(s):
	return find_between(s, "<!-- hide", " -->")

def main():
	HOW_TO = """1. Edit config.ini (if needed)
2. List ips to block in list.txt (in CIDR notation)
3. Run script
4. ???. Done
	"""
	
	print(PROGRAM_NAME+" "+"greets you!")
	print("How to:")
	print(HOW_TO)
	
	argc = len(sys.argv) - 1
	
	config = configparser.ConfigParser()
	config.read(CONFIG_FILE_NAME)
	config_validate(config)
		
	# cenlist
	if(argc > 0):
		censor_list = (str(sys.argv[1]))
	else:
		censor_list = "list.txt"
	
	lfile = open(censor_list, "r+")
	lines = [line.rstrip('\n') for line in lfile]
	work = len(lines)+1
	if(work <= 1):
		# no IPs
		raise ValueError("No input found in "+censor_list)
		
	bar = ProgressBar(work)
	
	# print for user
	print(PROGRAM_NAME+" initialised")
	print("stdout will be logged to "+logname)
	
	# pre-cook vars we will often use
	def_header = ast.literal_eval(c[C]['header']).extend(
		{'Authorization': gen_basicAuth(c[C]['login'], c[C]['pass'])})
		
	url = c[C]['host']
	url_view = url + c[C]['url_view']
	url_add = url + c[C]['url_add']
	
	url_doAdd = url + c[C]['url_doAdd']
	#/scoutflt.cmd?action=add&fltNa
	url_doAdd_template = url_doAdd_template + "?action="+c[C]['url_doAdd_action'] 
	
	ports = c['DEFAULT']['ports']
	lan = c['DEFAULT']['local']

	hidden_js_len_last = 0

	cookies = {}

	logname = PROGRAM_NAME+"_"+time_salt()+".log"
	log = open(logname, "a+")

	print("App will start in 2s")
	# allow user to change mind
	time.sleep(2)


	# authorise chk
	r = requests.get(c[C]['host'], cookies=cookies, headers=def_header)	
	if(r.status_code > 400):
		raise ValueError("Invalid credentials ("+r.status_code+")")
			
	#payload		
	for i in range(work):		
		line = strip(lines[i])
		ipversion = ipaddress.ip_network(line).version
		ipversion_str = str(ipversion)
		
		# if ip invalid
		if(len(ipversion_str) <= 0):		
			bar.numerator = i
			what_to_log = "Line: "+line+" - invalid IP! "
				
			log.write(what_to_log+"\n")
			print(what_to_log)		
			print(str(bar))

			continue
		
		# Steps might change if more effecient way found 
		# 1. Go to url_add
		r = requests.get(url_add, cookies=cookies, headers=def_header)
		
		# 2. Proc response
		txt = r.text
		
		## Hidden JS
		hidden_js = find_hiddenjs(txt)
		hidden_js_len = len(hidden_js)
		
		### grab a session key, which ive no idea how to grab overwise
		### r for faster as it tends to stay in the latter part of string
		skey = find_between_r(hidden_js, "sessionKey=", "';")
		
		# 3. Construct a get request
		##  Sample:
		# GET /scoutflt.cmd?action=add&fltName=name11111111111&ipver=4&protocol=0&srcAddr=222.222.222.222/22&srcPort=3:3333&dstAddr=44.44.44.44&dstPort=5:5555&sessionKey=440647167 HTTP/1.1
		
		url_construct =  url_doAdd_template #start
		
		# filtre name 
		url_construct += "&fltName="
		url_construct += keccakmod(line+time_salt) # will use time salted sha3 hash shortened by base62
		
		# ip version
		url_construct += "&ipver="
		url_construct += ipversion_str
		
		# protocol (always 0 for all traffic block)
		url_construct += "&protocol=0"
		
		# lan address
		url_construct += "&srcAddr="
		url_construct += lan
		
		# lan ports to block
		url_construct += "&srcPort="
		url_construct += ports
		
		# destination ip address range in CIDR
		url_construct += "&dstAddr="
		url_construct += line
		
		# their ports
		url_construct += "&dstPort="
		url_construct += ports
		
		# session key we grabbed before 
		url_construct += "&sessionKey="
		url_construct += skey
		
		#and... thats it folks
		
		# 4 Send a block request	
		r = requests.get(url_construct, cookies=cookies, headers=def_header)
		
		# 5 Document and start all over
		bar.numerator = i
		what_to_log = "Line: "+line+" | Code: "+(r.status_code)+" | Last JS len: "+hidden_js_len_last
		what_to_log +=" ({0:+}) ".format(hidden_js-hidden_js_len_last)
			
		log.write(what_to_log+"\n")
		print(what_to_log)		
		print(str(bar))
		#sys.stdout.flush()
		
		hidden_js_len_last = hidden_js_len
		
	# do loop partially
	# 1. Go to url_add
	r = requests.get(url_add, cookies=cookies, headers=def_header)
	
	# 2. Proc response
	txt = r.text
	
	## Hidden JS
	hidden_js = find_hiddenjs(txt)
	hidden_js_len = len(hidden_js)

	#payload (for-loop) over
	what_to_log = "Fin. Final JS len: "+str(hidden_js_len)

	log.write(what_to_log+"\n")
	print(what_to_log)
	
	log.close()

if __name__ == '__main__':
	main()