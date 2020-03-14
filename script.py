#/usr/bin/env python

'''
Scans hosts ,tests for vulnerabilities using NMAP NSE scripts and also suggest exploits using searchsploit
Uses
-Nmap
-Searchsploit
-Proxychains
-GeoIP Database 
Proxychains4 For scanning through tor or socks 
Searchsploit for suggesting hosts
GeoipDB for selecting ip of state/city

'''
import os
import subprocess
import csv
import json
import xmltodict
import argparse


parser = argparse.ArgumentParser() 

parser.add_argument("-t"    ,  help="Single target or range" , dest='target')
parser.add_argument("--p"   ,  help="All ports", dest='port',  action="store_true")
parser.add_argument("--u"   ,  help="Udp Scan", dest='udp',    action="store_true")
parser.add_argument("--q"   ,  help="Quick Without Service",   dest='quick', action="store_true")
parser.add_argument("--tor" ,  help="Uses tor for connection", dest='tor', action="store_true")
parser.add_argument("-S"    ,  help="Select all ip of State ", dest='state')
parser.add_argument("-c"    ,  help="Select all ip of City ",  dest='city')
parser.add_argument("--v"   ,  help="Scan for Vulnerabilities NSE check", dest='vuln',action="store_true")



args = parser.parse_args() #Arguments to be parsed

data={} #Ouput Data

nmap_args=[] #Arguments to be passed


#Path for Binaries

__nmap__='/usr/bin/nmap'
__searchsploit__='/usr/local/bin/searchsploit'
__proxychains4__='/usr/local/bin/proxychains4'
__data__='data.csv'


#Initializing Output Structure 

data['hosts']={}
data['hosts']['total']=0
data['hosts']['up']=0
data['hosts']['down']=0



#Function to call Nmap

def result_caclulate(target,nmap_args,conn):

	#Check if Tor Connection is to be made for Scan
	if conn==1:
		nmap=[__proxychains4__,'-q',__nmap__,'-oX','-',target]
	else:
		nmap=[__nmap__,'-oX','-',target]
	nmap.extend(nmap_args)
	result=subprocess.check_output(nmap)
	results=json.dumps(xmltodict.parse(result), indent=4, sort_keys=True)
	results = json.loads(results)
	nmap_data(results)


#Check for Depedencies

def check_system():
	if not (os.path.exists(__nmap__)):
		print("Nmap Not Found!")
		print("Check Path of Nmap")
		exit()

	if not (os.path.exists(__searchsploit__)):
		print("Searchsploit Not Found!")
		print("Check Path of Searchsploit")
		print("Continuing Scan without Suggesting Exploits")

	if not (os.path.exists(__proxychains4__)):
		print("Proxychains4 Not Found!")
		print("Check Path of Proxychains4")

	if not (os.path.exists(__data__)):
		print("Data.csv Not Found!")
		print("Check Path of Proxychains4")
	if( os.getuid()==0):
		print("Running As User root")
		print("Nmap will do syn sleath scan can take much time")

#Function to calculate all ip of an area from the file.

def locality(area,type,nmap_args,conn):
	with open(__data__,'rt')as f:
		data = csv.reader(f)
		for row in data:
			if(type==1):
				areamain=row[3]
			else:
				areamain=row[2]
			if(areamain)==area:
  				start=row[0].split('.')
  				end=row[1].split('.')
  				while(int(end[2])>=int(start[2])):
  					if(int(end[2])==int(start[2])):
  						ip=str(start[0])+'.'+str(start[1])+'.'+str(start[2])+'.'+str(start[3])+'-'+end[3]
  					else:
  						ip=str(start[0])+'.'+str(start[1])+'.'+str(start[2])+'.'+str(start[3])+'-255'
  					start[2]=int(start[2])+1
  					result_caclulate(ip,nmap_args,conn)


#Function to check for any exploits for the target in Searchsploit

def exploit_suggester(ip,port,service):
	searchsploit=[__searchsploit__,'-j',service]
	exploit=subprocess.check_output(searchsploit)
	exploit=json.loads(exploit.decode("utf-8"))
	for key,value in exploit.items():
		if type(value)==type(list()):
			for key,value in enumerate(value):
				eid=value['EDB-ID']
				data[ip]['exploits'][eid]={}
				data[ip]['exploits'][eid]['port']=port
				data[ip]['exploits'][eid]['title']=value['Title']
				data[ip]['exploits'][eid]['date']=value['Date']
				data[ip]['exploits'][eid]['type']=value['Type']
				data[ip]['exploits'][eid]['platform']=value['Platform']
				data[ip]['exploits'][eid]['path']=value['Path']

#Function to scan and pull results from NSE scripts Scan

def vulnerable(value,ip):
	data[ip]['vulnerbilities']={}
	if type(value['script'])==type(list()):
		for key1,value1 in enumerate(value['script']):
			try:
				if value1['#text']=='false':
					pass
			except:
				vid=value1['@id']
				data[ip]['vulnerbilities'][vid]={}
				data[ip]['vulnerbilities'][vid].update(value1['table'])
					
			


#Function to Insert Nmap data into Dictonary

def data_ips(address): 
	if type(address)==type(list()):
		for key,value in enumerate(address):
			if value['@addrtype']=='ipv4':
				ip=value['@addr']
				data[ip]={}
			try:
				if value['@addrtype']=='mac':
					data[ip]['mac']=value['@addr']
					data[ip]['vendor']=value['@vendor']
			except:
				pass
	else:
		if address['@addrtype']=='ipv4':
			ip=address['@addr']
			data[ip]={}
	return ip

#Function to collect important result of ports

def data_ports(ports,ip):

	if type(ports)==type(list()):	#Dealing with Multiple Port
		for key,value in enumerate(ports):
			if value['state']['@state']=='open':
				port=value['@portid']
				data[ip]['ports'][port]={}
				try:
					service=value['service']['@product']
					data[ip]['exploits']={}
					exploit_suggester(ip,port,service)
					
					#Get all data from the ports 
				
				except:
					pass
			try:
					data[ip]['ports'][port]['name']=value['service']['@name']
					data[ip]['ports'][port]['protocol']=value['@protocol']
					data[ip]['ports'][port]['service']=value['service']['@product']
					try:
						data[ip]['ports'][port]['cpe']=value['service']['cpe']
						data[ip]['ports'][port]['version']=value['service']['@version']
						data[ip]['ports'][port]['info']=value['service']['@extrainfo']
					except:
						pass
					data[ip]['ports'][port]['hostname']=value['service']['@hostname']
					data[ip]['ports'][port]['ostype']=value['service']['@ostype']
			except:
				pass
	else:			#Dealing with Single Ports
		value=ports
		if value['state']['@state']=='open':
			port=value['@portid']
			data[ip]['ports'][port]={}
			try:
				service=value['service']['@product']
				data[ip]['exploits']={}
				exploit_suggester(ip,port,service)
			except:
				pass
		try:
				data[ip]['ports'][port]['name']=value['service']['@name']
				data[ip]['ports'][port]['protocol']=value['@protocol']
				data[ip]['ports'][port]['service']=value['service']['@product']
				try:
					data[ip]['ports'][port]['cpe']=value['service']['cpe']
					data[ip]['ports'][port]['version']=value['service']['@version']
					data[ip]['ports'][port]['info']=value['service']['@extrainfo']
				except:
					pass
				data[ip]['ports'][port]['hostname']=value['service']['@hostname']
				data[ip]['ports'][port]['ostype']=value['service']['@ostype']
		except:
			pass

#Function to collect basic scan data results.

def nmap_data(results):

	for key,value in results.items():
		if key=='hosts':
			data['hosts']['total']+=int(value['@total'])
			data['hosts']['up']+=int(value['@up'])
			data['hosts']['down']+=int(value['@down'])


		if (key=='host'):
			if type(value)==type(dict()):      #Dealing with Single Host
				
				address=value['address']
				ip=data_ips(address)
				if value['hostnames']!=None:
					data[ip]['hostname']=value['hostnames']['hostname']['@name']
				if value['ports']!=None:
					data[ip]['ports']={}
					try:
						ports=value['ports']['port']
						data_ports(ports,ip)
					except:
						pass
				try:
					vulnerable(value['hostscript'],ip)
				except:
					pass
						
			elif type(value)==type(list()):    #Dealing with Multiple Hosts
				for key,value in enumerate(value):
					if type(value)==type(dict()):
						address=value['address']
						ip=data_ips(address)
						if value['hostnames']!=None:
							data[ip]['hostname']=value['hostnames']['hostname']['@name']
						if value['ports']!=None:
							data[ip]['ports']={}
							try:
								ports=value['ports']['port']
								data_ports(ports,ip)
							except:
								pass
						try:
							if value['hostscript']!=None:
								if type(value)==type(list()):
									vulnerable(value,ip)
						except:
							pass
					elif type(value)==type(list()):
						pass	

		if type(value) == type(dict()):
			nmap_data(value)
		elif type(value) == type(list()):
			for val in value:
				if type(val) == type(str()):
					pass
				elif type(val) == type(list()):
					nmap_data(value)
				else:
					nmap_data(val)


def main():
	path=check_system()
	conn=0

	if args.quick:
		pass
	else:
		nmap_args.append('-sV')

	
	if args.tor:
		conn=1 
	
	if args.udp:
		nmap_args.append('-sU')

	if args.port:
		nmap_args.append('-p-')
	
	if args.vuln:
		nmap_args.append('--script')
		nmap_args.append('vuln')


	if args.target != None :
		target=args.target

	elif args.city!= None:
		area=args.city
		locality(area,1,nmap_args,conn)
		print(json.dumps(data, indent=4, sort_keys=True)) 
		exit()

	elif args.state!= None:
		area=args.state
		locality(area,2,nmap_args,conn)
		print(json.dumps(data, indent=4, sort_keys=True))
		exit()

	else:
		print("No Argument Supplied . See --help -h for help")
		exit()

	result_caclulate(target,nmap_args,conn)
	print(json.dumps(data, indent=4, sort_keys=True))


if __name__ == '__main__':
    main()
