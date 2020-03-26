#!/usr/bin/python3

from xml.dom import minidom
from xml.dom.minidom import Document
from neo4j import GraphDatabase, basic_auth
import os,sys,datetime,time,re, subprocess
import multiprocessing
from multiprocessing import Process,Lock
import argparse



def isDomain():
	
	#Url: https://github.com/zakird/pyad/blob/master/pyad/adbase.py
	#Lines: 11-42 - adbase.py
	#Fix the code: @taso_x
	if sys.platform != 'win32':
		raise Exception("Must be running Windows.")

	else:	
		try:
			import win32api
			import pywintypes
			import win32com.client
			import win32security
		except ImportError:
			raise Exception("pywin32 library required. Download from http://sourceforge.net/projects/pywin32/")


		_adsi_provider = win32com.client.Dispatch('ADsNameSpaces')

		try:
			# Discover default domain and forest information
			__default_domain_obj = _adsi_provider.GetObject('', "LDAP://rootDSE")
			# connecting to rootDSE will connect to the domain that the
			# current logged-in user belongs to.. which is generally the
			# domain under question and therefore becomes the default domain.
			_default_detected_forest = __default_domain_obj.Get("rootDomainNamingContext")
			_default_detected_domain = __default_domain_obj.Get("defaultNamingContext")
			if(_default_detected_domain):
				print("[+] Domain Found: "+_default_detected_domain)
			if(_default_detected_forest):
				print("[+] Forest Found: "+_default_detected_forest)
			return True
			
		except:
			# If there was an error, this this computer might not be on a domain.
			__default_domain_obj = "None"
			_default_detected_forest = "None"
			_default_detected_domain = "None"
			print("[-] Couldn't connect with LDAP Server!")
			print("\r\n")
			return False
		

def sid2name(sid):
	dom = win32com.client.GetObject("LDAP://rootDSE").Get("defaultNamingContext")
	conn = win32com.client.Dispatch('ADODB.Connection')
	conn.Open("Provider=ADSDSOObject")
	query = "<LDAP://"+dom+">;(&(objectClass=*)(objectSid="+sid+"));sAMAccountName"
	record_set = conn.Execute(query)[0]
	targetUser=record_set.Fields("sAMAccountName").value
	return(targetUser)

	

def regEx(string):
	
	dotCounter=0
	if("@" in str(string)):
		s = re.findall("^\w+[^@]",str(string))[0]
	elif("\\" in str(string)):
		s = re.findall("[^\\\]*$",str(string))[0]
	elif("." in str(string)):
		for num,chr in enumerate(string):
			if chr == ".":
				dotCounter=dotCounter+1
		if dotCounter == 1: #Example username.lastname or desktop111-maria.domain.com
			s = re.findall("^.\w+[.|-]\w+",string)[0]  #Result: username.lastname or dektop111-maria
		elif dotCounter == 2: #Example username.domain.com
			s = re.findall("^\w+",string)[0] #Result: username
		elif dotCounter >= 3: #Example username.lastname.domain.com
			s = re.findall("^\w+[.-]\w+",string)[0] #Result: username.lastname
		else:
			s = str(string)
	
	else:
		s = str(string)
	return(s.upper())	

def regExIP(ip):
	ipAddress=str(ip)
	if(ipAddress.startswith(':')): #Example: ::ffff:192.168.100.50
		s = re.findall("\w+[.].*",ipAddress)[0] #Result: 192.168.100.50
	else:
		s = ipAddress
	
	return(s)
	
def neo4jConn(neo4jUri,neo4jUser,neo4jPass):

	try:
		driver = GraphDatabase.driver(neo4jUri, auth=basic_auth(user=neo4jUser, password=neo4jPass))
		#print("[+] Successful connection with database")			
		return(driver)	
	except Exception as e:
		print("[-] %s" % e)
		sys.exit(1)
			
		
def eventParser(eventIDs):
	
		
	dict={}
	dict2={}
	dict3={}
	counter=0
	t=[]

	try:
		for p in rootDoc.childNodes: 
			counter=counter+1
			
			for x in p.childNodes:
				for y in x.childNodes:
					try:
						if not y.firstChild:
							tag=y.nodeName
							attrs=y.attributes.items()
							value=y.firstChild
												
						else:
							tag=y.nodeName
							attrs=y.attributes.items()
							value=y.firstChild.nodeValue
						dict={'Tags':tag,'Attrs':attrs,'Value':value}
						if not dict['Attrs']:
							#print ("[+]%s:%s" %(dict['Tags'],dict['Value'])) [OK]
							key = dict['Tags']
							value = dict['Value']
						for key,value in dict['Attrs']:
							if dict['Tags'] != 'Data':						
								#print("[+]%s:%s" % (key,value))
								key = key
								value = value
							else:
								#print("[+]%s:%s" % (value, dict['Value']))
								key = value
								value = dict['Value']
						#print ("[+]%s:%s" % (key,value)) [OK]
						#if key not in ['Message']:
						dict2={key:value}
						dict3={counter:dict2}
						t.append(dict3)
					except:	
						pass
	except Exception as e:
		print(e)
	
	#print(t) [OK]	
	input_list = {}

	#Group events
	for x in range(len(t)):
		for k,v in t[x].items():
			if k not in input_list:
				input_list[k]=[v]
			else:
				input_list[k].append(v)
	
	#print(input_list)
	
	filterEvents = eventIDs
	localhostIPs=["","-","::1","127.0.0.1","localhost"]
	blacklistedUsers=["DWM-3","UMFD-3","UMFD-2","DWM-2","-","UMFD-0","UMFD-1","DWM-1"]
	blacklistedShareFolders=["\\\\*\\SYSVOL","\\\\*\\IPC$"]
	
	#How many data will process
	dataProcess = str(len(input_list.keys()))
	return (filterEvents, localhostIPs, blacklistedUsers, blacklistedShareFolders, input_list)

def createXML(evIDs,lhostIPs,bListedUsers,bListedShareFolders,eventList,sysmonFile,outXMLFile):


	targetUserList=[]
	remoteHostsList=[]
	uniqueIPs=[]
	file_handle = open(outXMLFile,"w")
	
	doc = Document()
	root = doc.createElement('Events')
	doc.appendChild(root)
	
	#print(eventList.items()) [OK]
	print("[+] Searching for TargetUsers, RemoteHosts, TargetHosts ...")
	if len(eventList.items()) > 0:
		t={}
		counter=0
		for key, value in eventList.items():
			for eventValues in value:
				t.update(eventValues)
			if t.get("EventID") in evIDs:
			
				if sysmonFile: #User provided Sysmon xml file.
					
					if t.get("User"):
						targetUser = t.get("User")
					elif t.get("UserID"):
						targetUser = t.get("UserID")
					elif t.get("SubjectUserName"):
						targetUser = t.get("SubjectUserName")
					else:	
						targetUser = "None"
						print("[-] Event ID %s with Record ID %s does not have a targetUser." % (t.get("EventID"),t.get("EventRecordID")))
						
					
					
					if t.get("SourceIp"):
						remoteHost = t.get("SourceIp")
					elif t.get("SourceHostname"):
						remoteHost = t.get("SourceHostname")
					else:
						remoteHost = t.get("Computer")
						
					
					
					if t.get("DestinationIp"):
						targetServer = t.get("DestinationIp") 
					else:
						targetServer = t.get("Computer")
						
					
					
					if targetUser in bListedUsers:
						print("[-] Event ID %s with Record ID %s discarded because the TargetUser %s is into the bListedUsers list." % (t.get("EventID"),t.get("EventRecordID"),targetUser))
						t.clear()
					else: #targetUser is not in bListedUsers list then update the values in Neo4j.
						t.update({'targetUser':targetUser})
						t.update({'remoteHost':remoteHost})
						t.update({'targetServer':targetServer})
						
						#Push name for every Event node because Neo4j needs it for naming the node else would be null. In addition, i use "name" in relationships.
						t.update({'name':t.get("EventID")}) 
					
				else:
				
					if t.get("TargetUserName"):
						targetUser = t.get("TargetUserName")
					elif t.get("SubjectUserName"):
						targetUser = t.get("SubjectUserName")
					elif t.get("Detection User"):	
						targetUser = t.get("Detection User")
					elif t.get("Computer"):
						targetUser = t.get("Computer")
					elif (t.get("EventID") not in ["4103","4104"]) and t.get("UserID"):
						sid = t.get("UserID")
						try:
							if (checkdom):
								#After converting sid->username check if user is blacklisted. 
								if sid2name(sid) not in bListedUsers:
									targetUser=sid2name(sid)					
								else:
									targetUser = sid
						except Exception as e:
							print(e)
					
					elif t.get("EventID") in ["4103"]: #Powershell Events don't have target user. ["4103","4104","4105","4106"]
						f = t.get("ContextInfo")
						if (re.findall('User = \w+.*',f)[0].split("= ")[1]):
							regX = re.findall('User = \w+.*',f)[0].split("= ")[1]
							targetUser = regEx(regX)
						try:
							HostApplication = re.findall('Host Application = \w+.*',f)[0].split("= ")[1] #Get Host Application from ContextInfo tag.
						except:
							HostApplication = "-"
						try:
							ScriptName = re.findall('Script Name = \w+.*',f)[0].split("= ")[1] #Get Script Name from ContextInfo tag.
						except:
							ScriptName = "-"
						try:
							CommandPath = re.findall('Command Path = \w+.*',f)[0].split("= ")[1] #Get Command Path from ContextInfo tag.
						except:
							CommandPath = "-"
						try:	
							SequenceNumber = re.findall('Sequence Number = \w+.*',f)[0].split("= ")[1] #Get Sequence Number from ContextInfo tag.
						except:
							SequenceNumber = "-"
						try:	
							Severity = re.findall('Severity = \w+.*',f)[0].split("= ")[1] #Get Sequence Number from ContextInfo tag.
						except:
							Severity = "-"
						t.update({'HostApplication':HostApplication})
						t.update({'ScriptName':ScriptName})
						t.update({'CommandPath':CommandPath})
						t.update({'SequenceNumber':SequenceNumber})
						t.update({'Severity':Severity})
					
					elif t.get("EventID") in ["4104"]:
						sid = t.get("UserID")
						try:
							if (checkdom):
								#After converting sid->username check if user is blacklisted. 
								if sid2name(sid) not in bListedUsers:
									targetUser=sid2name(sid)
							else:
								targetUser = sid
						except Exception as e:
							print(e)
					
					else:
						targetUser = "NULL"
						print("[+] Event ID: "+str(t.get("EventID"))+" with Record ID: "+str(t.get("EventRecordID"))+" does not have targetUser tag!")
					
					
					
					##########################################################################################
					#Extract remote IPs from Event, if IP source field does not exist then extact from the 'TargetServerName', if 'TargetServerName' does not exist then extract from 'Computer' tag.		
					if t.get("IpAddress") and (t.get("IpAddress") in lhostIPs):
						if t.get("Workstation") and (t.get("Workstation") not in lhostIPs):
							remoteHost = t.get("Workstation")
							t.update({'remoteHost':regExIP(remoteHost)})
						elif t.get("Computer") and (t.get("Computer") not in lhostIPs):	
							remoteHost = t.get("Computer")
							t.update({'remoteHost':regExIP(remoteHost)})
						else:
							print("[-] Event ID %s with Record ID %s does not have a remoteHost." % (t.get("EventID"),t.get("EventRecordID")))
						
					elif t.get("IpAddress") : #and (t.get("IpAddress") not in lhostIPs)
						remoteHost = t.get("IpAddress")
						t.update({'remoteHost':regExIP(remoteHost)})
					else:	
						remoteHost = t.get("Computer") #t.get("IpAddress")
						t.update({'remoteHost':regExIP(remoteHost)})

					
					
					
					########################################################################################
					
					
					#Add  'Attaking Hosts' into Neo4j
					targetServer = t.get("Computer")
					t.update({'targetServer':regEx(targetServer)})
						
					#print("[-] Event ID %s with Record ID %s does not have a targetServer." % (t.get("EventID"),t.get("EventRecordID")))
					t.update({'name':t.get("EventID")})
						
					##########################################################################################	
					
					
					###############################MESSAGE TAG###########################################################
					#Get values from the following keys inside from <Message> tag.
					#Error Code, Impersonation Level, Restricted Admin Mode, Virtual Account, Elevated Token
					if t.get("Message"):
						f = t.get("Message")
						if (re.findall('Error Code:',f)):	
							ErrorCode = re.findall('Error Code:\s+[\w+-]*',f)[0].split(":")[1].strip()
							t.update({'ErrorCode':ErrorCode})
							
						if (re.findall('Impersonation Level:',f)):
							ImpersonationLevel = re.findall('Impersonation Level:\s+[\w+-]*',f)[0].split(":")[1].strip()
							t.update({'ImpersonationLevelTranslate':ImpersonationLevel})
							
						if(re.findall('Restricted Admin Mode:',f)):
							RestrictedAdminMode = re.findall('Restricted Admin Mode:\s+[\w+-]*',f)[0].split(":")[1].strip()
							t.update({'RestrictedAdminMode':RestrictedAdminMode})
							
						if (re.findall('Virtual Account:',f)):
							VirtualAccount = re.findall('Virtual Account:\s+[\w+-]*',f)[0].split(":")[1].strip()
							t.update({'VirtualAccount':VirtualAccount})
							
						if (re.findall('Elevated Token:',f)):	
							ElevatedToken = re.findall('Elevated Token:\s+[\w+-]*',f)[0].split(":")[1].strip()
							t.update({'ElevatedToken':ElevatedToken})
					#else:
					#	print("[-] Couldn't find <Message> tag on Event ID %s with EventRecordID %s." % (t.get("EventID"),t.get("EventRecordID")))
						
					
					#####################################################################################################
					if targetUser in bListedUsers:
						print("[-] Event ID %s with Record ID %s discarded because the TargetUser %s is into the bListedUsers list." % (t.get("EventID"),t.get("EventRecordID"),targetUser))
						t.clear()
					else:	
						t.update({'targetUser':regEx(targetUser)})

				counter=counter+1 #How many events added!

				createTagEvent=doc.createElement("Event")
				doc.childNodes[0].appendChild(createTagEvent)
				for tagName in t.keys(): #Example of t.keys(): {"EventID":"4624","Version":"1"}
					if tagName != "Message": #Remove <Message> tag from Exported Windows XML. Too much info :)
						text = str(t.get(tagName))
						tag = str(tagName)
						createTag=doc.createElement(tag.replace(" ","")) #Remove SPACE from the Tag Name. Example: <Product Name>, <ProductName> 
						innerTXT = doc.createTextNode(text.replace("«",""))
						createTag.appendChild(innerTXT)
						createTagEvent.appendChild(createTag)
				
			else:
				print("[-] Event ID "+str(t.get("EventID"))+" is missing.")
				
			
		
	print("[+] Creating XML for neo4j...")
	doc.writexml(file_handle)
	#doc.writexml(sys.stdout)
	file_handle.close()

def neo4jXML(outXMLFile,neo4jUri,neo4jUser,neo4jPass):
	
	neo4jDriver=neo4jConn(neo4jUri,neo4jUser,neo4jPass)
	try:
		#Read the created XML from -o/--out argument.
		neo4jDocXML = minidom.parse(outXMLFile).documentElement
	except Exception as e:
		print(e)
		sys.exit(1)
		
	blackListedEventProperties=["Opcode","Keywords","Version","Level","TransmittedServices","KeyLength","LmPackageName","Key Length","Message","LogonGuid","ThreadID","TargetLogonGuid","SubjectDomainName","Guid","Provider","VirtualAccount","TicketEncryptionType","TicketOptions","Keywords","Level","KeyLength","CertIssuerName","CertSerialNumber","CertThumbprint","Channel","ObjectServer","PreAuth Type","ActivityID","TargetOutboundDomainName","FWLink","Unused","Unused2","Unused3","Unused4","Unused5","Unused6","OriginID","OriginName","ErrorCode","TypeID","TypeName","StatusDescription","AdditionalActionsID","SubStatus","ContextInfo","Product"]
	
	counter=0
	groupEvents=[] #Example [{ EventId: "4624",targetUser:"tasos"},{EventId: "4625", targetUser: "tzonis"}]
 	
	try:
		
		for eventTagNode in neo4jDocXML.childNodes:
			dictionaryEvents=dict() # {EventId: "4624",targetUser:"tasos"},{EventId: "4625", targetUser: "tzonis"}
			if eventTagNode.childNodes:
				#print(eventTagNode.childNodes) [OK]
				for eventTags in eventTagNode.childNodes:	
					#print(eventTags.nodeName)
					if (eventTags.nodeName not in blackListedEventProperties):
						for eventValues in eventTags.childNodes:
							#print(eventTags.nodeName,eventValues.nodeValue)
							dictionaryEvents.update({eventTags.nodeName:eventValues.nodeValue})
				#print("-------------------------")			
				groupEvents.append(dictionaryEvents)
		#print(groupEvents) #[OK]
		
		print("[+] Adding the Events ...")
		with neo4jDriver.session() as session:
			insertEvents = session.run("UNWIND {events} as eventPros CREATE (e:Event) SET e=eventPros MERGE (r:RemoteHosts {name:e.remoteHost}) MERGE (u:TargetUser {remoteHost: e.remoteHost,EventRecordIDs: [  ],name:e.targetUser}) MERGE (t:TargetHost {name:e.targetServer}) ",events=groupEvents) 
		print("[+] Event Correlation ...")
		with neo4jDriver.session() as session:
			test = session.run("MATCH (u:TargetUser),(e:Event),(r:RemoteHosts),(t:TargetHost) WHERE u.name=e.targetUser AND r.name=e.remoteHost AND t.name=e.targetServer AND u.remoteHost = r.name SET u.EventRecordIDs=u.EventRecordIDs+e.EventRecordID")
		print("[+] Creating the Relationships ...")
		with neo4jDriver.session() as session:
			remoteHost2DomUserRelationship=session.run("MATCH (r:RemoteHosts),(u:TargetUser) WHERE u.remoteHost = r.name MERGE (r)-[r1:Source2DomainUser]->(u)")
		with neo4jDriver.session() as session:
			targetUser2EventRelationship = session.run("MATCH (u:TargetUser),(e:Event) WHERE e.targetUser = u.name AND e.EventRecordID IN u.EventRecordIDs MERGE (u)-[r2:TargetUser2Event]->(e)")
		with neo4jDriver.session() as session:
			event2TargetHostRelationship= session.run("MATCH (t:TargetHost),(e:Event) WHERE t.name = e.targetServer MERGE (e)-[r3:Event2Destination]->(t)")
		
	except Exception as e:
		print(e)
	
	#Close the connection with Neo4j
	neo4jDriver.close()
	
	
def eventCounters(neo4jUri,neo4jUser,neo4jPass):
	neo4jDriver=neo4jConn(neo4jUri,neo4jUser,neo4jPass) #Call the function
	#Count Events
	with neo4jDriver.session() as session:
		k=session.run("MATCH (n:Event) RETURN count(n)")
	countEvents = 0
	for x in k:
		print ("[+] Added Events:"+str(x.value()))	
		countEvents = int(x.value())

	#Count RemoteHosts
	with neo4jDriver.session() as session:
		k=session.run("MATCH (n:RemoteHosts) RETURN count(n)")
	countRemHosts = 0
	for x in k:
		print ("[+] Added RemoteHosts:"+str(x.value()))	
		countRemHosts = int(x.value())

	#Count TargetHosts
	with neo4jDriver.session() as session:
		k=session.run("MATCH (n:TargetHost) RETURN count(n)")
	countTargetHosts = 0
	for x in k:
		print ("[+] Added TargetHosts:"+str(x.value()))	
		countTargetHosts = int(x.value())	

	#Count TargetUsers
	with neo4jDriver.session() as session:
		k=session.run("MATCH (n:TargetUser) RETURN count(n)")
	countTargetUsers = 0
	for x in k:
		print ("[+] Added TargetUsers:"+str(x.value()))	
		countTargetUsers = int(x.value())	

		
	#Count Relatioships
	with neo4jDriver.session() as session:
		k=session.run("MATCH p=()-->() RETURN count(p)")
	countRel = 0
	for x in k:
		print ("[+] Added Relationships:"+str(x.value()))	
		countRel = int(x.value())
		
	print ("[+] Total: "+str(countEvents+countRemHosts+countRel+countTargetHosts+countTargetUsers))
	print ('[+] Finished: {:%d-%m-%Y %H:%M:%S}'.format(datetime.datetime.now()))
	
	#Close the connection with Neo4j
	neo4jDriver.close()
	#print(neo4jDriver.closed())

	
if __name__ == '__main__':

	parser = argparse.ArgumentParser(description='Filter Exported XML.')
	parser.add_argument('-e','--eventID', nargs='+', default=["400","800","1102","1006","1015","1040","1042","1116","4103","4104","4105","4624","4625","4634","4648","4662","4672","4673","4688","4697","4698","4702","4713","4723","4724","4735","4737","4739","4755","4765","4766","4768","4769","4776","4780","4794","4798","4964","5136","5140","5145","5156","7045","8004","8007","1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","255"],help='Use comma to seperate eventIDs.')
	parser.add_argument('-x', '--xml',help='Windows Events Exported XML file.')
	parser.add_argument('-o', '--out',help='Save Neo4j XML file.')
	parser.add_argument('-i','--uri',help='neo4j host. Example: bolt://localhost',required=True)
	parser.add_argument('-D','--delete',help='Delete all data from Neo4j.',action='store_true')
	parser.add_argument('-u','--user',help='neo4j username.',required=True)
	parser.add_argument('-p','--passwd',help='neo4j password.',required=True)
	parser.add_argument('-s','--sysmon',help='Sysmon structure.',action='store_true')
	args = parser.parse_args()
	eventIDs=args.eventID
	neo4jUri=args.uri
	neo4jUser=args.user
	neo4jPass=args.passwd
	xmlFile = args.xml
	sysmonFile = args.sysmon
	delData = args.delete
	outXMLFile = args.out
	
	
	if(delData):
		neo4jDriver=neo4jConn(neo4jUri,neo4jUser,neo4jPass)
		print("[+] Connecting with neo4j ...")
		print("[+] Deleting all the data ...")
		with neo4jDriver.session() as session:
			delAll=session.run("MATCH (n) DETACH DELETE n")
		#Close the connection with Neo4j
		neo4jDriver.close()

	else:	
		try: 
			rootDoc = minidom.parse(xmlFile).documentElement #Open exported XML file. 

		except Exception:
			print("[-] Can't find the XML file or XML is not in the right format. Use -x/--xml to provide the Windows Event XML file.")
			sys.exit(1)
			
		#Check if the script is running in a Domain
		#checkdom = isDomain()

		
		#Parse Windows Event XML File - Process 1
		parl=multiprocessing.Lock()
		parl.acquire()
		print("[+] Parsing XML file ...")
		print ('[+] Parsing Started: {:%d-%m-%Y %H:%M:%S}'.format(datetime.datetime.now()))
		evIDs,lhostIPs,bListedUsers,bListedShareFolders,eventList = eventParser(eventIDs,)
		print ('[+] Parsing Finished: {:%d-%m-%Y %H:%M:%S}'.format(datetime.datetime.now()))
		parl.release()
		
		
		#Create neo4j XML - Process 2
		nl = multiprocessing.Lock()
		nl.acquire()
		cnodes = Process(target=createXML, args=(evIDs,lhostIPs,bListedUsers,bListedShareFolders,eventList,sysmonFile,outXMLFile))
		cnodes.start()
		cnodes.join()
		nl.release()
		
		#Read neo4j XML - Process 3
		ml = multiprocessing.Lock()
		ml.acquire()
		mnodes = Process(target=neo4jXML,args=(outXMLFile,neo4jUri,neo4jUser,neo4jPass))
		print("[+] Loading neo4j XML ...")
		mnodes.start()
		mnodes.join()
		ml.release()
		
		#Print Counters - Process 4
		cc=multiprocessing.Lock()
		cc.acquire()
		ccounters=Process(target=eventCounters,args=(neo4jUri,neo4jUser,neo4jPass))
		ccounters.start()
		#p=eventCounters()
		ccounters.join()
		cc.release()