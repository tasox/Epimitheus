#!/usr/bin/python3

from logging import NullHandler
from xml.dom import minidom
from xml.dom.minidom import Document
from neo4j import GraphDatabase, basic_auth
import os,sys,time,re, subprocess
import multiprocessing
from multiprocessing import Process,Lock
import argparse
import collections
import Evtx.Evtx as evtx
import uuid
from pathlib import Path
from xml.etree.cElementTree import Element, ElementTree
from lxml import etree
from io import StringIO, BytesIO
import unicodedata,codecs
import datetime


def get_events(input_file, parse_xml=False):
   # https://chapinb.com/python-forensics-handbook/ch03_event_logs.html#iterate-over-record-xml-data-evtx

    with evtx.Evtx(input_file) as event_log:
        for record in event_log.records():
            if parse_xml:
                evtxXML = record.lxml()
                yield evtxXML
                
            else:
                evtxXML = record.xml()
                yield evtxXML                 
    #return p
                
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


def eventParser(eventIDs,xmlDoc):


    dict={}
    dict2={}
    dict3={}
    counter=0
    t=[]
    rootDoc = xmlDoc

    try:
        for p in rootDoc.childNodes:
            counter=counter+1
            
            for x in p.childNodes:
                for y in x.childNodes:
                    tags=""
                    values=""
                    try:
                        if not y.firstChild:
                            tag=y.nodeName
                            attrs=y.attributes.items()
                            value=y.firstChild
                        else:
                            tag=y.nodeName
                            attrs=y.attributes.items()
                            value=y.firstChild.nodeValue

                        # Clean EventID tag from not useful attributes e.g <EventID Qualifer="0">.
                        # This happened when I used PowerShell events from CCPT.
                        # We need only the <EventID>
                        if tag == "EventID" and attrs == "": 
                            attrs=y.attributes.items()
                        elif tag == "EventID" and attrs != "":    
                            #trim the attributes of EventID tag
                            attrs=[]
                        else:
                            attrs=y.attributes.items()
                        #print(attrs) #[OK]                         
                        
                        dict={'Tags':tag,'Attrs':attrs,'Value':value}
                        #print(dict)
                        if not dict['Attrs'] and dict['Tags'] != 'Data':
                            #print ("[+]%s:%s" %(dict['Tags'],dict['Value'])) #[OK]
                            tags = dict['Tags']
                            values = dict['Value']

                        elif dict['Attrs'] and dict['Tags'] == 'Execution': # Then has 2 properties: ThreadID, ProcessID
                            #print("[+]%s:%s" % (key,value))
                            tags = dict['Tags']
                            dictExecution={}
                            for attrKey,attrValue in dict['Attrs']:
                                attrKey=attrKey
                                attrValue=attrValue
                                dictExecution.update({attrKey:attrValue})
                            
                            values=dictExecution # Set ProcessID and ThreadID in Dict format.

                        elif dict['Attrs'] and dict['Tags'] != 'Data' and dict['Tags'] != 'Execution':
                            #print ("[+]%s:%s" %(dict['Tags'],dict['Value'])) #[OK]
                            for key,value in dict['Attrs']:
                                
                                if key == "SystemTime":
                                    valueDate= datetime.datetime.fromisoformat(value)
                                    valueConvert=valueDate.isoformat()
                                    value=valueConvert
                                
                                #print ("[+]%s:%s" %(key,value)) #[OK]
                                if value:
                                    tags=key
                                    values=value
                                else:
                                    tags="ActivityID"
                            
                        
                        elif dict['Attrs'] and dict['Tags'] == 'Data':
                            #print("[+]%s:%s" % (key,value))
                            tags = dict['Tags']
                            for attrKey,attrValue in dict['Attrs']:
                                attrValue=attrValue
                            value = dict['Value']
                            values = {attrValue:value}
                        
                        # Some events don't have attributes on the tag 'DATA'
                        elif not dict['Attrs'] and dict['Tags'] == 'Data':
                            #print ("[+]%s:%s" %(dict['Tags'],dict['Value'])) #[OK]
                            tags = dict['Tags'] #<Data>
                            attrValue='ContextInfo' # <Data Name="<attrValue>" />
                            value = dict['Value']  # <Data Name="<attrValue>" /> <value> </Data>
                            values = {attrValue:value}

                        #print("[+] %s : %s" % (tags,values))    
                                               
                        #dict2=dict5
                        dict2={tags:values}
                        #print(dict2)
                                                
                        dict3={counter:dict2}
                        #print(dict3)
                        
                        t.append(dict3)
                    except:
                        pass
    except Exception as e:
        print(e)

    # List before EventID filtering
    input_list = {}

    
    #Group events
    for x in range(len(t)):
        for k,v in t[x].items():
            if k not in input_list:
                input_list[k]=[v]
            else:
                input_list[k].append(v)
    #print(input_list)
    # Event filtering procedure.
    input_list2 = {}
    for key,value in input_list.items():
        for val in value:
            if eventIDs and val.get("EventID") in eventIDs.split(","):
                input_list2[key]=value
            elif not eventIDs:
                input_list2 =  input_list  
     
    filterEvents = eventIDs
    localhostIPs=["","-","::1","127.0.0.1","localhost"]
    blacklistedUsers=["DWM-3","UMFD-3","UMFD-2","DWM-2","UMFD-0","UMFD-1","DWM-1"]
    blacklistedShareFolders=["\\\\*\\SYSVOL","\\\\*\\IPC$"]

    return (filterEvents, localhostIPs, blacklistedUsers, blacklistedShareFolders, input_list2)

def createXML(evIDs,lhostIPs,bListedUsers,bListedShareFolders,eventList,outXMLFile):


    targetUserList=[]
    remoteHostsList=[]
    uniqueIPs=[]
    
    # Create a random file and add the parsing data on it. See line
    file_handle = open(outXMLFile,"w")

    doc = Document()
    root = doc.createElement('Events')
    doc.appendChild(root)
    counter=0 # Event counter
    #print(eventList.items()) #[OK]
    print("[+] Searching for TargetUsers/Hosts, SourceUsers/Hosts, RemoteHosts/Users, TargetHosts/Users ...")

    if len(eventList.items()) > 0:
        
        for key, value in eventList.items():
            
            t={} #This dictionary Holds the properties of every event.
            #Unpacking the List -> Dict Event's keys and values            
            for eventValue in value: # Value holds the Event data, Keys and Values in Dict format {'EventID':'4624'}
                #https://stackoverflow.com/questions/54488095/python-3-dictionary-key-to-a-string-and-value-to-another-string
                key, value = list(eventValue.items())[0]
                #print(value)
                # Add ProcessID and ThreadID from the Execution tag.
                if key == "Execution":
                    for k,v in value.items():
                        t.update({k:v})

                
                # Unpack the 'Data' part of Event and update the 'Event' node.
                if key == "Data":
                    t.update(value)
                
                #if <Data> tag exists dictionary of the Event then append the inside
                
                if "Data" in t:
                    t["Data"].append(value)
                
                #If <Data> tag non-exist on the dict then created but in this format
                #e.g. {'Name':'PowerShell','Data':['log1','log2' etc.]}
                
                elif key == "Data":
                    t["Data"]=[]
                    t["Data"].append(value)

                   
                #Otherwise, just update the dictionary
                else:   
                    t.update(eventValue)

            ####################################REMOTE HOSTS######################################################
            #Extract remote IPs from Event, 
            # if IP source field does not exist then extact from the 'TargetServerName', 
            # if 'TargetServerName' does not exist then extract from 'Computer' tag.
            try:
                if t.get("IpAddress") and (t.get("IpAddress") in lhostIPs):
                    if t.get("Workstation") and (t.get("Workstation") not in lhostIPs):
                        remoteHost = t.get("Workstation")
                        t.update({'remoteHost':regExIP(remoteHost.lower())})
                    elif t.get("Computer") and (t.get("Computer") not in lhostIPs):
                        remoteHost = t.get("Computer")
                        t.update({'remoteHost':regExIP(remoteHost.lower())})
                    else:
                        print("[-] Event ID %s with Record ID %s does not have a remoteHost." % (t.get("EventID"),t.get("EventRecordID")))

                elif t.get("IpAddress") : #and (t.get("IpAddress") not in lhostIPs)
                    remoteHost = t.get("IpAddress")
                    t.update({'remoteHost':regExIP(remoteHost.lower())})
                    

                #if Sysmon File is provided, then "SourceIp" is the correct tag.
                elif t.get("SourceIp") and (t.get("SourceIp") not in lhostIPs):
                    remoteHost = t.get("SourceIp")
                    t.update({'remoteHost':regExIP(remoteHost.lower())})
                   

                else:
                    remoteHost = t.get("Computer") #t.get("IpAddress")
                    t.update({'remoteHost':regExIP(remoteHost.lower())})
                                
                if t.get("SourceHostname"):
                    remoteSourceHostname = t.get("SourceHostname")
                    t.update({'remoteHostname':remoteSourceHostname.lower()})
                else:
                    t.update({'remoteHostname':regExIP(remoteHost.lower())})

            except TypeError as te:
                print("[!] Something went wrong to `remoteHost` clause.")
                print(te)
            
            
            #print(remoteHost)
            
            ########################################END - REMOTE HOSTS####################################################
            
            ###############################MESSAGE TAG###########################################################
            #Get values from the following keys inside from <Message> tag.
            #Error Code, Impersonation Level, Restricted Admin Mode, Virtual Account, Elevated Token
            '''if t.get("Message"):
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
                    t.update({'ElevatedToken':ElevatedToken})'''
            #else:
            #	print("[-] Couldn't find <Message> tag on Event ID %s with EventRecordID %s." % (t.get("EventID"),t.get("EventRecordID")))

            ##################################END - MESSAGE TAG###################################################################
            
            if (t.get("EventID") not in ["4100","4103","4104","400","403","500","501","600","800"] and not "powershell" in t.get("Channel")): # Not In Powershell Events
                
                
                try:
                    if t.get("TargetUserName"):
                        targetUser = t.get("TargetUserName")
                    elif t.get("TargetName"):
                        targetUser = t.get("TargetName")
                        if re.findall('=[a-zA-Z0-9@./]+',str(targetUser)):
                            targetUser = re.findall('=[a-zA-Z0-9@./]+',str(targetUser))
                            targetUser = ''.join(targetUser)
                            targetUser = targetUser.split("=")[1].strip()
                        else:
                            targetUser = t.get("TargetName")                        
                    elif t.get("SubjectUserName"):
                        targetUser = t.get("SubjectUserName")
                    # if Sysmon File is provided, then "User" is the correct tag.
                    elif t.get("User"):
                        targetUser = t.get("User")
                    elif t.get("Detection User"):
                        targetUser = t.get("Detection User")
                    # if Sysmon File is provided, then "UserID" is the correct tag.
                    elif t.get("UserID"):
                        targetUser = t.get("UserID")
                    elif t.get("Computer"):
                        targetUser = t.get("Computer")
                except TypeError as te:
                    print(te)
                
                # If everything goes well then Update/Add the targetUser property to the Event.
                if targetUser not in bListedUsers:
                    t.update({'targetUser':targetUser})
                else:
                    print("[-] Event ID %s with Record ID %s discarded because the TargetUser %s is into the bListedUsers list." % (t.get("EventID"),t.get("EventRecordID"),targetUser))
                    

            # PowerShell logging cheatsheet: https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5760096ecf80a129e0b17634/1465911664070/Windows+PowerShell+Logging+Cheat+Sheet+ver+June+2016+v2.pdf
            elif t.get("EventID") in ["4100","4103","4104","400","403","500","501","600","800"]:
                
                if t.get("Data"):
                    eventData = t.get("Data")


                try:

                    #Check if the word "User=" or "UserId=" etc. exists inside the <Data> tag
                    # Before search unpack the Event data which are List format.
                    for eventX in eventData:                              
                        if eventX != None:
                            try:    
                                # Try find usernames on Description part of the Event e.g 4103,4104,800 
                                if eventX.get("ContextInfo"):
                                    if re.findall('Use[rId|rID|r]+.=.[a-zA-Z0-9]+.\w+.',str(eventX.get("ContextInfo"))):
                                        
                                        targetUser = re.findall('Use[rId|rID|r]+.=.\w+.[\w+]+[^\s]\w+.',str(eventX.get("ContextInfo")))
                                        targetUser=targetUser[0]
                                        targetUser = ''.join(targetUser)
                                        targetUser = targetUser.split("=")[1].strip()
                                    
                                        if targetUser in bListedUsers:
                                            print("[-] Event ID %s with Record ID %s discarded because the TargetUser %s is into the bListedUsers list." % (t.get("EventID"),t.get("EventRecordID"),targetUser))
                                                
                                        else:
                                            targetUser=re.findall('[^\s]+',targetUser.lower())
                                            targetUser=targetUser[0]
                                            targetUser=''.join(targetUser)
                                            t.update({'targetUser':targetUser})

                                   
                                    #If ContextInfo exist as well as the UserID. 
                                    elif t.get("UserID"):                                    
                                        targetUser=t.get("UserID")
                                        t.update({'targetUser':targetUser})

                                    else:
                                        #Some PowerShell events doesn't have the UserId property.
                                        #In this case, use a generic user, which is called `PSGenericUser` 
                                        #Check if targeUser key hasn't already set.
                                        targetUser = "PSGenericUser"
                                        t.update({'targetUser':targetUser})    
                                
                                
                                if not eventX.get("ContextInfo") and t.get("UserID") and not t.get("targetUser"):
                                    targetUser=t.get("UserID")
                                    t.update({'targetUser':targetUser})

                                elif not eventX.get("ContextInfo") and t.get("UserID") and not t.get("targetUser"):
                                    targetUser = "PSGenericUser"
                                    t.update({'targetUser':targetUser})
                            
                            except Exception as error:
                                print("[-] TargetUser RegEx error! %s" % error)
                                
                            

                            try:
                            
                                if eventX.get("ContextInfo"):
                                    if re.findall('HostApplication.*=.[\a-zA-Z0-9]+Engine',eventX.get("ContextInfo")):    
                                        HostApplication = re.findall('HostApplication.*=.[\a-zA-Z0-9]+Engine',str(eventX.get("ContextInfo")))
                                    else:
                                        HostApplication = re.findall('Host Application.*=.[\a-zA-Z0-9]+Engine',str(eventX.get("ContextInfo")))
                                    
                                    if HostApplication:
                                        HostApplication = ' '.join(HostApplication)
                                        HostApplication = HostApplication.replace("Engine","").strip()
                                        HostApplication = HostApplication.split("=")[1].strip()
                                        t.update({'HostApplication':HostApplication})
                            
                            except Exception as error:    
                                print("[-] HostApplication RegEx error! %s" % error)

                            try:
                                if eventX.get("ContextInfo"):
                                    if re.findall('ScriptName.*=.[\a-zA-Z0-9]+Command',eventX.get("ContextInfo")):
                                        ScriptName = re.findall('ScriptName.*=.[\a-zA-Z0-9]+Command',str(eventX.get("ContextInfo")))
                                    else:
                                        ScriptName = re.findall('Script Name.*=.[\a-zA-Z0-9]+Command',str(eventX.get("ContextInfo")))    
                                    
                                    if ScriptName:
                                        ScriptName = ' '.join(ScriptName)
                                        ScriptName = ScriptName.replace("Command","").strip()
                                        ScriptName = ScriptName.split("=")[1].strip()
                                        t.update({'ScriptName':ScriptName})
                                    #print(ScriptName)
                                    
                            except Exception as error:     
                                print("[-] ScriptName RegEx error! %s" % error)

                            try:
                                if eventX.get("ContextInfo"):
                                    if re.findall('CommandLine.*=.[\a-zA-Z0-9]+',eventX.get("ContextInfo")):
                                        CommandLine = re.findall('CommandLine.*=.[\a-zA-Z0-9]+',str(eventX.get("ContextInfo")))
                                        CommandLine = ' '.join(CommandLine)
                                        CommandLine = CommandLine.split("=")[1]
                                        t.update({'CommandLine':CommandLine})
                                        #print(CommandLine)
                            except Exception as error:
                                print("[-] commandLine RegEx error! %s" % error)

                            try:    
                                if eventX.get("ContextInfo"):
                                    if re.findall('CommandPath.*=.[\a-zA-Z0-9]+Sequence',eventX.get("ContextInfo")):
                                        CommandPath = re.findall('CommandPath.*=.[\a-zA-Z0-9]+Sequence',str(eventX.get("ContextInfo")))
                                    else:
                                        CommandPath = re.findall('Command Path.*=.[\a-zA-Z0-9]+Sequence',str(eventX.get("ContextInfo")))
                                    
                                    if CommandPath:
                                        CommandPath = ' '.join(CommandPath)
                                        CommandPath = CommandPath.replace("Sequence","").strip()
                                        CommandPath = CommandPath.split("=")[1]
                                        t.update({'CommandPath':CommandPath})
                                    
                            except Exception as error:
                                print("[-] CommandPath RegEx error! %s" % error)

                            try:
                                if eventX:
                                    contextInfo = re.findall('Severity.*=',str(eventX.get('ContextInfo')))
                                    if contextInfo != None:
                                        contextInfoSeverity = re.findall('Severity.*=.[a-zA-Z]+',str(contextInfo))
                                        if contextInfoSeverity and contextInfoSeverity != None:
                                            Severity = re.findall('Severity.*=.[a-zA-Z]+',str(contextInfo))
                                            Severity = ' '.join(Severity)
                                            Severity = Severity.split("=")[1].split(" ")[0]
                                            t.update({'Severity':Severity})
                                    else:
                                        contextInfoSeverity=""    
                                    
                                
                            
                            except Exception as error:
                                print("[-] Severity RegEx error! %s" % error)
                                

                    # print(t.get('EventRecordID')+"-->"+t.get('targetUser')) [OK]
                
                except Exception as error:
                    print("[-] Something went wrong while parsing the PowerShell Events!")
                    print("[+] Event ID: "+str(t.get("EventID"))+" with Record ID: "+str(t.get("EventRecordID")))
                    print(error)

                #print(t)
                                
                
            else:
                targetUser = "NULL"
                print("[+] Event ID: "+str(t.get("EventID"))+" with Record ID: "+str(t.get("EventRecordID"))+" does not have targetUser tag!")


            ########################################################################################
            #Add  'Attaking Hosts' into Neo4j
            # if Sysmon File is provided, then "DestinationIp" is the correct tag.
            if t.get("DestinationIp"):
                targetServer = t.get("DestinationIp")
                t.update({'targetServer':targetServer.lower()})
            elif t.get("Computer"):
                targetServer = t.get("Computer")
                t.update({'targetServer':targetServer.lower()})
            else:
                print("[-] Something went wrong during the 'DestinationHost' parsing! ")
            #print("[-] Event ID %s with Record ID %s does not have a targetServer." % (t.get("EventID"),t.get("EventRecordID")))
            t.update({'name':t.get("EventID")})
            ##########################################################################################

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

            #else:
            #	print("[-] Event ID "+str(t.get("EventID"))+" is missing.")



    print("[+] Creating XML for neo4j...")
    doc.writexml(file_handle)
    #doc.writexml(sys.stdout)
    file_handle.close()

#def neo4jXML(outXMLFile,neo4jUri,neo4jUser,neo4jPass):
def neo4jXML(outXMLFile,neo4jUri,neo4jUser,neo4jPass):
    
    neo4jDriver=neo4jConn(neo4jUri,neo4jUser,neo4jPass)
    try:
        #Read the created XML file with the UUID name. e.g. d1ba1cf8-0a30-42d1-ae6b-451289ca6c0d.xml
        neo4jDocXML = minidom.parse(outXMLFile).documentElement
    except Exception as e:
        print(e)
        sys.exit(1)

    blackListedEventProperties=[
        "Opcode",
        "Keywords",
        "Version",
        "Level",
        "TransmittedServices",
        "KeyLength",
        "LmPackageName",
        "Key Length",
        "Message",
        "SubjectDomainName",
        "TicketEncryptionType",
        "TicketOptions",
        "Keywords",
        "Level",
        "KeyLength",
        "CertIssuerName",
        "CertSerialNumber",
        "CertThumbprint",
        "ObjectServer",
        "PreAuth Type",
        "TargetOutboundDomainName",
        "FWLink",
        "Unused",
        "Unused2",
        "Unused3",
        "Unused4",
        "Unused5",
        "Unused6",
        "OriginID",
        "OriginName",
        "ErrorCode",
        "TypeID",
        "TypeName",
        "StatusDescription",
        "AdditionalActionsID",
        "SubStatus",
        "Product"
        ]

    counter=0
    groupEvents=[] #Example [{ EventId: "4624",targetUser:"tasos"},{EventId: "4625", targetUser: "tzonis"}]

    try:

        for eventTagNode in neo4jDocXML.childNodes:
            dictionaryEvents=dict() # {EventId: "4624",targetUser:"tasos"},{EventId: "4625", targetUser: "tzonis"}
            if eventTagNode.childNodes:
                #print(eventTagNode.childNodes) #[OK]
                for eventTags in eventTagNode.childNodes:
                    if (eventTags.nodeName not in blackListedEventProperties):
                        for eventValues in eventTags.childNodes:
                            #print(eventTags.nodeName,eventValues.nodeValue)
                            dictionaryEvents.update({eventTags.nodeName:eventValues.nodeValue})
                #print("-------------------------")
                groupEvents.append(dictionaryEvents)
        
        #print(groupEvents) #[OK]
        
        print("[+] Adding the Events ...")
        with neo4jDriver.session() as session:
            print("\n")
            print("=========Time Frame=========")
            total_time = 0
            start = time.time()
            # Create Neo4j Nodes
            insertEvents = session.run(
                "UNWIND $events as eventPros "
               
                "CREATE (e:Event) "
                "SET e=eventPros "
                "SET (CASE WHEN EXISTS(e.SubjectUserName) AND NOT EXISTS(e.TargetUserName) THEN e END).hasSubjectUser='false' "
                "SET (CASE WHEN EXISTS(e.SubjectUserName) AND EXISTS(e.TargetUserName) THEN e END).hasSubjectUser='true' "
                "SET (CASE WHEN EXISTS(e.SubjectUserName) AND EXISTS(e.TargetName) THEN e END).hasSubjectUser='true' "
                "SET (CASE WHEN NOT EXISTS(e.SubjectUserName) AND EXISTS(e.TargetUserName) THEN e END).hasSubjectUser='false' "
                #Example: PowerShell Events.
                "SET (CASE WHEN NOT EXISTS(e.SubjectUserName) AND NOT EXISTS(e.TargetUserName) THEN e END).hasSubjectUser='false' "
                "WITH e WHERE e.targetUser IS NOT NULL " #Avoid erros when targetUser is blacklisted and it's name will be NULL.
                
                #"MERGE (e:Event {EventRecordIDs:eventPros.EventRecordID}) SET e=eventPros " #Avoid dublicate Events with MERGE and filtering.
                "MERGE (r:RemoteHosts {name:e.remoteHost,remoteHostname:e.remoteHostname}) "
                
                "MERGE (u:TargetUser {name:e.targetUser,remoteHost:e.remoteHost,targetServer:e.targetServer,hasSubjectUser:e.hasSubjectUser,EventRecordIDs: [ ]}) "
                "SET u.EventRecordIDs=u.EventRecordIDs+e.EventRecordID " #Append the EventRecordIDs
                "SET u.SubjectUsernames=[ ] "
                "SET u.bindSubjectUserSids=[ ] "
                
                "MERGE (t:TargetHost {name:e.targetServer}) ",events=groupEvents)
            total_time += time.time() - start
            print("[1] Neo4j insertEvents query: %f " %(total_time))             

###########################################Subject Users ###############################################################

        with neo4jDriver.session() as session:
            total_time = 0
            start = time.time()
            # Create 'SubjectUser' Node - Initialization
            createSubjectUsers=session.run(

                "MATCH (e:Event) "
                #"WHERE EXISTS(e.SubjectUserName) AND EXISTS(e.TargetUserName) "
                "WHERE e.hasSubjectUser='true' "
                "WITH collect(e.SubjectUserName) as SubjectUserNames,e "
                "UNWIND SubjectUserNames as SubjectUserName "
                "FOREACH(p in SubjectUserName | MERGE (s:SubjectUser {name:p,SubjectUserRealName:p,TargetUsernames: [ ],EventRecordIDs: [ ],bindTargetUserSids: [ ],IsSubjectUser:'true',remoteHost:e.remoteHost,targetServer:e.targetServer,hasTargetUsernameTag:'true',hasSubjectUsernameTag:'true'}) "
                "SET s.IsCreated='true' "
                "SET s.IsSubjectUser='true' "
                "SET s.CreatedByEventRecordID=e.EventRecordID) "
            
            )

            total_time += time.time() - start
            print("[2] Neo4j createSubjectUsersNode query: %f " %(total_time)) 

        
        with neo4jDriver.session() as session:    
            total_time = 0
            start = time.time()
            # Update 'SubjectUser' node.
            UpdateSubjectUsers = session.run(
                "MATCH (e:Event),(u:TargetUser),(s:SubjectUser) "
                "WHERE s.name=e.SubjectUserName "
                "AND u.name=e.targetUser "
                "AND u.remoteHost=e.remoteHost "
                "AND u.targetServer=e.targetServer "
                "AND s.remoteHost=u.remoteHost "
                "AND s.targetServer=u.targetServer "
                "AND s.remoteHost=e.remoteHost "
                "AND s.targetServer=e.targetServer "
                "AND EXISTS(e.SubjectUserName) AND e.SubjectUserName IS NOT NULL "
                "AND ((EXISTS(e.TargetUserName) AND e.TargetUserName IS NOT NULL) OR (EXISTS(e.TargetName) AND e.TargetName IS NOT NULL)) "
                "SET s.EventRecordIDs=[e.EventRecordID] " #Adding the first matched EventRecordID. On the FOREACH part is adding the rest.
                "WITH collect(e.SubjectUserName) as subjectUsernames, e "
                "UNWIND subjectUsernames AS subjectUsername "
                "FOREACH(p IN subjectUsername | MERGE (b:SubjectUser {name:p,remoteHost:e.remoteHost,targetServer:e.targetServer}) "
                "SET b.IsSubjectUser='true' "
                "SET (CASE WHEN NOT e.EventRecordID IN b.EventRecordIDs THEN b END).EventRecordIDs=b.EventRecordIDs+e.EventRecordID "
                "SET (CASE WHEN NOT e.targetUser IN b.TargetUsernames THEN b END).TargetUsernames=b.TargetUsernames+e.targetUser "
                "SET (CASE WHEN NOT e.TargetUserSid IN b.bindTargetUserSids THEN b END).bindTargetUserSids=b.bindTargetUserSids+e.TargetUserSid "
                "SET b.SubjectUserRealName=e.SubjectUserName)"
            )

            deleteDublicateSubjectUsers= session.run(
                
                "MATCH (s:SubjectUser) "
                "WITH collect(s) as nodes,s.EventRecordIDs as evIDs,s.remoteHost as remoteHost,s.targetServer as targetServer,s.TargetUsernames as targetUserNames "
                "WHERE s.EventRecordIDs=evIDs "
                "AND s.remoteHost=remoteHost "
                "AND s.targetServer=targetServer "
                "AND s.TargetUsernames=targetUserNames "
                "AND size(nodes)>1 "
                "UNWIND nodes[1..] as node "
                "DETACH DELETE node"

            )    
            total_time += time.time() - start
            print("[3] Neo4j updateSubjectUserNode query: %f " %(total_time))

        

############################### Target Users ########################################## 
        with neo4jDriver.session() as session:               
            total_time = 0
            start = time.time()
            updateTargetUserNode = session.run(
                
                "MATCH (s:SubjectUser),(t:TargetUser) "
                "WHERE t.hasSubjectUser='true' "
                "WITH s.EventRecordIDs as subjectUserEventRecordIDs,t.EventRecordIDs as targetUserEventRecordIDs,t,s "
                "UNWIND subjectUserEventRecordIDs AS subjectUserEventRecordID "
                "FOREACH(p IN subjectUserEventRecordID | "
                "SET (CASE WHEN subjectUserEventRecordID IN targetUserEventRecordIDs THEN t END).SubjectUsernames=s.name)"
            )
            total_time += time.time() - start
            print("[4] Neo4j updateTargetUserNode query %f: " %(total_time))


###################################################Relationships######################################################
  
        with neo4jDriver.session() as session:
            total_time = 0
            start = time.time()
            # Check if Event node has the 'SubjectUserName'. If yes, then the relationship is:
            # IsSubjectTarget = Means that Event contains 'SubjectUserName'  property but has the same value with 'targetUsername'
            # RemoteHost -> User -> TargetUser -> EventID -> targetServer
        #    allInOnerelationship = session.run("MATCH (u:TargetUser),(u2:TargetUser),(e:Event),(r:RemoteHosts),(t:TargetHost) WHERE u.name IN u2.subjectUsernames AND e.EventRecordID IN u.EventRecordIDs AND e.EventRecordID IN u2.EventRecordIDs AND u.name = e.SubjectUserName AND u.remoteHost = r.name AND u.IsSubjectUser = 'true' AND u.IsTargetUser IS NULL AND t.name = u2.targetServer MERGE (r)-[r1:RemoteHostTOSubjectUsername]-(u)-[r2:SubjectUsernameTOTargetuser]-(u2)-[r3:TargetUserTOEventID]-(e)-[r4:EventIDTOtargetHost]->(t)") # WITH collect(r1)[1..] as rels, collect(r2)[1..] as rels2 FOREACH (r1 in rels | DELETE r1) FOREACH (r2 in rels2 | DELETE r2) 
            SubjectUserTargetUserRelationship1 = session.run(

                "MATCH (r:RemoteHosts),(t:TargetUser),(s:SubjectUser),(th:TargetHost),(e:Event) "
                "WHERE t.hasSubjectUser='true' "
                "AND e.remoteHost=r.name "
                "AND s.remoteHost=r.name "
                "AND t.remoteHost=s.remoteHost "
                "AND s.name IN t.SubjectUsernames "
                "AND t.targetServer=s.targetServer "
                "AND e.hasSubjectUser='true' "
                "AND e.EventRecordID IN s.EventRecordIDs "
                "MERGE (r)-[r1:RemoteHostTOSubjectUsername]-(s)-[r2:SubjectUsernameTOTargetuser]->(t)"
            
            )
            total_time += time.time() - start
            print("[5] Neo4j SubjectUserTargetUserRelationship1 query: %f " %(total_time))
        
        with neo4jDriver.session() as session:
            total_time = 0
            start = time.time()
            SubjectUserTargetUserRelationship2 = session.run(

                "MATCH (t:TargetUser),(e:Event),(th:TargetHost) "
                "WHERE t.hasSubjectUser='true' "
                "AND t.targetServer=e.targetServer "
                "AND t.remoteHost=e.remoteHost "
                "AND e.EventRecordID IN t.EventRecordIDs "
                "AND e.targetServer=th.name "
                "AND e.hasSubjectUser='true' "
                "MERGE (t)-[r3:TargetUserTOEvent]-(e)-[r4:EventIDTOtargetHost]->(th)"

            )
            total_time += time.time() - start
            print("[6] Neo4j SubjectUserTargetUserRelationship2 query: %f " %(total_time))

        with neo4jDriver.session() as session:   
            total_time = 0
            start = time.time()
            #allInOnerelationship = session.run("MATCH (t:TargetUser),(th:TargetHost),(e:Event) WHERE e.targetUser=t.TargetRealName AND t.targetServer=th.name AND e.targetServer=th.name MERGE (t)-[m1:test1]-(e)-[m2:test2]->(th)")
            #deleteDublicates_AllInOnerelationship = session.run("MATCH (r:RemoteHosts)-[r1]-(t:SubjectUser)-[r2]->(s:TargetUser) with r,t,s,type(r1) as typ, tail(collect(r1)) as coll foreach(x in coll | delete x)")
            # Create relationships only for Users that NOT contains 'SubjectUserName'
            remoteHost2DomUserRelationship=session.run(
                
                "MATCH (r:RemoteHosts),(u:TargetUser),(e:Event) "
                "WHERE u.remoteHost = r.name "
                "AND e.hasSubjectUser='false' "
                "AND u.hasSubjectUser='false' "
                "AND e.EventRecordID IN u.EventRecordIDs "
                "MERGE (r)-[r5:Source2TargetUser]->(u)"
            )
            total_time += time.time() - start
            print("[7] Neo4j remoteHost2DomUserRelationship query: %f " %(total_time))

        with neo4jDriver.session() as session:
            total_time = 0
            start = time.time()    
            targetUser2EventRelationship = session.run(
                
                "MATCH (u:TargetUser),(e:Event),(t:TargetHost) "
                "WHERE e.targetUser=u.name "
                "AND t.name=e.targetServer "
                "AND u.targetServer=t.name "
                "AND e.EventRecordID IN u.EventRecordIDs "
                "AND u.hasSubjectUser='false' "
                "MERGE (u)-[r7:TargetUser2Event]-(e)-[r8:Event2TargetHost]->(t)"
            )

            total_time += time.time() - start
            print("[8] Neo4j targetUser2EventRelationship query: %f " %(total_time))

############################################END###########################################################################
            
            
    except Exception as e:
        print(e)

    #Close the connection with Neo4j
    print("[+] All queries pushed to Neo4j successfully")
    neo4jDriver.close()
    print("[+] Connection with Neo4j is closed.")


def eventCounters(neo4jUri,neo4jUser,neo4jPass):
    neo4jDriver=neo4jConn(neo4jUri,neo4jUser,neo4jPass) #Call the function
    #Count Events
    #with neo4jDriver.session() as session:
    k=neo4jDriver.session().run("MATCH (n:Event) RETURN count(n)")
    countEvents = 0
    for x in k:
        print("[+] Added Events:"+str(x.value()))
        countEvents = int(x.value())
    #Count RemoteHosts
    #with neo4jDriver.session() as session:
    k=neo4jDriver.session().run("MATCH (n:RemoteHosts) RETURN count(n)")
    countRemHosts = 0
    for x in k:
        print ("[+] Added RemoteHosts:"+str(x.value()))
        countRemHosts = int(x.value())

    #Count TargetHosts
    #with neo4jDriver.session() as session:
    k=neo4jDriver.session().run("MATCH (n:TargetHost) RETURN count(n)")
    countTargetHosts = 0
    for x in k:
        print ("[+] Added TargetHosts:"+str(x.value()))
        countTargetHosts = int(x.value())

    #Count TargetUsers
    #with neo4jDriver.session() as session:
    k=neo4jDriver.session().run("MATCH (n:TargetUser) RETURN count(n)")
    countTargetUsers = 0
    for x in k:
        print ("[+] Added TargetUsers:"+str(x.value()))
        countTargetUsers = int(x.value())
    
    #Count SubjectUsers
    #with neo4jDriver.session() as session:
    k=neo4jDriver.session().run("MATCH (n:SubjectUser) RETURN count(n)")
    countTargetUsers = 0
    for x in k:
        print ("[+] Added SubjectUsers:"+str(x.value()))
        countSubjectUsers = int(x.value())

    #Count Relatioships
    #with neo4jDriver.session() as session:
    k=neo4jDriver.session().run("MATCH p=()-->() RETURN count(p)")
    countRel = 0
    for x in k:
        print ("[+] Added Relationships:"+str(x.value()))
        countRel = int(x.value())

    print ("[+] Total: "+str(countEvents+countRemHosts+countRel+countTargetHosts+countTargetUsers+countSubjectUsers))
    print ('[+] Finished: {:%d-%m-%Y %H:%M:%S}'.format(datetime.datetime.now()))

    #Close the connection with Neo4j
    neo4jDriver.close()


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Filter the Windows Events file.')
    parser.add_argument('-e','--eventID',help="EventID filtering",nargs='?',type=str, default=[])
    parser.add_argument('-ev', '--events',help='Windows Events in XML OR EVTX format.')
    parser.add_argument('-i','--uri',help='neo4j host. Example: bolt://localhost',required=True)
    parser.add_argument('-D','--delete',help='Delete all data from Neo4j.',action='store_true')
    parser.add_argument('-u','--user',help='neo4j username.',required=True)
    parser.add_argument('-p','--passwd',help='neo4j password.',required=True)
    args = parser.parse_args()
    eventIDs=args.eventID
    neo4jUri=args.uri
    neo4jUser=args.user
    neo4jPass=args.passwd
    eventsFile = args.events
    delData = args.delete
    
    outXMLFileArray=[]
    

    def parsingFunction(fileName,xmlDoc,outXMLfile):
        
        #Parse Windows Event XML File - Process 1
        parl=multiprocessing.Lock()
        parl.acquire()
        print("[+] Parsing file %s " % fileName)
        print ('[+] Parsing Started: {:%d-%m-%Y %H:%M:%S}'.format(datetime.datetime.now()))
        evIDs,lhostIPs,bListedUsers,bListedShareFolders,eventList = eventParser(eventIDs,xmlDoc)
        print ('[+] Parsing Finished: {:%d-%m-%Y %H:%M:%S}'.format(datetime.datetime.now()))
        parl.release()

        #Create neo4j XML - Process 2
        nl = multiprocessing.Lock()
        nl.acquire()
        cnodes = Process(target=createXML, args=(evIDs,lhostIPs,bListedUsers,bListedShareFolders,eventList,outXMLfile))
        cnodes.start()
        cnodes.join()
        nl.release()

        #Read neo4j XML - Process 3
        ml = multiprocessing.Lock()
        ml.acquire()
        mnodes = Process(target=neo4jXML,args=(str(outXMLfile),neo4jUri,neo4jUser,neo4jPass))
        print("[+] Loading neo4j XML ...")
        mnodes.start()
        mnodes.join()
        ml.release()
    
    def generateOutXMLFileRandomName(providedPathFile):
        
        #Output directory of parsing file. It will be on same path with the running Python script.
        #Get the directory of the files that are listing under provided path.
        #cwd = os.path.dirname(providedPathFile)
        
        if os.path.isfile(providedPathFile) and providedPathFile.endswith((".xml",".evtx")):
            # Directory of the file
            cwd = os.path.dirname(providedPathFile)
            #Create an XML file with random number
            randomName = str(uuid.uuid4()) + ".xml"
            #Generates a random number that will be used on later steps.
            outXMLFile = cwd + "\\" + randomName
        else:
            #Is Directory
            cwd = Path(providedPathFile)
            #Create an XML file with random number
            randomName = str(uuid.uuid4()) + ".xml"
            #Generates a random number that will be used on later steps.
            outXMLFile = cwd / randomName

        return outXMLFile


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
            
            # Check first if the user provided PATH or FILE and if it is exist.
            
            if os.path.isdir(eventsFile):               
                
                #Enumerate the files under the specified directory.
                eventsFolder = Path(eventsFile)
                
                dirFiles = os.listdir(eventsFolder)

                for file in dirFiles:
                    
                    fileFullPath = eventsFolder / file
                    if os.path.isfile(fileFullPath) and file.endswith('.evtx'):
                        
                        #Get the file which all the events will be imported befored moved to neo4j.
                        # It just an empty file which will be filled in with Events
                        #print(fileFullPath) #OK
                        outXMLFile = generateOutXMLFileRandomName(eventsFolder)
                        
                        # Read the contents of the EVTX file.
                        evtxDoc = get_events(fileFullPath)

                        # Create an XML file with the same name as EVTX
                        #evtx2xml = str(file).replace(".evtx", ".xml")
                        evtx2xml = str(fileFullPath).replace(".evtx", ".xml")
                        print ('[+] Started: {:%d-%m-%Y %H:%M:%S}'.format(datetime.datetime.now()))
                        print("[+] I'm fixing the fualty chars, I need sometime for that ...")
                        print("\n")
                        f = open(evtx2xml, "w")
                        f.write("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>")
                        f.write("\n")
                        f.write("<Events>")
                        for x in evtxDoc:
                            #discard the unicode chars
                            if re.findall('&#\d+;',str(x)): 
                                f.write(re.sub(r'&#\d+;',r'',x))
                            else:
                                f.write(x) 
                        f.write("</Events>")    
                        f.close()
                        rootDoc = minidom.parse(evtx2xml).documentElement
                        print("\n")

                        rootDoc = minidom.parse(evtx2xml).documentElement
                        parsingFunction(evtx2xml,rootDoc,outXMLFile)
                        print("\n")

                        # Remove temp files
                        os.remove(outXMLFile)
                        os.remove(evtx2xml)
                        #os.remove(file)

                    if os.path.isfile(fileFullPath) and file.endswith('.xml') and not file.endswith('_fixed.xml'):
                        #Get the file which all the events will be imported befored moved to neo4j.
                        # It just an empty file which will be filled in with Events
                        #print(fileFullPath) #OK
                        outXMLFile = generateOutXMLFileRandomName(eventsFolder)                     
                        
                        #Open exported XML and remove those chars - Step 1
                        openXMLread=open(fileFullPath,"r",encoding="utf-8")
                        fixChars=re.sub(r"ï»¿", r"", openXMLread.read()) #When Events exported from Windows Event Viewer has those bad chars inside the XML.
                        fixChars=re.sub(r'&#\d+;',r'',fixChars) # Clean the Unicode chars.
                        # https://stackoverflow.com/questions/51710082/what-does-unicodedata-normalize-do-in-python
                        # https://godatadriven.com/blog/handling-encoding-issues-with-unicode-normalisation-in-python/
                        fixChars=unicodedata.normalize("NFKD", fixChars).encode('WINDOWS-1252', 'ignore').decode('utf-8')
                        openXMLread.close()

                        #Write again the XML without those chars -Step 2
                        file=str(fileFullPath).replace(".xml","_fixed.xml")
                        openXMLwrite=open(file,"w")
                        openXMLwrite.write(fixChars)
                        openXMLwrite.close()

                        rootDoc = minidom.parse(file).documentElement #Open exported XML file.
                        
                        parsingFunction(file,rootDoc,outXMLFile)
                        print("\n")

                        # Remove temp files
                        os.remove(outXMLFile)
                        os.remove(file)
                    
            # User provided a file and not a directory.
            else:
                # Get the file name from -ev flag
                file = eventsFile
                # Get directory of the EVTX file.
                #cwd = os.path.dirname(file)
                if file.endswith('.evtx'):
                    
                    #Get the file which all the events will be imported befored moved to neo4j
                    outXMLFile = generateOutXMLFileRandomName(file)
                    # Read the contents of the EVTX file.
                    evtxDoc = get_events(file)
                    
                    # Create an XML file with the same name as EVTX
                    evtx2xml = str(file).replace(".evtx", ".xml")
                    print ('[+] Started: {:%d-%m-%Y %H:%M:%S}'.format(datetime.datetime.now()))
                    print("[+] I'm fixing the fualty chars, I need sometime for that ...")
                    print("\n")
                    f = open(evtx2xml, "w")
                    f.write("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>")
                    f.write("\n")
                    f.write("<Events>")
                    for x in evtxDoc:
                        #discard the unicode chars
                        if re.findall('&#\d+;',str(x)): 
                            f.write(re.sub(r'&#\d+;',r'',x))
                        else:
                            f.write(x) 
                    f.write("</Events>")    
                    f.close()
                    
                    rootDoc = minidom.parse(evtx2xml).documentElement
                    parsingFunction(evtx2xml,rootDoc,outXMLFile)
                    print("\n")

                    # Remove temp files
                    os.remove(outXMLFile)
                    os.remove(evtx2xml)
                    #os.remove(file) 
                
                elif file.endswith('.xml'):
                    
                    # Get the file which all the events will be imported befored moved to neo4j.
                    # It just an empty file which will be filled in with Events
                    outXMLFile = generateOutXMLFileRandomName(file)
                    #outXMLFileArray.append(outXMLFile)
                    
                    #Open exported XML and remove those chars
                    openXMLread=open(file,"r",encoding="utf-8")
                    fixChars=re.sub(r"ï»¿", r"", openXMLread.read()) #When Events exported from Windows Event Viewer has those bad chars inside the XML.
                    fixChars=re.sub(r'&#\d+;',r'',fixChars)
                    # https://stackoverflow.com/questions/51710082/what-does-unicodedata-normalize-do-in-python
                    # https://godatadriven.com/blog/handling-encoding-issues-with-unicode-normalisation-in-python/
                    fixChars=unicodedata.normalize("NFKD", fixChars).encode('WINDOWS-1252', 'ignore').decode('UTF-8')
                    openXMLread.close()
                    
                    #Write again the XML without those chars
                    file=file.replace(".xml","_fixed.xml")
                    openXMLwrite=open(file,"w")
                    openXMLwrite.write(fixChars)
                    openXMLwrite.close()
                    rootDoc = minidom.parse(file).documentElement #Open exported XML file.
                    parsingFunction(file,rootDoc,outXMLFile)
                    print("\n")

                    # Remove temp files
                    os.remove(outXMLFile)
                    os.remove(file)
                
                else:
                    print("[!] Provide an XML or EVTX file! ")
                    
        except Exception as e:
            print(e)
            #print("[-] Can't find the XML file or XML is not in the right format. Use -x/--xml to provide the Windows Event XML file.")
            sys.exit(1)

    
    #Print Counters - Process 4
    print("\n")
    print("========= Database Information ==========")
    cc=multiprocessing.Lock()
    cc.acquire()
    ccounters=Process(target=eventCounters,args=(neo4jUri,neo4jUser,neo4jPass))
    ccounters.start()
    #p=eventCounters()
    ccounters.join()
    cc.release()


