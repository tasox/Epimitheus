#!/usr/bin/python3

from xml.dom import minidom
from xml.dom.minidom import Document
from neo4j import GraphDatabase, basic_auth
import os,sys,datetime,time,re, subprocess
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
                #print(x)
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
                        ###############################################################################
                        
                        dict={'Tags':tag,'Attrs':attrs,'Value':value}
                        if not dict['Attrs']:
                            #print ("[+]%s:%s" %(dict['Tags'],dict['Value'])) #[OK]
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
                        #print ("[+]%s:%s" % (key,value))
                        
                        #if key not in ['Message']:
                        dict2={key:value}
                        dict3={counter:dict2}
                        t.append(dict3)
                    except:
                        pass
    except Exception as e:
        print(e)

    #print(t)
    input_list = {}

    #Group events
    for x in range(len(t)):
        for k,v in t[x].items():
            if k not in input_list:
                input_list[k]=[v]
            else:
                input_list[k].append(v)


    filterEvents = eventIDs
    localhostIPs=["","-","::1","127.0.0.1","localhost"]
    blacklistedUsers=["DWM-3","UMFD-3","UMFD-2","DWM-2","UMFD-0","UMFD-1","DWM-1"]
    blacklistedShareFolders=["\\\\*\\SYSVOL","\\\\*\\IPC$"]

    #How many data will process
    dataProcess = str(len(input_list.keys()))
    return (filterEvents, localhostIPs, blacklistedUsers, blacklistedShareFolders, input_list)

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
    print("[+] Searching for TargetUsers, RemoteHosts, TargetHosts ...")

    if len(eventList.items()) > 0:
        
       
        for key, value in eventList.items():
            
            t={} #This dictionary Holds the properties of every event.
            
            #Unpacking the List -> Dict Event's keys and values            
            for eventValue in value: # Value holds the Event data, Keys and Values in Dict format {'EventID':'4624'}
                #https://stackoverflow.com/questions/54488095/python-3-dictionary-key-to-a-string-and-value-to-another-string
                key, value = list(eventValue.items())[0]
                
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
                        t.update({'remoteHost':regExIP(remoteHost)})
                    elif t.get("Computer") and (t.get("Computer") not in lhostIPs):
                        remoteHost = t.get("Computer")
                        t.update({'remoteHost':regExIP(remoteHost)})
                    else:
                        print("[-] Event ID %s with Record ID %s does not have a remoteHost." % (t.get("EventID"),t.get("EventRecordID")))

                elif t.get("IpAddress") : #and (t.get("IpAddress") not in lhostIPs)
                    remoteHost = t.get("IpAddress")
                    t.update({'remoteHost':regExIP(remoteHost)})
                    

                #if Sysmon File is provided, then "SourceIp" is the correct tag.
                elif t.get("SourceIp") and (t.get("SourceIp") not in lhostIPs):
                    remoteHost = t.get("SourceIp")
                    t.update({'remoteHost':regExIP(remoteHost)})

                else:
                    remoteHost = t.get("Computer") #t.get("IpAddress")
                    t.update({'remoteHost':regExIP(remoteHost)})
                                

            except TypeError as te:
                print("[!] Something went wrong to `remoteHost` clause.")
                print(te)
            
            
            #print(remoteHost)
            
            ########################################END - REMOTE HOSTS####################################################
            
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

            ##################################END - MESSAGE TAG###################################################################
            
            if (t.get("EventID") not in ["4103","4104","400","403","500","501","600","800"]): # Not In Powershell Events
                
                
                try:
                    if t.get("TargetUserName"):
                        targetUser = t.get("TargetUserName")
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
                t.update({'targetUser':targetUser})
            
            # PowerShell logging cheatsheet: https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5760096ecf80a129e0b17634/1465911664070/Windows+PowerShell+Logging+Cheat+Sheet+ver+June+2016+v2.pdf
            elif t.get("EventID") in ["4103","4104","400","403","500","501","600","800"]:
                
                eventData = t.get("Data")
                try:

                    #Check if the word "User=" or "UserId=" etc. exists inside the <Data> tag
                    # Before search unpack the Event data which are List format.
                    for eventX in eventData:
                        try:
                            if(re.findall('UserId=.*\w+.*',eventX)):
                                # Find the "UserId" string inside the properties of an Event. If "exists" then catch the Username
                                targetUser = re.findall('UserId=.*\w+.*',eventX)
                                # Convert List results -> String e.g ['AD\Administrator'] -> 'AD\Administrator'
                                targetUser = ' '.join(targetUser)
                                #if exists then split the string and get the value after "=" e.g UserId=15241 grab the 15241
                                targetUser = targetUser.split("=")[1]
                                try:
                                    if targetUser in bListedUsers:
                                        print("[-] Event ID %s with Record ID %s discarded because the TargetUser %s is into the bListedUsers list." % (t.get("EventID"),t.get("EventRecordID"),targetUser))
                                        break
                                    else:
                                        t.update({'targetUser':targetUser})
                                except Exception as error:
                                    print(error)

                            else:
                                #Some PowerShell events doesn't have the UserId property.
                                #In this case, use a generic user, which is called `PSGenericUser` 
                                #Check if targeUser key hasn't already set.
                                if not t.get("targetUser"):
                                    targetUser = "PSGenericUser"
                                    t.update({'targetUser':targetUser})
                        
                        except Exception as error:
                            print(error)
                             
                        try:        
                            if(re.findall('HostApplication=.*\w+.*',eventX)):
                                # Find the "UserId" string inside the properties of an Event. If "exists" then catch the Username
                                HostApplication = re.findall('HostApplication=.*\w+.*',eventX)
                                # Convert List results -> String e.g ['AD\Administrator'] -> 'AD\Administrator'
                                HostApplication = ' '.join(HostApplication)
                                #if exists then split the string and get the value after "=" e.g UserId=15241 grab the 15241
                                HostApplication = HostApplication.split("=")[1]
                                #print(HostApplication)
                                t.update({'HostApplication':HostApplication})
                        
                        except Exception as error:    
                            print(error)
                        
                        try:
                            if(re.findall('ScriptName=.*\w+.*',eventX)):
                                # Find the "UserId" string inside the properties of an Event. If "exists" then catch the Username
                                ScriptName = re.findall('ScriptName=.*\w+.*',eventX)
                                # Convert List results -> String e.g ['AD\Administrator'] -> 'AD\Administrator'
                                ScriptName = ' '.join(ScriptName)
                                #if exists then split the string and get the value after "=" e.g UserId=15241 grab the 15241
                                ScriptName = ScriptName.split("=")[1]
                                t.update({'ScriptName':ScriptName})
                                #print(ScriptName)
                                
                        except Exception as error:     
                            print(error)
                        
                        try:
                            if(re.findall('CommandLine=.*\w+.*',eventX)):
                                # Find the "UserId" string inside the properties of an Event. If "exists" then catch the Username
                                CommandLine = re.findall('CommandLine=.*\w+.*',eventX)
                                # Convert List results -> String e.g ['AD\Administrator'] -> 'AD\Administrator'
                                CommandLine = ' '.join(CommandLine)
                                #if exists then split the string and get the value after "=" e.g UserId=15241 grab the 15241
                                CommandLine = CommandLine.split("=")[1]
                                t.update({'CommandLine':CommandLine})
                                #print(CommandLine)
                        except Exception as error:
                            print(error)
                        
                        try:    
                            if(re.findall('CommandPath=.*\w+.*',eventX)):
                                # Find the "UserId" string inside the properties of an Event. If "exists" then catch the Username
                                CommandPath = re.findall('CommandPath=.*\w+.*',eventX)
                                # Convert List results -> String e.g ['AD\Administrator'] -> 'AD\Administrator'
                                CommandPath = ' '.join(CommandPath)
                                #if exists then split the string and get the value after "=" e.g UserId=15241 grab the 15241
                                CommandPath = CommandPath.split("=")[1]
                                t.update({'CommandPath':CommandPath})
                                #print(CommandPath)
                                
                        except Exception as error:
                            print(Error)
                        
                        try:                        
                            if(re.findall('SequenceNumber=.*\w+.*',eventX)):
                               # Find the "UserId" string inside the properties of an Event. If "exists" then catch the Username
                               SequenceNumber = re.findall('SequenceNumber=.*\w+.*',eventX)
                               # Convert List results -> String e.g ['AD\Administrator'] -> 'AD\Administrator'
                               SequenceNumber = ' '.join(SequenceNumber)
                               #if exists then split the string and get the value after "=" e.g UserId=15241 grab the 15241
                               SequenceNumber = SequenceNumber.split("=")[1]
                               t.update({'SequenceNumber':SequenceNumber})
                               #print(SequenceNumber)
                        except Exception as error:
                               print(error)
                        
                        try:
                            if(re.findall('Severity=.*\w+.*',eventX)):
                               # Find the "UserId" string inside the properties of an Event. If "exists" then catch the Username
                               Severity = re.findall('Severity=.*\w+.*',eventX)
                               # Convert List results -> String e.g ['AD\Administrator'] -> 'AD\Administrator'
                               Severity = ' '.join(Severity)
                               #if exists then split the string and get the value after "=" e.g UserId=15241 grab the 15241
                               Severity = Severity.split("=")[1]
                               t.update({'Severity':Severity})
                               #print(Severity)
                        
                        except Exception as error:
                            print(error)
                       

                   ############ UPDATE #################################
                    #t.update({'targetUser':targetUser})    
                    #t.update({'HostApplication':HostApplication})
                    #t.update({'ScriptName':ScriptName})
                    #t.update({'CommandLine':CommandLine})
                    #t.update({'CommandPath':CommandPath})
                    #t.update({'SequenceNumber':SequenceNumber})
                    #t.update({'Severity':Severity})
                    ######################################################
                        
                    # print(t.get('EventRecordID')+"-->"+t.get('targetUser')) [OK]
                
                except Exception as error:
                    print("[-] Something went wrong while parsing the PowerShell Events!")
                    print(error)
               
                                
                
            else:
                targetUser = "NULL"
                print("[+] Event ID: "+str(t.get("EventID"))+" with Record ID: "+str(t.get("EventRecordID"))+" does not have targetUser tag!")


            ########################################################################################
            #Add  'Attaking Hosts' into Neo4j
            # if Sysmon File is provided, then "DestinationIp" is the correct tag.
            if t.get("DestinationIp"):
                targetServer = t.get("DestinationIp")
                t.update({'targetServer':targetServer})
            elif t.get("Computer"):
                targetServer = t.get("Computer")
                t.update({'targetServer':regEx(targetServer)})
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

    blackListedEventProperties=["Opcode","Keywords","Version","Level","TransmittedServices","KeyLength","LmPackageName","Key Length","Message","SubjectDomainName","Guid","Provider","VirtualAccount","TicketEncryptionType","TicketOptions","Keywords","Level","KeyLength","CertIssuerName","CertSerialNumber","CertThumbprint","Channel","ObjectServer","PreAuth Type","TargetOutboundDomainName","FWLink","Unused","Unused2","Unused3","Unused4","Unused5","Unused6","OriginID","OriginName","ErrorCode","TypeID","TypeName","StatusDescription","AdditionalActionsID","SubStatus","ContextInfo","Product"]

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
            insertEvents = session.run("UNWIND $events as eventPros CREATE (e:Event) SET e=eventPros MERGE (r:RemoteHosts {name:e.remoteHost}) MERGE (u:TargetUser {remoteHost: e.remoteHost,EventRecordIDs: [ ], name:e.targetUser}) MERGE (t:TargetHost {name:e.targetServer})",events=groupEvents)
        print("[+] Event Correlation ...")
        with neo4jDriver.session() as session:
            test = session.run("MATCH (u:TargetUser),(e:Event),(r:RemoteHosts),(t:TargetHost) WHERE u.name=e.targetUser AND r.name=e.remoteHost AND t.name=e.targetServer AND u.remoteHost = r.name AND NOT e.EventRecordID IN u.EventRecordIDs SET u.EventRecordIDs=u.EventRecordIDs+e.EventRecordID")
        print("[+] Delete Dublicates ...")
        with neo4jDriver.session() as session:
            deleteDublicates = session.run("MATCH (t:TargetUser) WITH t.name as n, t.remoteHost as r, collect(t) as dublicateTargetUser where size(dublicateTargetUser) > 1 UNWIND dublicateTargetUser[1..] AS p DETACH DELETE p")
        print("[+] Creating the Relationships ...")
        with neo4jDriver.session() as session:
            remoteHost2DomUserRelationship=session.run("MATCH (r:RemoteHosts),(u:TargetUser) WHERE u.remoteHost = r.name MERGE (r)-[r1:Source2TargerUser]->(u)")
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

    #Count Relatioships
    #with neo4jDriver.session() as session:
    k=neo4jDriver.session().run("MATCH p=()-->() RETURN count(p)")
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

    parser = argparse.ArgumentParser(description='Filter the Windows Events file.')
    parser.add_argument('-e','--eventID', nargs='+', default=["400","403","600","800","1102","1006","1015","1040","1042","1116","4103","4104","4105","4624","4625","4634","4648","4662","4672","4673","4688","4697","4698","4702","4713","4723","4724","4735","4737","4739","4742","4755","4765","4766","4768","4769","4776","4780","4794","4798","4964","5136","5140","5145","5156","5805","7045","8004","8007","1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","255"],help='Use comma to seperate eventIDs.')
    parser.add_argument('-ev', '--events',help='Windows Events in XML OR EVTX format.')
    parser.add_argument('-i','--uri',help='neo4j host. Example: bolt://localhost',required=True)
    parser.add_argument('-D','--delete',help='Delete all data from Neo4j.',action='store_true')
    parser.add_argument('-u','--user',help='neo4j username.',required=True)
    parser.add_argument('-p','--passwd',help='neo4j password.',required=True)
    parser.add_argument('-s','--sysmon',help='Sysmon file.')
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

                for files in dirFiles:
                    
                    fileFullPath = eventsFolder / files
                    if os.path.isfile(fileFullPath) and files.endswith('.evtx'):
                        
                        #Get the file which all the events will be imported befored moved to neo4j.
                        # It just an empty file which will be filled in with Events
                        #print(fileFullPath) #OK
                        outXMLFile = generateOutXMLFileRandomName(eventsFolder)
                        
                        # Read the contents of the EVTX file.
                        evtxDoc = get_events(fileFullPath)
                        
                        # Create an XML file with the same name as EVTX
                        #evtx2xml = str(file).replace(".evtx", ".xml")
                        file = str(fileFullPath).replace(".evtx", ".xml")

                        f = open(file, "w")
                        f.write("\n")
                        f.write("<Events>")
                        for x in evtxDoc:
                            f.write(x)
                        f.write("</Events>")    
                        f.close()
                        rootDoc = minidom.parse(file).documentElement
                        parsingFunction(file,rootDoc,outXMLFile)
                        print("\n")
                        
                        # Remove temp files
                        os.remove(outXMLFile)
                        os.remove(file)                        

                    if os.path.isfile(fileFullPath) and files.endswith('.xml'):
                        #Get the file which all the events will be imported befored moved to neo4j.
                        # It just an empty file which will be filled in with Events
                        #print(fileFullPath) #OK
                        outXMLFile = generateOutXMLFileRandomName(eventsFolder)                     
                        
                        #Open exported XML and remove those chars - Step 1
                        openXMLread=open(fileFullPath,"r")
                        fixChars=re.sub(r"ï»¿", r"", openXMLread.read()) #When Events exported from Windows Event Viewer has those bad chars inside the XML.
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
                    f = open(evtx2xml, "w")
                    f.write("\n")
                    f.write("<Events>")
                    for x in evtxDoc:
                        f.write(x)
                    f.write("</Events>")    
                    f.close()
                    rootDoc = minidom.parse(evtx2xml).documentElement
                    parsingFunction(file,rootDoc,outXMLFile)
                    print("\n")

                    # Remove temp files
                    os.remove(outXMLFile)
                    os.remove(evtx2xml)  
                
                elif file.endswith('.xml'):
                    
                    # Get the file which all the events will be imported befored moved to neo4j.
                    # It just an empty file which will be filled in with Events
                    outXMLFile = generateOutXMLFileRandomName(file)
                    #outXMLFileArray.append(outXMLFile)
                    
                    #Open exported XML and remove those chars
                    openXMLread=open(file,"r")
                    fixChars=re.sub(r"ï»¿", r"", openXMLread.read()) #When Events exported from Windows Event Viewer has those bad chars inside the XML.
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


