# Epimitheus
Epimitheus is a python tool that uses graphical database Neo4j for Windows Events visualization. The job of "epimitheus" is to read the exported Windows Events (including Sysmon) in XML form, create a new XML with the correct Event properties and import it to neo4j. 


#### Import Windows Events to Neo4j
python3 epimitheus.py -i "bolt://localhost" -u "neo4j" -p "<password>" -x "Windows_Events.xml" -o "output.xml"

#### Import Windows Events/Sysmon to Neo4j
epimitheus.py -i "bolt://localhost" -u "neo4j" -p "<password>" -x "Windows_Evenst.xml" -o "output.xml" -s
  
#### Delete data from Neo4j
epimitheus.py -i "bolt://localhost" -u "neo4j" -p "<password>" -D

#### Adding Events missing EventIDs

![alt text](https://github.com/tasox/Epimitheus/blob/master/images/addEventIDs.png)


### Neo4j Queries - Examples
More Neo4j queries are coming ...

##### RDP Connections (Sysmon and Windows Events)

MATCH p=(a:RemoteHosts)-->(b:TargetUser)-->(c:Event)-->(d:TargetHost) WHERE c.LogonType = '10' AND c.EventID='4624' RETURN p

##### Pass-The-Hash

MATCH p=(a:RemoteHosts)-->(b:TargetUser)-->(c:Event)-->(d:TargetHost) WHERE c.LogonProcessName = 'NtLmSsp ' AND NOT c.TargetUserName IN ['ANONYMOUS LOGON'] RETURN p

##### Runas (Potential)

MATCH p=(a:RemoteHosts)-->(b:TargetUser)-->(c:Event)-->(d:TargetHost) WHERE c.LogonType = '2' ANd c.LogonProcessName = "seclogo" RETURN p

##### Mimikatz (PtH)

MATCH p=(a:RemoteHosts)-->(b:TargetUser)-->(c:Event)-->(d:TargetHost) WHERE c.LogonType = "9" AND c.LogonProcessName = "seclogo" RETURN p

##### Memory dump (procdump)

MATCH p=(a:RemoteHosts)-->(b:TargetUser)-->(c:Event)-->(d:TargetHost) WHERE c.EventID="10" AND c.TargetImage =~ ".*lsass.*" RETURN p - Sysmon
MATCH p=(a:RemoteHosts)-->(b:TargetUser)-->(c:Event)-->(d:TargetHost) RETURN collect(c.TargetFilename)  - Sysmon

##### Windows Defender

MATCH p=(a:RemoteHosts)-->(b:TargetUser)-->(c:Event)-->(d:TargetHost) WHERE c.EventID = '1116' RETURN c.Path

#### PowerShell

MATCH p=(a:RemoteHosts)-->(b:TargetUser)-->(c:Event)-->(d:TargetHost) WHERE c.HostApplication =~ ".*Power.*" RETURN p LIMIT 10

