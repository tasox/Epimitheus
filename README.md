# Epimitheus
Epimitheus is a python tool that uses graphical database Neo4j for Windows Events visualization. The job of "epimitheus" is to read the exported Windows Events (including Sysmon) in XML form, create a new XML with the correct Event properties and import it to neo4j. 


#### Import Windows Events to Neo4j
python3 epimitheus.py -i "bolt://localhost" -u "neo4j" -p "<password>" -x "Windows_Events.xml" -o "output.xml"

#### Import Windows Events/Sysmon to Neo4j
python3 epimitheus.py -i "bolt://localhost" -u "neo4j" -p "<password>" -x "Windows_Evenst.xml" -o "output.xml" -s
  
#### Delete data from Neo4j
python3 epimitheus.py -i "bolt://localhost" -u "neo4j" -p "<password>" -D

#### Adding Events missing EventIDs

![alt text](https://github.com/tasox/Epimitheus/blob/master/images/addEventIDs.png)


### Neo4j Queries - Examples
More Neo4j queries are coming ...

#### RDP Connections (Sysmon and Windows Events)

MATCH p=(a:RemoteHosts)-->(b:TargetUser)-->(c:Event)-->(d:TargetHost) WHERE c.LogonType = '10' AND c.EventID='4624' RETURN p

#### Pass-The-Hash

MATCH p=(a:RemoteHosts)-->(b:TargetUser)-->(c:Event)-->(d:TargetHost) WHERE c.LogonProcessName = 'NtLmSsp ' AND NOT c.TargetUserName IN ['ANONYMOUS LOGON'] RETURN p

#### Runas (Potential)

MATCH p=(a:RemoteHosts)-->(b:TargetUser)-->(c:Event)-->(d:TargetHost) WHERE c.LogonType = '2' ANd c.LogonProcessName = "seclogo" RETURN p

#### Lateral Movement - Pass-The-Hash /w Mimikatz

MATCH p=(a:RemoteHosts)-->(b:TargetUser)-->(c:Event)-->(d:TargetHost) WHERE c.EventID IN ["4624","4672"] AND c.LogonType = "9" AND c.LogonProcessName = "seclogo" RETURN p

MATCH p=(a:RemoteHosts)-->(b:TargetUser)-->(c:Event)-->(d:TargetHost) WHERE c.EventID IN ["4624","4672"] AND c.LogonType = "9" AND c.LogonProcessName = "seclogo" AND c.TargetLogonId=c.SubjectLogonId RETURN c.EventID,c.remoteHost,c.targetUser,c.TargetLogonId,c.targetServer,c.PrivilegeList,c.SystemTime

MATCH (c:Event),(d:Event) WHERE c.EventID = "4672" AND d.EventID="4688" AND c.SystemTime=d.SystemTime RETURN c.targetUser,d.SubjectUserName,d.targetServer,d.NewProcessName,d.TokenElevationType

MATCH (c:Event),(d:Event) WHERE c.EventID="4672" AND d.EventID="4688" AND c.SystemTime=d.SystemTime WITH [(c.EventID),(c.targetUser),(c.remoteHost),(c.SystemTime)] as Event4672,[(d.EventID),(d.targetUser),(d.remoteHost),(d.SystemTime)] as Event4688 RETURN Event4672,Event4688


#### Memory dump (procdump)

MATCH p=(a:RemoteHosts)-->(b:TargetUser)-->(c:Event)-->(d:TargetHost) WHERE c.EventID="10" AND c.TargetImage =~ ".*lsass.*" RETURN p - Sysmon 

MATCH p=(a:RemoteHosts)-->(b:TargetUser)-->(c:Event)-->(d:TargetHost) RETURN collect(c.TargetFilename)  - Sysmon

MATCH p=(a:RemoteHosts)-->(b:TargetUser)-->(c:Event)-->(d:TargetHost) WHERE c.EventID="10" AND c.TargetImage="C:\\Windows\\system32\\lsass.exe" RETURN p - Sysmon

MATCH p=(a:RemoteHosts)-->(b:TargetUser)-->(c:Event)-->(d:TargetHost) WHERE c.EventID="10" AND c.TargetImage="C:\\Windows\\system32\\lsass.exe" RETURN c.EventRecordID,c.targetUser, c.SourceImage,c.TargetImage,c.TargetFilename

#### Windows Defender

MATCH p=(a:RemoteHosts)-->(b:TargetUser)-->(c:Event)-->(d:TargetHost) WHERE c.EventID = '1116' RETURN c.Path

#### PowerShell

MATCH p=(a:RemoteHosts)-->(b:TargetUser)-->(c:Event)-->(d:TargetHost) WHERE c.HostApplication =~ ".*Power.*" RETURN p LIMIT 10

#### Defense Evasion - PS Script blogging 

MATCH p=(a:RemoteHosts)-->(b:TargetUser)-->(c:Event)-->(d:TargetHost) WHERE c.TargetObject="HKLM\\SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\\EnableScriptBlockLogging" RETURN p

MATCH p=(a:RemoteHosts)-->(b:TargetUser)-->(c:Event)-->(d:TargetHost) WHERE c.TargetObject="HKLM\\SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\\EnableScriptBlockLogging" RETURN c.EventID,c.targetUser,c.EventType,c.Details,c.targetServer,c.TargetObject

#### Defense Evasion - PPID Spoofing

MATCH (c:Event),(d:Event) WHERE c.EventID = "10" AND d.EventID ="1" AND c.TargetProcessId = d.ProcessId RETURN c.EventRecordID,c.targetUser, c.SourceImage,c.SourceProcessId,c.TargetProcessId,d.Image,d.targetUser

#### References
https://medium.com/@pentesttas/windows-events-sysmon-visualization-using-neo4j-part-1-529ca5ab4593

https://medium.com/@pentesttas/windows-events-sysmon-visualization-using-neo4j-part-2-d4c2fd3c9413
