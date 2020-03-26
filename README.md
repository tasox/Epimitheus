# Epimitheus
Epimitheus is a tool that uses graphical database Neo4j for Windows Events visualization. The job of "epimitheus" is to read the exported Windows Events (including Sysmon) in XML form, create a new XML with the correct Event properties and import it to neo4j.


### Import Windows Events to Neo4j
python3 epimitheus.py -i "bolt://localhost" -u "neo4j" -p "<password>" -x "Windows_Events.xml" -o "output.xml"

### Import Windows Events/Sysmon to Neo4j
epimitheus.py -i "bolt://localhost" -u "neo4j" -p "<password>" -x "Windows_Evenst.xml" -o "output.xml" -s
  
### Delete data from Neo4j
epimitheus.py -i "bolt://localhost" -u "neo4j" -p "<password>" -D

### Adding Events missing EventIDs

![alt text]()


### Neo4j Queries

#### RDP Connections (Sysmon and Windows Events)

MATCH p=(a:RemoteHosts) →(b:TargetUser) →(c:Event) →(d:TargetHost) WHERE c.LogonType = '10' AND c.EventID='4624' RETURN p

#### Pass-The-Hash

MATCH p=(a:RemoteHosts) →(b:TargetUser) →(c:Event) →(d:TargetHost) WHERE c.LogonProcessName = 'NtLmSsp ' AND NOT c.TargetUserName IN ['ANONYMOUS LOGON'] RETURN p

#### Runas

##### Mimikatz (PtH)

MATCH p=(a:RemoteHosts) →(b:TargetUser) →(c:Event) →(d:TargetHost) WHERE c.LogonType = "9" AND c.LogonProcessName = "seclogo" RETURN p

#### Memory dump (procdump)

MATCH p=(a:RemoteHosts) →(b:TargetUser) →(c:Event) →(d:TargetHost) RETURN collect(c.TargetFilename)  - Sysmon

#### Windows Defender
