#!/usr/bin/python3
from ldap3 import Server, Connection, ALL, NTLM
from collections import defaultdict
import ipaddress
import pprint
import os
import json
import os.path
from os import path

WORKDIR='/opt/wireguard'
NETWORK='192.168.55.0/24'  		# WG CLIENT NETWORK
LDAPSERVER='192.168.55.2'  		# AD SERVER ADDRESS
FIRSTRUN=False             		# CHANGE TO True ON FIRST RUN
ADUSER="AD\\wireguardintegration"  	# NONE ADMIN USER FOR USER LISTING 
ADPASSWORD="XXXXXXXXX"  		# 
WGSERVERPUBKEY="2sWDUc6GkvlGPuv+jf528s9q9g3HufGTlVs7QJi2nms="  #WG PUB KEY 
CLIENTCONFIGDIR="clientconfigdir" 	#DIR WHERE CLIENTS CONFIGS PLACED

#LDAP MAGIC https://gist.github.com/jonlabelle/0f8ec20c2474084325a89bc5362008a7
SEARCH_BASE='OU=Users,OU=moscow,DC=ad,DC=local' # BASE STRING WHERE TO SEARCH
SEARCH_FILTER='(&(objectClass=person) (memberof=CN=vpn,OU=Groups,OU=moscow,DC=ad,DC=local)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' # FILTER LDAP SEARCH FOR GROUP (CN=VPN)

os.chdir(WORKDIR)

users = {}


if not path.exists("users.json"):
    FIRSTRUN=True
else:
    print("found users.json, loading...")
    usersold=json.load(open("users.json"))


#connect to AD
server = Server(LDAPSERVER, get_info=ALL)
conn = Connection(server, user=ADUSER, password=ADPASSWORD, authentication=NTLM)

if conn.bind():
    print("connection to {} sucsessfull".format(LDAPSERVER))
else:
    print("unable connect to LDAP {} !".format(LDAPSERVER))



def generatePrivPubKeys():
    stream = os.popen('wg genkey')
    privkey=stream.read().rstrip()
    stream = os.popen('echo "{}"|wg pubkey'.format(privkey))
    pubkey = stream.read().rstrip()
    os.close
    stream.close()
    return privkey,pubkey

def addwgroute(newip):
    stream = os.popen('ip -4 route add {}/32 dev wg0'.format(newip))
    res=stream.read().rstrip()           
    stream.close()
    print(res)


def delwgroute(newip):
    stream = os.popen('ip -4 route del {}/32 dev wg0'.format(newip))
    res=stream.read().rstrip()
    stream.close()
    print(res)
   
def makeqr():
    stream = os.popen(WORKDIR+'/makeqr.sh')
    res=stream.read().rstrip()
    stream.close()
    print(res)


conn.search(
    search_base=SEARCH_BASE,
    search_filter=SEARCH_FILTER,
    attributes = ['sAMAccountName']
)


#generate available ips list from ip NETWORK
ips=[]
for addr in ipaddress.ip_network(NETWORK).hosts():
   ips.append(str(addr))


#remove server ip from top of the list
del ips[0]
ipindex=0


#generate users dict from AD with empty vals
for entry in conn.entries:
    users[str(entry['sAMAccountName']).lower()]={'ip':ips[ipindex],'pubk':'','privk':''}
    ipindex+=1



if FIRSTRUN:
    ipindex=0
    for u in users:
        privk,pubk=generatePrivPubKeys()
        users[u] = {'ip':ips[ipindex],'pubk':pubk,'privk':privk}
        ipindex+=1
    json.dump( users, open( "users.json", 'w' ),indent=4 )   
    print("users.json saved.Exit. Configs will be generated on the next run ")
    exit()    


#generate list of available ips
freeips=set(ips)
for x in usersold.keys():
    if  usersold[x]['ip'] in freeips:
        freeips.discard(usersold[x]['ip'])
freeips=list(freeips)        
freeipsindex=0


#check added,remove users relative to saved users.json file

if users.keys() != usersold.keys():
   if users.keys() - usersold.keys():
       print("new users")
       diff=users.keys() - usersold.keys()
       print(diff)
       for x in diff:
           privk,pubk=generatePrivPubKeys()
           users[x]['privk']= privk
           users[x]['pubk'] = pubk
           users[x]['ip'] = freeips[freeipsindex]
           addwgroute(users[x]['ip'])
           freeipsindex+=1

   if usersold.keys() - users.keys():
       print("some users removed")
       diff=usersold.keys() - users.keys()
       print(diff)
       for x in diff:
           delwgroute(usersold[x]['ip'])
           users.pop(x,'none')

   for u in users:
       if u in usersold:
           users[u]=usersold[u]

else:
   print("no users modified, exit")
   users=usersold

json.dump( users, open( "users.json", 'w' ),indent=4 )   

serverconfig="""[Interface]
#Address = 192.168.160.1/23
ListenPort = 5033
PrivateKey = SOjbrvxGcOPLx4IL6LX3w9zh7h0l43r4GD4xJJYxs0c=

"""

def generateServerSidePeer(username,pubk,ip):
    peer="""
[Peer]
#{}
PublicKey = {}
AllowedIPs = {}/32
PersistentKeepalive = 25
"""
    return(peer.format(username,pubk,ip))


#generate server config
for u in users:
    serverconfig+=generateServerSidePeer(u,users[u]['pubk'],users[u]['ip'])

#print(serverconfig)    
f = open('wg0.conf', 'w')
f.write(serverconfig)
f.close()

if not path.exists(WORKDIR+"/"+CLIENTCONFIGDIR):
    os.mkdir(WORKDIR+"/"+CLIENTCONFIGDIR)

clientsidepeer="""[Interface]
Address = {}/23
PrivateKey = {}
DNS = 192.168.2.1, 192.168.2.2

[Peer]
#{}
PublicKey = 0vp124knBlJ1kOMztLttb5bQyO7ADx87di86Bhwdj0U=
AllowedIPs = 10.10.220.0/24, 10.10.10.0/23
Endpoint = XXX.XY:5033
"""

def GenerateClientSidePeer(ip,privk,username):
    return (clientsidepeer.format(ip,privk,username))


#generate client configs 
for u in users:
    configpath=WORKDIR+"/"+CLIENTCONFIGDIR+"/"+u
    if not path.exists(configpath):
       os.mkdir(configpath)
    f = open(configpath+'/'+'/office_vpn.conf', 'w')
    f.write(GenerateClientSidePeer(users[u]['ip'],users[u]['privk'],u))
    f.close()
       
#generate qr's in users dir
makeqr()

