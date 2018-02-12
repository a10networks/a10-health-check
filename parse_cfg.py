'''
A10 Health Check

Date:
Author: Terry Jones
Summary:


Need to modify this to log into device and pull conf per partition. Full configuration at once will
make single list of objects for entire device, which will not work for this methodology.

'''

import re

server=[]
srv_grp=[]
virtual_srvr=[]
partitions=[]
cfg = open('vThunder_Config.txt', 'r')
for line in cfg:
    if 'application-type' in line:
        partitions.append(re.sub("[^\w._-]", " ", line).split())
    elif 'slb server' in line:
        server.append(re.sub("[^\w._-]", " ", line).split())
    elif 'slb service-group' in line:
        srv_grp.append(re.sub("[^\w._-]", " ", line).split())
    elif 'slb virtual-server' in line:
        virtual_srvr.append(re.sub("[^\w._-]", " ", line).split())

print("\nPartition List\n")
partition_list=[]
for item in partitions:
    partition_list.append(item[1])
print("There are ",len(partition_list), " total partitions.\n")
print(partition_list)


print("\nServer List\n")
srvr_list=[]
for item in server:
 srvr_list.append(item[2])
print("There are ",len(srvr_list), " total servers.\n")
print(srvr_list)

print("\nService-groups\n")
svc_grps=[]
for item in srv_grp:
 svc_grps.append(item[2])
print("There are ",len(svc_grps)," total service-groups.\n")
print(svc_grps)

print("\nVirtual Servers\n")
vips=[]
for item in virtual_srvr:
 vips.append(item[2])
print("There are ",len(vips)," total vips.\n")
print(vips)

#Add partitions