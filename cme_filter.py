import re
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-i', type=str)
parser.add_argument('-v', type=int)
args = parser.parse_args()

regex = r".*SMB.*\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:?).*\[\*\].*?\s+(.*:?)\s+\(name:(.*:?)\)\s+\(domain:(.*:?)\)\s+\(signing:(.*:?)\)\s+\(SMBv1:(.*:?)\)"

SMBv1 = []
SMBv2 = []

if not args.i:
    print("now input file. exiting..")
    exit()

if not args.v and args.v < 1 or args.v > 2:
    print("invalid smb version. exiting..")
    exit()

with open(args.i, 'r') as i:
    line = i.readline().rstrip('\n')
    while line:
        matcher = re.match(regex, line)
        if matcher:
            isSMBv1 = matcher.group(6)
            ip = matcher.group(1)
            SMBv1.append(ip) if isSMBv1 == 'True' else SMBv2.append(ip)
        line = i.readline()

import socket
SMBv1 = sorted(SMBv1, key=lambda item: socket.inet_aton(item))
SMBv2 = sorted(SMBv2, key=lambda item: socket.inet_aton(item))

ranges_smb_1 = []
ranges_smb_2 = []

smb_selector = {1: SMBv1, 2: SMBv2}
smb_list = smb_selector[args.v]
i = 0
while i < len(smb_list):
    if i + 1 == len(smb_list):
        ranges_smb_1.append(smb_list[i] + '-' + smb_list[i])
        break
    j = i
    while True:
        current_last_oct = smb_list[j].split('.')[3]
        next_last_oct = smb_list[j+1].split('.')[3]
        if int(current_last_oct) + 1 == int(next_last_oct):
            j +=1
        else:
            break
    ranges_smb_1.append(smb_list[i] + '-' + smb_list[j])
    i = j + 1 if i != j else i + 1


print(smb_list)
print("SMBv" + str(args.v) + " ranges:")
for r in ranges_smb_1:
    print(r, end='\n')