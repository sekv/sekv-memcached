import os,sys

hashpower = (20,21,22,23,24,25,26)

for i in range(0,7):
    command = "./myhash " + str(hashpower[i]) + " " + str(2**hashpower[i])
    print command 
    os.system(command)
