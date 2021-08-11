# DNSzonefileManager
A Phyton library that provides methods for DNS zonefiles

Validate a zone file

Convert a zone file to json and convert it back to txt


## How to use it


```
from zonefile import ParseZoneFile, GenerateZoneFile

zonefile = "mydomain.com"

fh = open(zonefile,"r")
zf = fh.read()
fh.close()

ZF = ParseZoneFile(zf)

print(ZF.showinput())
ret, rerr = ZF.validate()
print(rerr)
print ("--------------------------------------------")

print(ZF.showjson(True))
print ("--------------------------------------------")

jsonfile = ZF.showjson()
out = GenerateZoneFile(jsonfile)

print(out.showtext()) 
print ("--------------------------------------------")
```
