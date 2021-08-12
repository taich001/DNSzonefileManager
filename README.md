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
print ("This is the original")
print(ZF.showinput())
print ("--------------------------------------------")

print ("Check it it is valid")
ret, rerr = ZF.validate()
if not ret:
    Print("There is an error in this file!")
    print(rerr)
print ("--------------------------------------------")


print ("This is the zonefile in json (formatted)")
print(ZF.showjson(True))

print ("This is the zonefile in json")
jsonfile = ZF.showjson()


print ("Convert the json back to txt")
out = GenerateZoneFile(jsonfile)
print(out.showtext()) 
print ("--------------------------------------------")
```

## Limitatzions

Only specific recorod keys are accepted.
Not supported record keys will bo omitted from output.

supported record types are:
- $ORIGIN
- $TTL
- SOA
- NS
- A
- AAAA
- HINFO
- CNAME
- MX
- PTR
- TXT
- SRV
- URI


## To do

- Disable logfile
- Determine logfile name
- Remove IgnoredLines parameter
- Implemt DNSSEC, DNSKEY, DS records


## Important RFC's

- RFC 1035 - Domain Names
- RFC 1912 - Common DNS Operational and Configuration Errors
