# Firewall

``` text
   UP Network Dev
         |          
     Attachment -> Monitor -> Firewall Alghorithm -> Log
                      |             |
                      |             --------------> Return Checking
              All Network Protocol

```

## Used Packages

- Scapy

## Command Line

``` bash
==> ip -br link

lo               UNKNOWN        00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP> 
eno1             DOWN           bc:fc:e7:3a:be:99 <NO-CARRIER,BROADCAST,MULTICAST,UP> 
wlp0s20f3        UP             30:e3:a4:34:45:18 <BROADCAST,MULTICAST,UP,LOWER_UP>
```