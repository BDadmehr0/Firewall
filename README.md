# Firewall
بسته‌ها را قبل از رسیدن به سرویس بررسی می‌کند و طبق Ruleها اجازه می‌دهد، محدود می‌کند یا Drop می‌کند.

``` text
   UP Network Dev
         |
     Attachment -> Monitor -> Firewall Alghorithm -> Log <-----|
                      |             |                 _______ Drop 
                      |             ------Rule-----> |_______ Accept -> Forward
              All Network Protocol

```

## Rule

- Add rate limiting for excessive incoming traffic.
- Limit new TCP connections per source IP.
- Drop invalid and malformed packets.
- Add basic SYN flood protection.
- Rate-limit ICMP/ping requests.
- Block unnecessary ports and allow only required services.
- Add temporary blocking for IPs that exceed defined limits.
- Keep established and related connections allowed.

## Log

- Test the rules to avoid blocking legitimate users.
- Log suspicious or dropped traffic without flooding the logs.

## Used Packages

- Scapy

## Command Line

``` bash
==> ip -br link

lo               UNKNOWN        00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP> 
eno1             DOWN           bc:fc:e7:3a:be:99 <NO-CARRIER,BROADCAST,MULTICAST,UP> 
wlp0s20f3        UP             30:e3:a4:34:45:18 <BROADCAST,MULTICAST,UP,LOWER_UP>
```
