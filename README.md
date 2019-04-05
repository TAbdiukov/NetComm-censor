# NetComm-censor

## Trivia
Censorship is almost always bad. But consider someone everyday accessing aljazeera or rt, or other outlets radicalising and promoting segregation. Sure, they aren't messed with on the global scale, but if they vastly affect one community, wouldn't it be ethical to obstruct access to them? Sure, one can download vpn and then access, but that's already some hastle to access that stuff. Assuming one figures out how to set this up 🙂

## Script
What script does is it requests the NetComm Wireless (R) routers to blacklist IP address ranges (in CIDR) from the file of of "list.txt" . Even if router's blocking functionality is restricted. Seemily all Netcomm routers are compatible

## Routers tested on
* NetComm Wireless NF18ACV (NBN)
* Sagemcom F@ST 5355
* Belong F@ST 4315

## Usage
1. Edit config.ini (if needed)
2. List IP addresses or IP ranges to block in list.txt (in CIDR notation)
3. Run script
4. ???. Done

## Useful links
* [Hurricane Electric BGP](https://bgp.he.net)
* [Exploits DB: Sagemcom 3864 V2 get admin password](https://www.exploit-db.com/exploits/37801)
* [Whirlpool thread of netcomm reverse engineering](https://forums.whirlpool.net.au/archive/2746904)