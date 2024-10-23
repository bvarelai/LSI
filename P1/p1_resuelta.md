# Practica 1
## Configuración de las interfaces
- Archivo `/etc/network/interfaces`
```
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).
#source /etc/network/interfaces.d/*
# The loopback network interface
auto lo ens33 ens34 6to4
iface lo inet loopback
iface ens33 inet static
        address 10.11.48.203/23
        gateway 10.11.48.1
        dns-nameservers 10.8.12.47 10.8.12.49 10.8.12.50
iface ens34 inet static
        address 10.11.50.203/23
iface ens34:0 inet static
        address 10.11.51.203/23
iface 6to4 inet6 v4tunnel
        pre-up modprobe ipv6
        address 2002:a0b:30cb::1
        netmask 16
        gateway ::10.11.48.1
        endpoint any
        local 10.11.48.203
```
- Esquema visual de esta configuración
```mermaid
graph TD;
    lo[Loopback] --> lo_iface[iface lo inet loopback];
    ens33[ens33 Interface] -->|Static| ens33_iface[10.11.48.203/23];
    ens33_iface --> gateway1[Gateway: 10.11.48.1];
    ens33_iface --> dns[DNS:<br/>10.8.12.47<br/>10.8.12.49<br/>10.8.12.50];
    
    ens34[ens34 Interface] -->|Static| ens34_iface[10.11.50.203/23];
    ens34_alias[ens34:0 Interface] -->|Static| ens34_0_iface[10.11.51.203/23];
    
    tunnel[6to4 Interface] -->|Tunnel| ipv6_tunnel[2002:a0b:30cb::1/16];
    ipv6_tunnel --> gateway2[IPv6 Gateway: ::10.11.48.1];
    ipv6_tunnel --> local_tunnel[Local: 10.11.48.203];
