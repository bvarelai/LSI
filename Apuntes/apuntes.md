# Temario LSI (2023-2024)
## Siglas
- **MD5/SHA/SHA3** : Es una funcion hash que puedes aplicarla sobre algo(un PDF) y te devuelve una huella digital(cadena) que es el resumen.
                     No es un algoritmo criptográfico
- **AES/chacha** : Algoritmos criptograficos que cifran la informacion para evitar que te la roben.
- **Firma Digital** : Darle validez legal a un PDF, documento o sesión tráfico de red. En los certificados digitales se cifra la clave privada 
                      para evitar que te suplanten.
- **Clave privada** : Cifrar
- **Clave publica** : Descrifrar 
- **NTP(Network Time Protocol)**: Es el que pone en hora todo.
- **VPN(Virtual Private Network)**: El trafico va cifrado y autenticado desde mi pc hasta la máquina(a traves del servidor de UDC).
- **Intranet** : Red donde estan las BD.
- **SMTP** : Protocolo de correo electronico.
- **GNS3** : Simulador de redes (no emula). 
- **NAT(Network Adress Translate)**: Tus dispositivos estan en una intranet(red privada).
- **DHCP** : configurar las maquinas de manera dinamica(asigna las IP a cada maquina de una intranet).
- **CVE(Common vulnerable exponse)** : Lista de todo tipo de vulnerabilidades de todo tipo de plataformas.
- **NVD(National Vulnerable Database)** : Base de datos de vulnerabilidades.
- **CVE(Common Vulnerability Exposure)**
- **CWE (Common Weakness Exposure)**
- **CVSS(Common Vulnerbility Store System)**
- **CPE(Common Platform Emmeration)**
- **OVAL OPEN (Vulnerability and assessment language)** : Aparece ya que **CVE**, 
  **CWE**, **CVSS** tenian problemas a la hora de establecer los campos.
### Orden para cifrar un PDF
- **PDF** -> **HASH** -> **Huella** -> **Cifrar** -> **Huella digital**
## Tema 1: Fundamentos y Categorias de ataques
### Vulnerabilidad
Las hay de Software y Hardware. Se les reconoce por una sigla llamada **CVE** y **CVSS**.  
Ejemplo : CVE-2013-3527
#### Tipos
- **Zero-Day** : Vulnerabilidad encontrada no parcheada, que puede ser utilizada para un posible ataque.  
  Se le asigna un **CWE** y **CVE**.Los hay sin **CWE** y **CVE** por que no interesa en algunos casos.
- **Zerodium** : Intermediario entre empresa y hackers para hacer negocio.
### Amenazas
Se les reconoce por una sigla llamada **CWE**.  
Ejemplo : CWE-89 nvd.mst gov/vdn
### Ataques
Aprovechan una vulnerabilidad para conseguir algo a cambio.
#### Tipos
 - **[D]Dos** : Los hay por **UDP**(aunque pierda paquetes no pasa nada)
                y **TCP**(info cortada al perder paquetes). 
 - **Fuerza Bruta** 
 - **Poisoning** : Envenenar la red para hacer creer a la red que formo parte de ella 
 - **Inyection Web** : Permite recuperar cookies 
 - **Incidente** : Evento que produce un fallo de servicio(lo que paso el lunes) 
                   tipos: internos,externos,accidentales y no accidentales(son ataques)
### Virus 
#### Tipos
- **Troyano** : Puerta trasera (codigo maligno que se hace pasar por un software 
  venigno)
- **Gusano** : Software que se expande. Wanacrey
- **Dropper** : Virus + Gusano
- **Propagacion**  : Gusano y Dropper
- **Ocultacion** : Dropper y Troyano
### Otros
- **Backdoor** : Puerta trasera que sirve de acceso a un compañero.
- **Sniffer** : Captar trafico de la red.
- **Malware/Virus** : Software maligno, que hace cosas que debe hacer pero otras a
  mayores por detras (MDA SSA256)
- **BOT** : Sistema o infraestructura que esta a servicio de un tercero.
  Ordenadores, telefonos moviles, neveras, teles.  
  Cualquier cosa que tenga connectividad.
- **KeyLoggers** : Dispositivo que registra claves.
### Lo que compone Internet
- **Google** : (5% de internet)
- **Deepweb** : Trozo de internet que no esta indexado 
- **Darkweb** : Donde se venda drogas,armas,familias (1% de internet)

### Diferencia entre Modelo TCO/IP y TCP/IP
#### Modelo TCO/IP  
  4. APP  ---> 7,6,5
  3. Transporte  ---> 4 
  2. internet/red --> 3
  1. acceso ---> 1,2
#### Modelo TCP/IP
  7. Aplicacion 
  6. Presentacion
  5. Sesison 
  4. transporte 
  3. red
  2. enlace 
  1. fisica

- **Phisjing** : Aplicacion o sesion o presentacion
- **Spoofing** : 2. a la 5. 
- **Shifing**  : 3  a la 7.
- **fisica** : 3 a la 7.

### Categorias de Ataques 
- Se basan en este esquema: **Origen** -> **Flujo** -> **Destino** 
#### Interrupción 
Que un servicio deje de funcionar o funcione mal
##### Tipos
- **Dos** : Ataque de sistema sobre sistema. Siempre por inundacion
- **[D]Dos** : Varios Sistemas atacan a un solo sistema. Ejemplo : BotNet
- **Ataque de Negacion de servicio de tipo logico** : Se resulve con un parche, ya que usan las vulnerabilidades para atacar
- **Ataque de Negacion de servicio por Inundacion** : Mas dificil de proteger.  
  Ejemplos : **Traffic Shapinc**(forma de gestionar la calidad del servicio) y **QoS**(buscar la calidad)  
#### Detección
Importante para evitar problemas
##### Tipos
- **IDS** : Detectar posibles ataques e intrusiones en el sistema
- **IPS** : Deteccion y prevención de posibles ataques e intrusiones en el sistema  
  Ejemplos: **SNORT**, **SURICATA**.  
  En un principio se colocaban los IPS en los putnso críticos de la red (la entrada), pero se paso a poner IPS
  en distintos puntos de una red.     
  Ante un problema hay que acotar el problema de manera que sepanos si el problema lo tiene el flujo o el destino.  
  Una vez que detectas el problema(**IDS**) lo solucionas (**IPS**)
- **Sensores**
- **Sistemas de deteccion basados en Red** : Se monta en un punto de la red donde hay mucho trafico
  Ejemplo : Ataques
- **Sistemas de deteccion basados en Host** : Analiza la informacion del logs de los hosts
- **Fallos de los Sistemas Operativos y las Aplicaciones**
#### Modificación
- Ataque contra la **integridad** (Funcion hash)  
  Ej: Modificar una **BD** (mediante ataques sql), modificacion de programas(crackers), malware,  
  troyanos, modificar elementos hardware, modificar sesiones, desbordamiento de pila...
#### Spoofing
- Suplantar cosas : **IP4** direcciones(32 bits) **IP6**(direcciones de 128 bits) **MAC**(direcciones de 48 bits)  
  Para hacer spoofing con correo (netstat [ip] [puerto]).  
  Ejemplos: **SMSFake**(de pago), **SPoofcar**(llamadas telefonicas), **FakeNameGenerator**      
#### Generación/Fabricación
- Ataque contra **Auntenticidad**  
   Ej: Intentar falsear cache, infecciones de malware, DNS Spoofing , HPING3, SCAPY, packit...
#### Amenazas
- Mirar el **PDF de Adrian**
#### Mas cosas
- **Gnat** : 
- **Proxy** : Maquina en la que los host de mi red se conectan si quieren acceder a internet.  
  Esto se usa para evitar que mis maquinas se conecten a cualquier, inundaciones,etc...  
  El problema es que con un proxy cortas conexiones de tu organizacion, que son conexiones legales.   
  Debido a que del proxy sale una unica IP que es usada por cualquier maquina que quiera acceder a internet.     
  Ejemplo : squid, apache
- **Redundancia** : Se hace por seguridad. Se suelen redundar las comunicaciones.   
  En el caso de caer la fibra optica por autopista es bueno tener otro camino de fibra.
## Tema 1.2:  Information Gathering (Recoleccion de Información)
### Host Discovery
- Descubrir un host(**servidores DNS**, **web** y **email** los mas faciles de encontrar. Si es en intranet es mas dificil)
### Port Scanning
- Escogi masquinas y **escaneo puertos** para saber cuales estan levantados y cuales no
#### Comandos
- **IDLE SCAN** : nmap **-l0** **-p** 80 -s | x.x.x.x  www.loquesea     
                  **-l0** --> que no haga host dicovery    
                  **-s** --> maquina zombie                         
- ip id +1 = el puerto esta cerrado  
- ip id -2 = el puerto esta abierto  
Hay que saber que maquina es la zombie(hay que ver que tenga kernels con ip ids secuenciales)   
fw con control de estado esta se caeria al seguir control del estado de las conexiones.
En internet hay mas fw sin control de estado que con control de estado 
     
### Fingerprinting
- Técnicas para determinar que SO y version tiene la maquina. Este se aplica al **PORT SCANNING** ya que al saber un puerto que esta    
  levantado puedo saber lo que esta corriendo ahi y asi descubrir vulnerabilidades.  
  Hacer **port scanning** --> **fingerprinting** activo    
  buscar info ---> **fingerprinting** pasivo
### FootPrinting 
- Recolectar info de paginas web, redes sociales(info publica)
### Google Hacking/Dorks 
- Uso de toda la semantica para la ayuda de buscar info y asi acceder a infraextructuras
### Fuentes Publicas 
- **JMALTEGO**(CREAS ENTIDADES QUE SON COSAS QUE DESCUBRES(IP,MAQUINAS,PERSONAS),**NETGLUB**
### Osint
- **Open Source Intelligent** (Coger info, procesarla y usarla)
### Net Rangos
- PUBLICA  
  NIC (NETWORK INFORMATION CENTER) es --> udc (NO HAY INTRANET)  
  RIPE (REDES IPS EUROPEAS)  
  NCC  (CENTRO EUROPEO) 
### Payloads
- Son módulos de **metasploid**
#### Términos 
- **Single**      
- **Stargers**     
- **STAGES** : Utlidades(para hacer todo tipo de cosas contra esa maquina que he reventado).  
  Ejemplo: **Meterpreter**(tema de logs).  
- **SET** : Herramienta de ingenieria social.   
- **msfplyaloads** : Te permite hacer playloads para hacer **metasploid**(tema de troyanos).  
- **msfencode** : Ofuscador, reescribir el código de los **playloads** para hacer que sea menos detectable.  
  Estos dos se integraron en msfvenon.
### Capa 7
- **Aplicativo Web**
**WAF** ---> **WEB APPLICATION FIREWAL** (Firewall en capa 7, filtra los posibles ataques a aplicaciones web)
Si montas aplicativos web: **WAF** --> se basa en parar problemas de seguridad  
Ejemplo : **modsecurity**, **cloudfare**,**infogure**    
**Explotación** : Escalado de privilegios y pivoting
### OWASP
- **Open Web Aplication Security Project**      
  Muchas líneas de trabajo: Desarrollo de tecnologias,Metodologias para auditar.  
- **OWASP TOP 10** : Documento pequeño(lectura recomendada para el desarrollo software).  
  Lo editan cada 4 años(el último es de 2021) analiza la seguridad web de internet, y hace un top 10.  
  El **1)** siempre fue "INJECTION", pero eso cambio en 2021.  
  **1) Broken Access Control** : Id inseguros -> Path transversal.  
  **2) CRYPTOGRAPHIC FAILURES** : Malas implmentaciones criptorgraficas.      
  **3) INJECTION** : **Sql** inyection, **LDAP** inyection, **OS** inyection,etc.**XSS**(cross-size scripting)   
  **4) INSECURE DESIGN** :   
  **5) SEC MISCONFIGURATION** : **HTTP** mal formadas, error parches actuales y **XXE** (ataques que van contra aplicativos que utilizan XML y JSON)  
  **6) VULNERABLE AND DU+DATED COMPONENTS**  
  **7) AUTENTICACION**  : Problemas de gestion de sesiones, usuarios y password comprometidas, robo de cookies  
  **8) INTEGRIDAD DE SOFTWARE Y DATOS**  
  **9) TEMAS DE MONITORIZACION Y LOGGING**   
  **10) SERVER SIDE REQUEST FORGERY (SSRP)**              
- **ASUS** : Standar para analizar el nivel de seuguridad de un aplicativo web (APPLICATION SECURITY VERFICATION STANDAR)  
- **ZAP** : Escaner de seguridad de **OWASP**  
#### Comandos
- wmic process list full  ---> ps
- ipconfig /displaydan --->
- ipconfig /all  ----> ifconfig -a
- nc -v -n -w IP 21-180
### 4º Generación
APLICACION --> CAPA 7 --> Modificar parametros de la maquina
 Directorio /proc/syslnet ---> aqui dentro hay ficheros que puedo modificar,estos ficheros determinan como se comporta la maquina a nivel de red(UDP y TCP)) 
 OFUSCACION ---> TTL(valor que se decrementa en 1 cuando se envia un paquete a un destino) 
                 WINDOWS = TTL DE 128 ---> reg edit
                 LINUX = TTL DE G4 ---> echo 128 > /proc/sys/net/ipv4/ipdefault_ttl   

### Firewalls
iptables ---> configurar firewalls ---> iptables -t MANGLE -I OUTPUT -j TTL -ttl -set 53
 nft ---> configurar firewalls 


## Practica 3 

