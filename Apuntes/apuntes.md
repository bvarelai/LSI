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
#### Comandos
- nmap -sP 10.11.48.0/24 : Nos hace un hostdicovery(si nos responde es que hay maquina)
### Port Scanning
- Escogi masquinas y **escaneo puertos** para saber cuales estan levantados y cuales no.
#### Estado de los puertos
- **open** : abierto   
- **closed** : cerrado pero hay algo    
- **filtered** : filtro que te impide llegar a ese puerto  
- **unfiltered** : no esta filtrado pero no es capaz de determniar si esta abierto o cerrado   
- **open filtered** : no sabe si esta filtrado o abierto  
- **close filtered** : no sabe si esta filtrado o cerrado
#### Comandos
- **IDLE SCAN** : nmap **-l0** **-p** 80 -s | x.x.x.x  www.loquesea     
                  **-l0** --> que no haga host dicovery    
                  **-s** --> maquina zombie                         
- **ip id +1** = el puerto esta cerrado  
- **ip id -2** = el puerto esta abierto  
Hay que saber que maquina es la zombie(hay que ver que tenga kernels con ip ids secuenciales)   
fw con control de estado esta se caeria al seguir control del estado de las conexiones.
En internet hay mas fw sin control de estado que con control de estado 

- **hping3 -c 1 -s -p 22 [IP]** : Si delvuelve ACK(se inicia la charla) si es reset(esta apagado)
- **nmap -sS -p 22,80,443,512...** : Saber si los puertos estan cerrados(escaneo de puertos)... 
- **nmap -sA-p 22,80,443,512...**  : Escaneo de puertos con ACK  

Se envio un ACK Y RECIBO UN RESET SE QUE EN EL MEDIO NO HAY UN FIREWALL DE CONTROL DE ESTADO
pero si no recibo nada puede que si que haya un firewall o la maquina este apagada.
Hay casos donde recibes reset y puede ser que lo envie el firewall, por lo que si recibes reset puede haber firewall 
  
- **nmap -PU 512,123,57...** : Escaneo por udp  
- **nmap -D [IP][IP][IP][IP]** : Escaneo de **IPs** (decoyscan)  
- **nmpa -6 []** : escaneo **IPv6**  
- **nmap -T 0** : las peticiones se envian seguidos(no es bueno si se envian muchos paquetes a la vez)  
- **nbtscan** : escaner pero en windows  
- **Descubrir/investigar maquinas** : Si trazo una ruta a un servidor web, la ultima IP es posible que sea la del firewall de la organizacion.  
  Podemos usar "traceroute" para llegar al servidor web   
- **traceroute -T -U [IP]** : Paquete sync por TCP (llega seguro al servidor web)
### Fingerprinting
- Técnicas para determinar que SO y version tiene la maquina. Este se aplica al **PORT SCANNING** ya que al saber un puerto que esta    
  levantado puedo saber lo que esta corriendo ahi y asi descubrir vulnerabilidades.  
  Hacer **port scanning** --> **fingerprinting** activo    
  buscar info ---> **fingerprinting** pasivo
#### Comandos
- nmap -O [IP] : que SO y version tiene la maquina(fingerprinting del SO)  
- nmap -sP -sV 10.11.48.0/24 : (fingerprinting de servicios y puertos)      
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
  **NIC(NETWORK INFORMATION CENTER)** es --> udc (NO HAY INTRANET)  
  **RIPE(REDES IPS EUROPEAS)**  
  **NCC(CENTRO EUROPEO)** 
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
- **wmic process list full** : ps
- **ipconfig /displaydan** :
- **ipconfig /all** : ifconfig -a
- **nc -v -n -w IP 21-180**
### 4º Generación
- **APLICACION(CAPA 7)** : Modificar parametros de la maquina
- Directorio **/proc/syslnet** : aqui dentro hay ficheros que puedo modificar,estos ficheros determinan como se comporta la maquina a nivel de red(UDP y TCP) 
- **OFUSCACION** : **TTL**(valor que se decrementa en 1 cuando se envia un paquete a un destino)  
                 **Windows** = **TTL** DE 128 ---> reg edit  
                 **Linux** = **TTL** DE G4 ---> echo 128 > /proc/sys/net/ipv4/ipdefault_ttl   
#### Más sobre Ofuscación
- **OSfuscate**  
- en /etc/apache/apache2.conf                   
- **ServerTokens**  
- **ServerSysnatune**
- $lynx -head -dmap http://www.usc.es : informacion del servidor web(lo que tiene montado)   
- Para hacer **portscanning** ---> usar nmap  
- **whatweb**  
- **SMNTP** (Verified(Desactivado) Respt to(El destinatatio)) : se puede hacer a mano con netcat. Sino usar smtp-move-daemon -M VRFY/REPT -U -T servirtol      
### Firewalls
#### Comandos para configurar Firewalls  
- **iptables**  : iptables -t MANGLE -I OUTPUT -j TTL -ttl -set 53  
- **nft**
#### Tipos
- **Firewall sin control de estado** : Funciona en capa 2   
- **Firewall con control de estado** : A mayores comprueba el estado de todas las conexiones que se hacen(siguiendo los hand sakes). Se envian los acks           
- **Firewalls modo router** : Router donde hago routung y defino listas de acceso(que IP`s dejo pasar) para filtrar  
- **Firewalls NAT** : Router donde hago routing y nating  
- **Firewalls modo transparentes** : Trabajan en capa 2 (sus interfaces no tienen IP). La gente de fuera de la red local no lo ve  
  ya que es de capa 2 y no se puede hacer routing para llegar a el.  
  mtables(montar firewall en capa 2, lo opuesto a iptables) www.nslap.com  
- **Firewalls de nueva generacion** : Desde capa 2 a 7(los mas potentes)
### Más cosas a mayores
- **Information gallery** : MALTEGO, NETGLUB
- **Metadatos** : CREEPY(recolecta fotos y geolocaliza el lugar donde se han hecho a traves de metadatos)
- **SPIDER** : engancharse a servidores web de internet(donde hay un idex.html). Recorre el arbol web empezando por el index.html de servidor en servidor. 
- **CRAWLER** : Lo mismo que el spidering pero ademas busca la vulnerablidades/y hace un analisis sintactico) de los servidores
- **SCRAPPER** : Coger informacion de varios sitios para comparar "precios"/cosas.
- **HARDENING** : endurecer nuestro sistema para mejorar la seguridad 
               Herramienta: lynis audit system (te da consejos para mejorar la seguridad de tu maquina)    
               Libreria: lilpum-tmpdir    
- **atp-listbugs** : Permite ver los bugs de los paquetes   
- **apt install needstart** : Se usa cuando hay cambios de librerias  
- **debsecan** : te da las vulnerabilidades no parcheadas de tu maquina    
- **debsums -d** : Te dice las diferencias de cada paquete instalado  
- **fail2ban** : ataques password-guessing los evita.   
- **systemd-analize security apache2.service** : Analisis del nivel de seguridad (las directivas que aparecen en el .service)   
- Protect.system:full   
- **sandbox** : Entorno acotado(donde se corre un servicio con sus librerias, de manera que si acceden a ese servicio no afecta al resto de servicios). Write-only patch    
- **etc/security/limits.conf** : Puedo establecer limites a ciertas cosas(RAM,Disco,Pila,CPU). Se hace modificando las variables    
- **fichero core** : Volcado de memoria(imagen del SO). En casos de errores       
- **Mayor redundancia** -> Mayor seguridad  
- **PAE**(**PHYSICAL ADDRESS EXTENSION**) : permite ampliar la RAM de nuestros sistema (pasar de 4GB a 64GB)  
- **DEP**(**DATA EXECUTION PREVENTION** (otro nombre: no execute)): las zonas dedicadas a datos(la pila), el sistema las controla como de no ejecucion  
- **/etc/pam.d/common-password** : Donde podemos modificar parametros. Si ponemos ramds=20000 en el fichero, la contraseña que ponemos al entrar se le aplicara la funcion hash 20000 veces.  
Con esto se hace mas dificil crackear los passwords.  
- **/etc/shadow** : se almacena el hash y el password de todos los usuarios. Cuando te autentifica la passord que poner se le aplica hash y si esa password  
coincide con la que esta alamcenada en shadow te deja entrar. 
- **chage -lsi** : para ese usuario la fecha actual, cuando cambie la contraseña,etc...  
- **passwd -e lsi** : hace que expire la contraseña de este usuario  
#### Librerias que hacen como deben ser la passwords(tema caracteres, anchuras, que no repitas contraseñas) 
- pam-cracklib
- pam-passwdqc 
- pwquality

- **Umask 022** : los ficheros creados tendran como permisos rwxw-xx-x (usa profile)
- **Umask 027** : el fichero credado tiene como permisos rwx r-x--- (usa bashrc)
- **/etc/profile** : (Generico para todos los usuarios)aqui puedo modifcar el umask)
- **$home/.profile** : (Para cada usuario especifico)
- **/etc/bash.bashrc**
- **$home/.bashrc**
- **LVM** : **Gestion Virtual de dispositivos de alamacenamiento**    
Permite aumentar/reducir las particiones de la máquina(buscando espacio de otra partición)  
- echo 1 > /etc/sys/kernel/modules-disabled  
- /etc/modprofile.d/blacklist.conf : Te mira reducir las sesiones, el numero de intentos de contraseñas  
## Tema 1.3:  Ocultación
### NAT
Usando **NAT** no hay ocultación    
Si yo accedo a un servidor web a traves de **NAT**, ese servidor con sripting puede conocer mi ip. Por ello Hay que trabajar la ocultacion en todos los niveles de la **capa OSI**.  
La clave es cambiar la **MAC** ya que cambiar la **IP** no es tan seguro si tienes la misma MAC siempre.
### PROXY
REMOTE_ADDR : IP(X) IP(X) IP : solo se vera la ip del ultimo proxy   
X_FORWARDED_FORI : IP,IP
#### TIPOS
- **PROXYS HTTP**
- **PROXYS SOCK**
- **PROXYS TRANSPARENTE** : No da ocultacion ni privacidad (HTTP FORWARDING FOR)
- **PROXYS ANONIMMOS**  
- **PROXYS ANONIMICIDAD**  
- **PROXYS RUIDOSOS** : En las cabeceras meten ruido(direcciones falsas)
##### PROXY HTTP
- **export http_proxy=http://x.x.x.x:3128**  : hago de proxy de las peticiones http
- **export ftp_proxy=ftp://x.x.x.x:3128**  : hago proxy de las peticiones ftp
- **software para montar un proxy http** : squid
- **/etc/profile** : proxy HTTP      
- **$''/profile** : proxy HTTP
##### PROXY SOCK
- etc/socks.conf
- direct 127.0.0.1 255.255.255.255
- direct 10.11.48.0 255.255.254.0 
- sockd @:x.x.x.x  0.0.0.0  0.0.0.0 
## Tema 1.4:  Sniffing
### AIRMON
- **airmon -ng** : Tarjeta WI-FI "modo monitor" -- esnifas todo el trafico en el aire(que es el medio del WI-FI)   
- **airondump -ng** : Captura trafico  
- **aireplay -ng** : Enviar paquetes de auntentucacion(a una maquina) y quitarte la autenticacion de la wifi  
- **aircrack -ng** : Crackeador de HANDSHAKES (WPA2)  
- **airmon -ng start wlan0** : Modo monitor la tarjeta wlan0  
- **airondump -ng mon0** : El mon0 es el lugar donde capturo trafico de la wlan0.  
  Muestra: BSSID (mac del pubto de acceso) , ESSID (nombre de la wifi, maquinas conectadas a ese punto de acceso)  
- **airondumo -ng --CANAL -bssid [punto de acceso] -w captura mon0** : Pilla eñ trafico de y lo alamacena en el fichero "captura"  
- **airplay -ng -0 1 -a XXXXX -c xxxxx mon0** : Asi le le quito la auntenticacion  
- **aircrack -ng -w disc captura** : Le crackeo(me calcula PNK`s)  
### PROCESO DE CRACKEO CON WPA2 A UNA WIFI PTK: PNK ANNOUNCE SNOUNS MAC(PUNTO DE ACCCESO) MAC (DE LA ESTACION)
El PNK de la clave de acceso(password)
Si todo lo que metes del PTK coincide con ese NICK del password -> YA ESTARIA

- **WPS** : Se usaba hace años. Estandard en el que habia un indentificador(QR) para conectarse mas facil a la WIFI  
El identificador tenia 7 digitos decimales. Cuando se programo el WPS se hizo 10^4 + 10^3 en vez de 10^7,  
Por lo que disminuyo el numero de convinaciones posibles(la gente robaba el WI-FI)  
- **FLUXION** ---> Herramienta de Ingeniera Social(Suplanta un punto de acceso)
### HERRAMIENTA DE CRACKEO DE HASH
- **hashcat** : soporta como 200 hashes
- **CAIN&ABEL**
- **john**     
- **unshadow /etc/passwd /etc/shadow fichero**
  **/etc/shadow** (aparecen los usuarios)  
  $numero$ : --> **funcion hash** que utilizamos para la password  
  $numero$ : [8 y 16 SALT] [12 a 64 password hasheado y salteado]    
  **HASH:SHA512(PASSW + SALT) + SALT**   

- **SHA512** : funcion hash que devuelve una huella    
- **CEWL** : genera un diccionario  a partir de los terminos de una web (usando spidering)   
- **mutator**  
- **chunk**  
- **thehandnoster**  
- **hashat**
- **Herramienta** : hash_identifice (le das un hash y te dice la funcion con la que fue hasheada) y el hash_id          
- **findmyhash** : te busca en una BD si ese hash ha sido roto o no  



