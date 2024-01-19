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
Las hay de Software y Hardware. 
Se les reconoce por una sigla llamada **CVE** y **CVSS**
Ejemplo : CVE-2013-3527
#### Tipos
- **Zero-Day** : Vulnerabilidad encontrada no parcheada, que puede ser utilizada para un posible ataque. Se le asigna un **CWE** y **CVE**. Los hay sin **CWE** y **CVE** por que no interesa en algunos casos.
- **Zerodium** : Intermediario entre empresa y hackers para hacer negocio.
### Amenazas
Se les reconoce por una sigla llamada **CWE**
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
  Ordenadores, telefonos moviles, neveras, teles. Cualquier cosa que tenga 
  connectividad.
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
#### Interrupcón 
Que un servicio deje de funcionar o funcione mal
##### Tipos
- **Dos** : Ataque de sistema sobre sistema. Siempre por inundacion
- **[D]Dos** : Varios Sistemas atacan a un solo sistema. Ejemplo : BotNet
- **Ataque de Negacion de servicio de tipo logico** : Se resulve con un parche, ya que usan las vulnerabilidades para atacar
- **Ataque de Negacion de servicio por Inundacion** : Mas dificil de proteger.
Ejemplos : **Traffic Shapinc**(forma de gestionar la calidad del servicio)
           **QoS**(buscar la calidad)    

## Practica 2


## Practica 3 

