#!/usr/bin/env python3
"""
Advanced Network & Port Scanner v2.0
Industry-ready GUI reconnaissance tool for authorized security assessments.
New: Null scan, FIN scan, Xmas scan, service version detection,
     rate limiting, scope enforcement, CVE expansion, enhanced reporting.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import socket
import time
import json
import csv
import os
import re
import ssl
import platform
import subprocess
import ipaddress
import random
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue

# ── Scapy ─────────────────────────────────────────
try:
    from scapy.all import (
        sr1, sr, IP, TCP, UDP, ICMP, ARP, Ether,
        conf as scapy_conf, RandShort
    )
    scapy_conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ── python-nmap ────────────────────────────────────
try:
    import nmap as nmap_lib
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

# ── requests ──────────────────────────────────────
try:
    import requests as req_lib
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ═══════════════════════════════════════════════════
#  VULNERABILITY / SERVICE DATABASE  (expanded)
# ═══════════════════════════════════════════════════
VULNERABLE_PORTS = {
    # ── Remote Access / Admin ──
    21:    {"service":"FTP",           "risk":"HIGH",    "cve":"CVE-2011-2523",  "desc":"Anonymous FTP login / cleartext credentials"},
    22:    {"service":"SSH",           "risk":"MEDIUM",  "cve":"CVE-2018-10933", "desc":"LibSSH auth bypass; check version for brute-force exposure"},
    23:    {"service":"Telnet",        "risk":"CRITICAL","cve":"CVE-2020-10188", "desc":"Cleartext protocol — credentials fully exposed in transit"},
    512:   {"service":"rexec",         "risk":"CRITICAL","cve":"CVE-1999-0651",  "desc":"Remote execution without any encryption"},
    513:   {"service":"rlogin",        "risk":"CRITICAL","cve":"CVE-1999-0651",  "desc":"Trust-based login; no encryption"},
    514:   {"service":"rsh",           "risk":"CRITICAL","cve":"CVE-1999-0651",  "desc":"Remote shell — no authentication or encryption"},
    3389:  {"service":"RDP",           "risk":"CRITICAL","cve":"CVE-2019-0708",  "desc":"BlueKeep/DejaBlue pre-auth RCE; patch immediately"},
    5900:  {"service":"VNC",           "risk":"HIGH",    "cve":"CVE-2019-15694", "desc":"VNC brute-force / auth bypass risk"},
    5901:  {"service":"VNC-1",         "risk":"HIGH",    "cve":"CVE-2019-15694", "desc":"VNC secondary display — same risk as 5900"},
    4444:  {"service":"Backdoor/MSF",  "risk":"CRITICAL","cve":"N/A",            "desc":"Common Metasploit/reverse-shell listener — investigate immediately"},
    # ── Web ──
    80:    {"service":"HTTP",          "risk":"MEDIUM",  "cve":"CVE-2021-41773", "desc":"Cleartext HTTP; path traversal on Apache 2.4.49/50"},
    443:   {"service":"HTTPS",         "risk":"LOW",     "cve":"CVE-2014-0160",  "desc":"Verify TLS version; Heartbleed on unpatched OpenSSL"},
    8443:  {"service":"HTTPS-Alt",     "risk":"MEDIUM",  "cve":"CVE-2021-22986", "desc":"F5 BIG-IP iControl REST unauthenticated RCE"},
    8888:  {"service":"HTTP-Dev",      "risk":"MEDIUM",  "cve":"CVE-2020-13379", "desc":"Grafana/Jupyter dev server; SSRF / unauth access"},
    7001:  {"service":"WebLogic",      "risk":"CRITICAL","cve":"CVE-2020-14882", "desc":"Oracle WebLogic pre-auth RCE via console path traversal"},
    7002:  {"service":"WebLogic-SSL",  "risk":"CRITICAL","cve":"CVE-2020-14882", "desc":"WebLogic SSL — same RCE vector"},
    # ── Mail ──
    25:    {"service":"SMTP",          "risk":"MEDIUM",  "cve":"CVE-2020-7247",  "desc":"OpenSMTPD RCE; open relay / cleartext auth"},
    110:   {"service":"POP3",          "risk":"HIGH",    "cve":"CVE-2003-0989",  "desc":"Cleartext mail retrieval"},
    143:   {"service":"IMAP",          "risk":"MEDIUM",  "cve":"CVE-2021-38371", "desc":"Cleartext IMAP; STARTTLS stripping attack"},
    465:   {"service":"SMTPS",         "risk":"LOW",     "cve":"N/A",            "desc":"Encrypted SMTP — verify certificate validity"},
    587:   {"service":"SMTP-Sub",      "risk":"MEDIUM",  "cve":"CVE-2020-7247",  "desc":"Mail submission — check for open relay"},
    993:   {"service":"IMAPS",         "risk":"LOW",     "cve":"N/A",            "desc":"Encrypted IMAP — verify certificate validity"},
    995:   {"service":"POP3S",         "risk":"LOW",     "cve":"N/A",            "desc":"Encrypted POP3 — verify certificate validity"},
    # ── Directory / Auth ──
    389:   {"service":"LDAP",          "risk":"HIGH",    "cve":"CVE-2021-44228", "desc":"Anonymous LDAP bind; Log4Shell JNDI LDAP vector"},
    636:   {"service":"LDAPS",         "risk":"MEDIUM",  "cve":"CVE-2021-44228", "desc":"Encrypted LDAP; still a Log4Shell vector"},
    88:    {"service":"Kerberos",      "risk":"MEDIUM",  "cve":"CVE-2020-17049", "desc":"Kerberos Bronze Bit attack; AS-REP roasting"},
    # ── File Sharing ──
    69:    {"service":"TFTP",          "risk":"HIGH",    "cve":"CVE-2008-2161",  "desc":"No authentication — arbitrary file read/write"},
    111:   {"service":"RPCbind",       "risk":"HIGH",    "cve":"CVE-2017-8779",  "desc":"RPC amplification DDoS; NFS enumeration"},
    135:   {"service":"MSRPC",         "risk":"HIGH",    "cve":"CVE-2003-0352",  "desc":"MS-RPC DCOM vulnerability (Blaster worm vector)"},
    137:   {"service":"NetBIOS-NS",    "risk":"HIGH",    "cve":"CVE-2017-0144",  "desc":"EternalBlue recon; NetBIOS enumeration"},
    138:   {"service":"NetBIOS-DGM",   "risk":"HIGH",    "cve":"CVE-2017-0144",  "desc":"NetBIOS datagram service; SMB recon"},
    139:   {"service":"NetBIOS-SSN",   "risk":"HIGH",    "cve":"CVE-2017-0144",  "desc":"SMB/NetBIOS session — EternalBlue exposure"},
    445:   {"service":"SMB",           "risk":"CRITICAL","cve":"CVE-2017-0144",  "desc":"EternalBlue/WannaCry/NotPetya — highest priority patch"},
    2049:  {"service":"NFS",           "risk":"HIGH",    "cve":"CVE-2019-3010",  "desc":"NFS exports without authentication"},
    # ── Databases ──
    1433:  {"service":"MSSQL",         "risk":"HIGH",    "cve":"CVE-2020-0618",  "desc":"SQL Server Reporting Services RCE; weak SA creds"},
    1434:  {"service":"MSSQL-Mon",     "risk":"HIGH",    "cve":"CVE-2002-0649",  "desc":"MSSQL Monitor — SQL Slammer worm vector"},
    1521:  {"service":"Oracle",        "risk":"HIGH",    "cve":"CVE-2012-1675",  "desc":"Oracle TNS listener poisoning"},
    3306:  {"service":"MySQL",         "risk":"HIGH",    "cve":"CVE-2016-6662",  "desc":"MySQL RCE via config overwrite; unauthenticated access"},
    5432:  {"service":"PostgreSQL",    "risk":"HIGH",    "cve":"CVE-2019-9193",  "desc":"PostgreSQL COPY TO/FROM arbitrary file read/write"},
    6379:  {"service":"Redis",         "risk":"CRITICAL","cve":"CVE-2022-0543",  "desc":"Unauthenticated Redis — RCE via Lua sandbox escape"},
    9200:  {"service":"Elasticsearch", "risk":"HIGH",    "cve":"CVE-2015-1427",  "desc":"Unauthenticated Elasticsearch; Groovy script RCE"},
    9300:  {"service":"ES-Transport",  "risk":"HIGH",    "cve":"CVE-2015-1427",  "desc":"Elasticsearch transport — same unauth exposure"},
    27017: {"service":"MongoDB",       "risk":"CRITICAL","cve":"CVE-2013-4650",  "desc":"Unauthenticated MongoDB — direct data access"},
    27018: {"service":"MongoDB-shard", "risk":"CRITICAL","cve":"CVE-2013-4650",  "desc":"MongoDB shard — same unauthenticated access risk"},
    5984:  {"service":"CouchDB",       "risk":"HIGH",    "cve":"CVE-2017-12635", "desc":"CouchDB admin party / remote privilege escalation"},
    # ── Infrastructure ──
    53:    {"service":"DNS",           "risk":"MEDIUM",  "cve":"CVE-2020-1350",  "desc":"SIGRed DNS RCE; DNS amplification / zone transfer"},
    161:   {"service":"SNMP",          "risk":"HIGH",    "cve":"CVE-2017-6736",  "desc":"Default community strings; full device info leakage"},
    162:   {"service":"SNMP-Trap",     "risk":"MEDIUM",  "cve":"CVE-2017-6736",  "desc":"SNMP trap receiver — info leakage"},
    500:   {"service":"IKE/IPSec",     "risk":"MEDIUM",  "cve":"CVE-2019-14899", "desc":"IKE aggressive mode fingerprinting"},
    623:   {"service":"IPMI",          "risk":"CRITICAL","cve":"CVE-2013-4786",  "desc":"IPMI cipher zero — auth bypass; plaintext passwords"},
    1900:  {"service":"UPnP",          "risk":"HIGH",    "cve":"CVE-2020-12695", "desc":"CallStranger UPnP SSRF / DDoS amplification"},
    5353:  {"service":"mDNS",          "risk":"MEDIUM",  "cve":"CVE-2017-14491", "desc":"mDNS reflection; Bonjour info disclosure"},
    # ── Message Brokers / Middleware ──
    5672:  {"service":"AMQP",          "risk":"HIGH",    "cve":"CVE-2021-22117", "desc":"RabbitMQ AMQP — default guest:guest credentials"},
    15672: {"service":"RabbitMQ-Mgmt", "risk":"HIGH",    "cve":"CVE-2021-22117", "desc":"RabbitMQ management UI — default credentials"},
    9092:  {"service":"Kafka",         "risk":"HIGH",    "cve":"CVE-2018-17196", "desc":"Apache Kafka without SASL/TLS — unauthenticated access"},
    2181:  {"service":"ZooKeeper",     "risk":"HIGH",    "cve":"CVE-2019-0201",  "desc":"ZooKeeper information disclosure; no auth by default"},
    61616: {"service":"ActiveMQ",      "risk":"CRITICAL","cve":"CVE-2023-46604", "desc":"ActiveMQ ClassInfo deserialization RCE — critical patch"},
    # ── Container / Cloud ──
    2375:  {"service":"Docker",        "risk":"CRITICAL","cve":"CVE-2019-5736",  "desc":"Docker daemon exposed — full host compromise possible"},
    2376:  {"service":"Docker-TLS",    "risk":"HIGH",    "cve":"CVE-2019-5736",  "desc":"Docker TLS API — verify client cert enforcement"},
    6443:  {"service":"K8s-API",       "risk":"CRITICAL","cve":"CVE-2018-1002105","desc":"Kubernetes API server — anonymous auth / privilege escalation"},
    10250: {"service":"Kubelet",       "risk":"CRITICAL","cve":"CVE-2019-11248", "desc":"Kubelet API unauthenticated — full node RCE"},
    2379:  {"service":"etcd",          "risk":"CRITICAL","cve":"CVE-2020-15106", "desc":"etcd without TLS/auth — all K8s secrets exposed"},
    # ── CI/CD / Dev Tools ──
    8080:  {"service":"HTTP-Alt",      "risk":"MEDIUM",  "cve":"CVE-2021-41773", "desc":"Jenkins/Tomcat/proxy — check for admin panels"},
    50000: {"service":"Jenkins-Agent", "risk":"HIGH",    "cve":"CVE-2020-2100",  "desc":"Jenkins agent UDP discovery — CSRF / RCE chain"},
    4848:  {"service":"GlassFish",     "risk":"HIGH",    "cve":"CVE-2011-0807",  "desc":"GlassFish admin console — default admin:adminadmin"},
    # ── Monitoring ──
    3000:  {"service":"Grafana",       "risk":"HIGH",    "cve":"CVE-2021-43798", "desc":"Grafana path traversal — arbitrary file read"},
    9090:  {"service":"Prometheus",    "risk":"MEDIUM",  "cve":"CVE-2019-3826",  "desc":"Prometheus /metrics — internal data exposure"},
    9100:  {"service":"Node-Exporter", "risk":"MEDIUM",  "cve":"N/A",            "desc":"Prometheus node exporter — system metrics exposed"},
}

# ── Top-1000 common ports list ──────────────────────
_EXTRA = [
    8,9,13,17,19,20,26,37,42,43,49,70,79,
    81,82,83,84,85,102,104,106,109,113,119,123,
    179,199,211,212,222,254,255,264,280,311,366,
    406,407,425,427,444,458,464,465,481,497,515,
    524,541,543,544,545,548,554,555,563,593,616,
    617,625,631,646,648,666,683,687,691,700,705,
    711,714,720,722,726,749,765,777,783,787,800,
    801,808,843,873,880,888,898,900,901,902,903,
    911,912,981,987,990,992,993,995,999,1000,1001,
    1007,1009,1010,1011,1021,1022,1023,1024,1025,
    1026,1027,1028,1029,1030,1110,1234,1720,1723,
    1755,2000,2001,2002,2003,2004,2005,2006,2007,
    2008,2009,2010,2100,2103,2105,2107,2121,2161,
    2222,2301,2381,2383,2401,2601,2717,2869,2967,
    3001,3128,3222,3260,3310,3322,3333,3456,3512,
    3632,3690,3703,3737,3784,3800,3801,3809,3826,
    3869,3878,3889,3945,3971,3995,3998,4000,4001,
    4002,4003,4004,4005,4006,4045,4125,4129,4224,
    4242,4279,4321,4343,4443,4445,4446,4449,4550,
    4567,4662,4899,4900,4998,5000,5001,5002,5003,
    5004,5009,5030,5033,5050,5051,5054,5060,5061,
    5080,5087,5100,5101,5102,5120,5190,5200,5214,
    5221,5222,5225,5226,5269,5280,5298,5357,5405,
    5414,5431,5440,5500,5510,5544,5550,5555,5560,
    5566,5631,5633,5666,5800,5814,5859,5902,6000,
    6001,6002,6003,6004,6005,6006,6007,6009,6025,
    6059,6100,6101,6106,6112,6123,6129,6156,6346,
    6389,6502,6510,6543,6547,6565,6566,6567,6580,
    6646,6666,6667,6668,6669,6689,6692,6699,6779,
    6788,6789,6792,6839,6881,6901,6969,7000,7004,
    7007,7019,7025,7070,7100,7103,7106,7200,7402,
    7435,7443,7496,7512,7625,7627,7676,7741,7777,
    7778,7800,7911,7937,7938,7999,8000,8001,8002,
    8007,8008,8009,8010,8011,8021,8022,8031,8042,
    8045,8088,8089,8093,8099,8180,8181,8192,8193,
    8194,8200,8222,8254,8290,8291,8292,8300,8333,
    8383,8400,8402,8500,8600,8649,8651,8652,8654,
    8701,8800,8873,8899,8994,9000,9001,9002,9003,
    9009,9010,9011,9040,9050,9071,9080,9081,9091,
    9099,9101,9102,9103,9110,9111,9290,9415,9418,
    9485,9500,9502,9503,9535,9575,9593,9594,9595,
    9618,9666,9876,9877,9878,9898,9900,9917,9929,
    9943,9944,9968,9998,9999,10000,10001,10002,
    10003,10004,10009,10010,10012,10024,10025,10082,
    10180,10215,10243,10566,10616,10617,10621,10626,
    10628,10629,10778,11110,11111,11967,12000,12174,
    12265,12345,13456,13722,13782,13783,14238,14441,
    14442,15000,15002,15003,15004,15660,15742,16000,
    16001,16012,16016,16018,16080,16113,16992,16993,
    17877,17988,18040,18101,18988,19101,19283,19315,
    19350,19780,19801,19842,20005,20031,20221,20222,
    20828,21571,22939,23502,24444,24800,25734,25735,
    26214,27000,27352,27353,27355,27356,27715,28201,
    30000,30718,30951,31038,31337,32768,32769,32770,
    32771,32772,32773,32774,32775,32776,32777,32778,
    32779,32780,32781,32782,32783,32784,32785,33354,
    33899,34571,34572,34573,35500,38292,40193,40911,
    41511,42510,44176,44442,44443,44501,45100,48080,
    49152,49153,49154,49155,49156,49157,49158,49159,
    49160,49161,49163,49165,49167,49175,49176,49400,
    49999,50001,50002,50003,50006,50300,50389,50500,
    50636,50800,51103,51493,52673,52822,52848,52869,
    54045,54328,55055,55056,55555,55600,56737,56738,
    57294,57797,58080,60020,60443,61532,61900,62078,
    63331,64623,64680,65000,65129,65389,
]
COMMON_PORTS = sorted(set(list(VULNERABLE_PORTS.keys()) + _EXTRA))

TOP_100_PORTS = [
    21,22,23,25,53,69,80,88,110,111,135,137,138,139,
    143,161,389,443,445,465,512,513,514,587,623,636,
    993,995,1433,1521,1900,2049,2181,2375,2376,2379,
    3000,3306,3389,4444,4848,5432,5672,5900,5984,
    6379,6443,7001,8080,8443,8888,9090,9092,9200,
    9300,10250,15672,27017,27018,50000,61616,
]


# ═══════════════════════════════════════════════════
#  SERVICE VERSION DETECTION PROBES
# ═══════════════════════════════════════════════════
SERVICE_PROBES = {
    # ── Web ──────────────────────────────────────────────────────────────────
    "HTTP": {
        "ports": [80,8080,8000,8888,3000,8081,8082,9080,8800,8180,8090],
        "probe": b"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (compatible; SecurityScanner/2.0)\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        "regex": [
            (r"Server:\s*(.+)",        "server"),
            (r"X-Powered-By:\s*(.+)", "powered_by"),
            (r"HTTP/[\d.]+ (\d+)",    "http_status"),
            (r"X-Generator:\s*(.+)",  "generator"),
            (r"X-AspNet-Version:\s*(.+)", "aspnet"),
        ]
    },
    "HTTPS": {
        "ports": [443,8443,9443,4443],
        "probe": b"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
        "regex": [
            (r"Server:\s*(.+)",       "server"),
            (r"HTTP/[\d.]+ (\d+)",   "http_status"),
        ]
    },
    # ── Remote Access ─────────────────────────────────────────────────────────
    "SSH": {
        "ports": [22,2222,22222],
        "probe": None,
        "regex": [
            (r"SSH-([\d.]+)-(.+)",   "version"),
            (r"OpenSSH[_\s]([\d.]+)","openssh_ver"),
        ]
    },
    "FTP": {
        "ports": [21,990],
        "probe": None,
        "regex": [
            (r"220[- ](.+)",         "version"),
            (r"vsFTPd ([\d.]+)",     "vsftpd"),
            (r"ProFTPD ([\d.]+)",    "proftpd"),
        ]
    },
    "Telnet": {
        "ports": [23],
        "probe": b"\xff\xfd\x03\xff\xfb\x18\xff\xfb\x1f",   # DO/WILL negotiation
        "regex": [
            (r"login:\s*(.+)",       "prompt"),
            (r"([A-Za-z]+\s+[\d.]+) login", "os_hint"),
        ]
    },
    "RDP": {
        "ports": [3389],
        "probe": b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00",
        "regex": [(r"(.{4,})",        "banner")]
    },
    "VNC": {
        "ports": [5900,5901,5902],
        "probe": None,
        "regex": [(r"RFB ([\d.]+)",  "version")]
    },
    # ── Mail ─────────────────────────────────────────────────────────────────
    "SMTP": {
        "ports": [25,587,2525],
        "probe": b"EHLO scanner.local\r\n",
        "regex": [
            (r"220[- ](.+)",         "banner"),
            (r"Postfix|Exim|Sendmail|OpenSMTPD|Exchange", "mta"),
        ]
    },
    "POP3": {
        "ports": [110],
        "probe": None,
        "regex": [(r"\+OK (.+)",     "version")]
    },
    "IMAP": {
        "ports": [143],
        "probe": b"a001 CAPABILITY\r\n",
        "regex": [
            (r"\* OK (.+)",          "banner"),
            (r"IMAP4rev\d",          "proto"),
        ]
    },
    # ── Databases ────────────────────────────────────────────────────────────
    "MySQL": {
        "ports": [3306],
        "probe": None,
        "regex": [
            (r"([\d]+\.[\d]+\.[\d]+[-\w]*)", "version"),
            (r"mysql_native_password|caching_sha2_password", "auth_plugin"),
        ]
    },
    "PostgreSQL": {
        "ports": [5432],
        # Startup message: protocol 3.0, user=postgres
        "probe": b"\x00\x00\x00\x08\x00\x03\x00\x00",
        "regex": [
            (r"FATAL:\s*(.+)",       "error"),
            (r"PostgreSQL ([\d.]+)", "version"),
        ]
    },
    "Redis": {
        "ports": [6379],
        "probe": b"*1\r\n$4\r\nINFO\r\n",
        "regex": [
            (r"redis_version:([\d.]+)", "version"),
            (r"os:(.+)",             "os"),
            (r"tcp_port:(\d+)",      "port_confirm"),
        ]
    },
    "MongoDB": {
        "ports": [27017,27018,27019],
        # MongoDB wire protocol: OP_QUERY isMaster
        "probe": (b"\x41\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00"
                  b"\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00"
                  b"\x00\x00\x00\x00\xff\xff\xff\xff"
                  b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"),
        "regex": [
            (r'"version"\s*:\s*"([\d.]+)"', "version"),
            (r"ismaster|isMaster",   "role"),
        ]
    },
    "MSSQL": {
        "ports": [1433],
        # SQL Server pre-login packet
        "probe": b"\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00",
        "regex": [
            (r"([\d]+\.[\d]+\.[\d]+\.[\d]+)", "version"),
        ]
    },
    "Elasticsearch": {
        "ports": [9200],
        "probe": b"GET / HTTP/1.0\r\n\r\n",
        "regex": [
            (r'"number"\s*:\s*"([\d.]+)"', "version"),
            (r'"cluster_name"\s*:\s*"([^"]+)"', "cluster"),
            (r'"name"\s*:\s*"([^"]+)"', "node_name"),
        ]
    },
    "CouchDB": {
        "ports": [5984],
        "probe": b"GET / HTTP/1.0\r\n\r\n",
        "regex": [
            (r'"version"\s*:\s*"([\d.]+)"', "version"),
            (r'"couchdb"\s*:\s*"([^"]+)"',  "welcome"),
        ]
    },
    # ── Infrastructure / Network ─────────────────────────────────────────────
    "SNMP": {
        "ports": [161],
        "probe": None,   # UDP — handled in udp_scan
        "regex": []
    },
    "SMB": {
        "ports": [445,139],
        # SMB1 negotiate
        "probe": (b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00"
                  b"\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                  b"\x00\x00\xff\xff\xff\xfe\x00\x00\x00\x00\x00\x62\x00"
                  b"\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50"
                  b"\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c"
                  b"\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e"
                  b"\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b"
                  b"\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02"
                  b"\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41"
                  b"\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c"
                  b"\x4d\x20\x30\x2e\x31\x32\x00"),
        "regex": [(r"SMB|CIFS|Windows",  "protocol")]
    },
    # ── Container / Cloud ────────────────────────────────────────────────────
    "Docker": {
        "ports": [2375,2376],
        "probe": b"GET /version HTTP/1.0\r\n\r\n",
        "regex": [
            (r'"Version"\s*:\s*"([\d.]+)"',    "docker_version"),
            (r'"KernelVersion"\s*:\s*"([^"]+)"',"kernel"),
            (r'"Os"\s*:\s*"([^"]+)"',           "os"),
        ]
    },
    "Kubernetes": {
        "ports": [6443,8080],
        "probe": b"GET /version HTTP/1.0\r\n\r\n",
        "regex": [
            (r'"gitVersion"\s*:\s*"([^"]+)"', "k8s_version"),
        ]
    },
    "etcd": {
        "ports": [2379],
        "probe": b"GET /version HTTP/1.0\r\n\r\n",
        "regex": [
            (r'"etcdserver"\s*:\s*"([^"]+)"', "version"),
        ]
    },
    # ── Message Brokers ───────────────────────────────────────────────────────
    "RabbitMQ": {
        "ports": [5672],
        "probe": b"AMQP\x00\x00\x09\x01",
        "regex": [(r"AMQP|RabbitMQ",  "protocol")]
    },
    "ActiveMQ": {
        "ports": [61616],
        "probe": b"ACTIVEMQ\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "regex": [(r"ActiveMQ ([\d.]+)", "version")]
    },
    # ── Monitoring ────────────────────────────────────────────────────────────
    "Grafana": {
        "ports": [3000],
        "probe": b"GET /api/health HTTP/1.0\r\n\r\n",
        "regex": [
            (r'"version"\s*:\s*"([\d.]+)"', "version"),
            (r'"database"\s*:\s*"([^"]+)"', "db_status"),
        ]
    },
    "Prometheus": {
        "ports": [9090],
        "probe": b"GET /api/v1/status/buildinfo HTTP/1.0\r\n\r\n",
        "regex": [(r'"version"\s*:\s*"([\d.]+)"', "version")]
    },
}


# ═══════════════════════════════════════════════════
#  SCAN TECHNIQUE DESCRIPTIONS  (shown in UI)
# ═══════════════════════════════════════════════════
SCAN_DESCRIPTIONS = {
    "SYN":   "SYN (Stealth) — Sends SYN; RST on SYN-ACK. Never completes handshake. Fast, low-noise.",
    "TCP":   "TCP Connect — Full 3-way handshake. No root required. Logged by target.",
    "NULL":  "NULL Scan — Sends packet with NO flags set. Open ports drop packet (no response). Evades some stateless ACL rules.",
    "FIN":   "FIN Scan — Sends FIN flag only. Open ports silently drop packet per RFC 793. Closed ports respond with RST.",
    "XMAS":  "Xmas Scan — Sets FIN+PSH+URG flags ('lit up'). Open ports drop, closed ports RST. Named for blinking Christmas tree.",
    "ACK":   "ACK Scan — Maps firewall rules; determines filtered vs unfiltered ports. Does NOT detect open/closed.",
    "WIN":   "Window Scan — Variant of ACK scan; examines TCP window field to infer port state on some OS.",
}


# ═══════════════════════════════════════════════════
#  SCANNER ENGINE
# ═══════════════════════════════════════════════════
class ScannerEngine:
    def __init__(self, log_callback=None, progress_callback=None):
        self.log_callback = log_callback
        self.progress_callback = progress_callback
        self.results = {}
        self._stop_event = threading.Event()

    def stop(self):   self._stop_event.set()
    def reset(self):  self._stop_event.clear(); self.results = {}

    def log(self, msg, level="INFO"):
        if self.log_callback: self.log_callback(msg, level)

    def set_progress(self, val):
        if self.progress_callback: self.progress_callback(val)

    # ────────────────────────────────────────────────
    #  HOST DISCOVERY
    # ────────────────────────────────────────────────
    def ping_host(self, host):
        param = "-n" if platform.system().lower() == "windows" else "-c"
        try:
            r = subprocess.run(["ping", param, "1", "-W", "1", host],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
            return r.returncode == 0
        except Exception:
            return False

    def scapy_ping(self, host):
        if not SCAPY_AVAILABLE:
            return self.ping_host(host)
        try:
            pkt = sr1(IP(dst=host)/ICMP(), timeout=1, verbose=0)
            return pkt is not None
        except Exception:
            return self.ping_host(host)

    def discover_network(self, cidr):
        live = []
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            hosts = list(net.hosts())
            total = len(hosts)
            self.log(f"[*] Network discovery on {cidr} — {total} addresses", "INFO")
            for i, host in enumerate(hosts):
                if self._stop_event.is_set(): break
                h = str(host)
                if self.scapy_ping(h):
                    live.append(h)
                    self.log(f"[+] Host UP: {h}", "SUCCESS")
                self.set_progress(int((i+1)/total*100))
        except Exception as e:
            self.log(f"[!] Discovery error: {e}", "ERROR")
        return live

    # ────────────────────────────────────────────────
    #  SCAN TECHNIQUES
    # ────────────────────────────────────────────────
    def tcp_connect_scan(self, host, port, timeout=1.0):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            r = s.connect_ex((host, port))
            s.close()
            return "open" if r == 0 else None
        except Exception:
            return None

    def syn_scan(self, host, port, timeout=1.0):
        if not SCAPY_AVAILABLE:
            return self.tcp_connect_scan(host, port, timeout)
        try:
            pkt = sr1(IP(dst=host)/TCP(sport=RandShort(), dport=port, flags="S"),
                      timeout=timeout, verbose=0)
            if pkt and pkt.haslayer(TCP):
                flags = pkt[TCP].flags
                if flags & 0x12 == 0x12:   # SYN-ACK
                    sr1(IP(dst=host)/TCP(dport=port, flags="R"), timeout=0.1, verbose=0)
                    return "open"
                elif flags & 0x04:          # RST
                    return None
            return None
        except Exception:
            return self.tcp_connect_scan(host, port, timeout)

    def null_scan(self, host, port, timeout=1.0):
        """
        RFC 793 NULL scan — no TCP flags set.
        OPEN  → no response (packet silently dropped)
        CLOSED → RST+ACK
        FILTERED → no response (indistinguishable from open)
        Works best against Linux/Unix targets; Windows returns RST for all.
        """
        if not SCAPY_AVAILABLE:
            self.log("[!] Null scan requires Scapy (root). Falling back to TCP Connect.", "WARNING")
            return self.tcp_connect_scan(host, port, timeout)
        try:
            pkt = sr1(IP(dst=host)/TCP(sport=RandShort(), dport=port, flags=0),
                      timeout=timeout, verbose=0)
            if pkt is None:
                return "open|filtered"     # No response = open or filtered
            if pkt.haslayer(TCP) and pkt[TCP].flags & 0x04:
                return None                # RST = definitely closed
            if pkt.haslayer(ICMP):
                return "filtered"          # ICMP unreachable = filtered
            return "open|filtered"
        except Exception:
            return None

    def fin_scan(self, host, port, timeout=1.0):
        """
        RFC 793 FIN scan.
        OPEN  → no response
        CLOSED → RST
        Good for bypassing non-stateful packet filters.
        """
        if not SCAPY_AVAILABLE:
            return self.tcp_connect_scan(host, port, timeout)
        try:
            pkt = sr1(IP(dst=host)/TCP(sport=RandShort(), dport=port, flags="F"),
                      timeout=timeout, verbose=0)
            if pkt is None:
                return "open|filtered"
            if pkt.haslayer(TCP) and pkt[TCP].flags & 0x04:
                return None
            if pkt.haslayer(ICMP):
                return "filtered"
            return "open|filtered"
        except Exception:
            return None

    def xmas_scan(self, host, port, timeout=1.0):
        """
        Xmas scan — FIN + PSH + URG flags set.
        Same RFC 793 semantics as NULL and FIN scans.
        Named because all bits 'light up like a Christmas tree'.
        """
        if not SCAPY_AVAILABLE:
            return self.tcp_connect_scan(host, port, timeout)
        try:
            pkt = sr1(IP(dst=host)/TCP(sport=RandShort(), dport=port, flags="FPU"),
                      timeout=timeout, verbose=0)
            if pkt is None:
                return "open|filtered"
            if pkt.haslayer(TCP) and pkt[TCP].flags & 0x04:
                return None
            if pkt.haslayer(ICMP):
                return "filtered"
            return "open|filtered"
        except Exception:
            return None

    def ack_scan(self, host, port, timeout=1.0):
        """
        ACK scan — maps firewall ruleset.
        Returns 'unfiltered' (RST received) or 'filtered' (no response / ICMP unreachable).
        Does NOT determine open/closed — use for firewall mapping only.
        """
        if not SCAPY_AVAILABLE:
            return None
        try:
            pkt = sr1(IP(dst=host)/TCP(sport=RandShort(), dport=port, flags="A"),
                      timeout=timeout, verbose=0)
            if pkt is None:
                return "filtered"
            if pkt.haslayer(TCP) and pkt[TCP].flags & 0x04:
                return "unfiltered"
            if pkt.haslayer(ICMP):
                return "filtered"
            return "filtered"
        except Exception:
            return None

    def window_scan(self, host, port, timeout=1.0):
        """
        TCP Window scan — ACK probe examining TCP window field.
        Non-zero window → open; zero window → closed. OS-dependent accuracy.
        """
        if not SCAPY_AVAILABLE:
            return None
        try:
            pkt = sr1(IP(dst=host)/TCP(sport=RandShort(), dport=port, flags="A"),
                      timeout=timeout, verbose=0)
            if pkt and pkt.haslayer(TCP):
                if pkt[TCP].window > 0:
                    return "open"
                else:
                    return None
            return None
        except Exception:
            return None

    def udp_scan(self, host, port, timeout=2.0):
        if not SCAPY_AVAILABLE:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(timeout)
                s.sendto(b"\x00"*8, (host, port))
                s.recvfrom(1024)
                s.close()
                return "open"
            except socket.timeout:
                return "open|filtered"
            except Exception:
                return None
        try:
            pkt = sr1(IP(dst=host)/UDP(dport=port), timeout=timeout, verbose=0)
            if pkt is None:
                return "open|filtered"
            if pkt.haslayer(UDP):
                return "open"
            return None
        except Exception:
            return None

    # ────────────────────────────────────────────────
    #  SERVICE VERSION DETECTION
    # ────────────────────────────────────────────────
    def detect_service_version(self, host, port, timeout=3.0):
        """
        Multi-probe service version detection with:
        - TLS certificate inspection (CN, expiry, issuer)
        - 30+ service-specific protocol probes
        - Multi-field regex extraction per service
        - Graceful fallback to raw banner grab
        Returns a dict of extracted fields.
        """
        TLS_PORTS = {443, 8443, 9443, 4443, 636, 993, 995, 465, 6443, 2376}
        info = {
            "banner": "", "version": "", "server": "",
            "http_status": "", "tls": False,
            "tls_cn": "", "tls_expire": "", "tls_issuer": "",
        }

        # ── TLS inspection ───────────────────────────
        if port in TLS_PORTS:
            info["tls"] = True
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=timeout) as raw:
                    with ctx.wrap_socket(raw, server_hostname=host) as tls_sock:
                        cert = tls_sock.getpeercert(binary_form=False) or {}
                        # Extract cert metadata
                        subj   = dict(x[0] for x in cert.get("subject",   []))
                        issuer = dict(x[0] for x in cert.get("issuer",    []))
                        info["tls_cn"]     = subj.get("commonName",    "")
                        info["tls_expire"] = cert.get("notAfter",      "")
                        info["tls_issuer"] = issuer.get("organizationName", "")
                        # Send HTTP probe over TLS
                        tls_sock.sendall(
                            b"GET / HTTP/1.1\r\nHost: " + host.encode() +
                            b"\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                        )
                        data = self._recv_all(tls_sock, 4096, timeout)
                        text = data.decode(errors="replace")
                        for pat, key in [
                            (r"Server:\s*(.+)",         "server"),
                            (r"X-Powered-By:\s*(.+)",   "powered_by"),
                            (r"HTTP/[\d.]+ (\d+)",      "http_status"),
                            (r"X-Generator:\s*(.+)",    "generator"),
                        ]:
                            m = re.search(pat, text, re.IGNORECASE)
                            if m and not info.get(key):
                                info[key] = m.group(1).strip()
                        info["banner"] = text[:250]
                        return info
            except Exception:
                pass  # fall through to TCP probe

        # ── Find matching probe config ───────────────
        probe_bytes  = None
        probe_regex  = []
        matched_name = ""
        for svc_name, cfg in SERVICE_PROBES.items():
            if port in cfg["ports"]:
                probe_bytes  = cfg["probe"]
                probe_regex  = cfg["regex"]
                matched_name = svc_name
                break

        # ── TCP probe + banner read ──────────────────
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))

            if probe_bytes:
                # Substitute {host} placeholder if present
                if b"{host}" in probe_bytes:
                    probe_bytes = probe_bytes.replace(b"{host}", host.encode())
                s.sendall(probe_bytes)
            # For listen-first services (SSH, FTP, etc.) read immediately
            raw  = self._recv_all(s, 8192, min(timeout, 3.0))
            s.close()

            text = raw.decode(errors="replace").strip()
            info["banner"] = text[:350]

            # Apply all regexes for this service
            for pattern, key in probe_regex:
                m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
                if m and not info.get(key):
                    info[key] = m.group(1).strip() if m.lastindex else m.group(0).strip()

            # Generic version heuristics if nothing matched yet
            if not info.get("version") and not info.get("server"):
                # Look for SemVer-like strings
                m = re.search(r"v?([\d]+\.[\d]+\.[\d]+[\w.-]*)", text)
                if m:
                    info["version"] = m.group(1)

        except ConnectionRefusedError:
            pass
        except Exception:
            pass

        return info

    def _recv_all(self, sock, max_bytes: int, timeout: float) -> bytes:
        """Read from socket until max_bytes, timeout, or connection close."""
        raw      = b""
        deadline = time.time() + timeout
        try:
            sock.settimeout(max(0.1, timeout * 0.3))
            while time.time() < deadline and len(raw) < max_bytes:
                try:
                    chunk = sock.recv(min(4096, max_bytes - len(raw)))
                    if not chunk:
                        break
                    raw += chunk
                except socket.timeout:
                    break
        except Exception:
            pass
        return raw

    # ────────────────────────────────────────────────
    #  OS FINGERPRINTING
    # ────────────────────────────────────────────────
    def os_fingerprint(self, host):
        ttl_os = {
            (1,   64): "Linux/Android/Unix",
            (65, 128): "Windows",
            (129,255): "Cisco/Network Device",
        }
        if SCAPY_AVAILABLE:
            try:
                pkt = sr1(IP(dst=host)/ICMP(), timeout=2, verbose=0)
                if pkt and pkt.haslayer(IP):
                    ttl = pkt[IP].ttl
                    for (lo, hi), name in ttl_os.items():
                        if lo <= ttl <= hi:
                            return f"{name} (TTL={ttl})"
                    return f"Unknown (TTL={ttl})"
            except Exception:
                pass
        # TCP-based fallback: check open ports for OS hints
        if self.tcp_connect_scan(host, 445, 0.5):
            return "Likely Windows (SMB open)"
        if self.tcp_connect_scan(host, 22, 0.5):
            return "Likely Linux/Unix (SSH open)"
        return "Unknown"

    def resolve_hostname(self, host):
        try:   return socket.gethostbyaddr(host)[0]
        except: return host

    def get_mac(self, host):
        if not SCAPY_AVAILABLE: return "N/A"
        try:
            ans = sr1(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=host), timeout=2, verbose=0)
            if ans: return ans[Ether].src
        except Exception:
            pass
        return "N/A"

    # ────────────────────────────────────────────────
    #  RATE-LIMITED SCAN LOOP
    # ────────────────────────────────────────────────
    def _rate_limited_scan(self, scan_fn, host, ports, max_threads, pps_limit, randomize):
        """
        Concurrent scan with optional packets-per-second throttle and port randomisation.
        pps_limit=0 means unlimited.
        """
        if randomize:
            ports = list(ports)
            random.shuffle(ports)

        open_ports = []
        total = len(ports)
        done = 0
        interval = (1.0 / pps_limit) if pps_limit > 0 else 0

        with ThreadPoolExecutor(max_workers=max_threads) as ex:
            futures = {}
            last_submit = time.time()
            for p in ports:
                if self._stop_event.is_set(): break
                if interval > 0:
                    elapsed = time.time() - last_submit
                    if elapsed < interval:
                        time.sleep(interval - elapsed)
                    last_submit = time.time()
                futures[ex.submit(scan_fn, host, p)] = p

            for fut in as_completed(futures):
                if self._stop_event.is_set(): break
                done += 1
                result = fut.result()
                port = futures[fut]
                if result:
                    open_ports.append((port, result))
                self.set_progress(int(done / total * 100))

        return sorted(open_ports)

    # ────────────────────────────────────────────────
    #  MAIN SCAN ORCHESTRATOR
    # ────────────────────────────────────────────────
    def scan_host(self, host, ports, scan_type="SYN", max_threads=200,
                  timeout=1.0, udp=False, version_detect=True,
                  pps_limit=0, randomize_ports=False):
        self.reset()

        scan_fns = {
            "SYN":  lambda h, p: self.syn_scan(h, p, timeout),
            "TCP":  lambda h, p: self.tcp_connect_scan(h, p, timeout),
            "NULL": lambda h, p: self.null_scan(h, p, timeout),
            "FIN":  lambda h, p: self.fin_scan(h, p, timeout),
            "XMAS": lambda h, p: self.xmas_scan(h, p, timeout),
            "ACK":  lambda h, p: self.ack_scan(h, p, timeout),
            "WIN":  lambda h, p: self.window_scan(h, p, timeout),
        }

        host_info = {
            "host": host,
            "hostname": "",
            "mac": "N/A",
            "os": "Unknown",
            "open_ports": [],
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_type": scan_type,
            "total_ports_scanned": len(ports),
        }

        self.log(f"[*] Resolving {host}…", "INFO")
        host_info["hostname"] = self.resolve_hostname(host)

        self.log(f"[*] OS fingerprinting…", "INFO")
        host_info["os"] = self.os_fingerprint(host)
        self.log(f"[+] OS guess: {host_info['os']}", "SUCCESS")

        try:
            if ipaddress.ip_address(host).is_private:
                host_info["mac"] = self.get_mac(host)
        except Exception:
            pass

        scan_fn = scan_fns.get(scan_type, scan_fns["SYN"])
        throttle_str = f" @ {pps_limit}pps" if pps_limit > 0 else " (unlimited)"
        rand_str     = " [randomised]" if randomize_ports else ""
        self.log(f"[*] {scan_type} scan — {len(ports)} ports{throttle_str}{rand_str}", "INFO")

        if scan_type in ("NULL","FIN","XMAS") and not SCAPY_AVAILABLE:
            self.log("[!] Scapy not available — falling back to TCP Connect for this scan type.", "WARNING")

        open_results = self._rate_limited_scan(
            scan_fn, host, ports, max_threads, pps_limit, randomize_ports
        )

        # ── Enrich each result ──
        for port, state in open_results:
            if self._stop_event.is_set(): break
            self.log(f"[+] TCP {port}/{state}", "SUCCESS")

            # Version detection
            svc_info = {}
            if version_detect and state in ("open", "open|filtered", "unfiltered"):
                svc_info = self.detect_service_version(host, port, timeout=min(timeout*2, 4.0))

            vuln = VULNERABLE_PORTS.get(port)
            service_name = (vuln["service"] if vuln
                            else svc_info.get("server", "") or self._guess_service(port))

            banner_parts = []
            if svc_info.get("server"):   banner_parts.append(f"Server: {svc_info['server']}")
            if svc_info.get("version"):  banner_parts.append(f"Ver: {svc_info['version']}")
            if svc_info.get("http_status"): banner_parts.append(f"HTTP {svc_info['http_status']}")
            if svc_info.get("tls"):      banner_parts.append("TLS✓")
            if svc_info.get("tls_cn"):   banner_parts.append(f"CN={svc_info['tls_cn']}")
            if not banner_parts and svc_info.get("banner"):
                banner_parts.append(svc_info["banner"][:120])
            banner = "  |  ".join(banner_parts)

            port_data = {
                "port":       port,
                "protocol":   "tcp",
                "state":      state,
                "service":    service_name,
                "banner":     banner,
                "risk":       vuln["risk"] if vuln else "INFO",
                "cve":        vuln["cve"]  if vuln else "N/A",
                "vuln_desc":  vuln["desc"] if vuln else "No known critical vulnerability in database",
                "tls":        svc_info.get("tls", False),
                "tls_cn":     svc_info.get("tls_cn", ""),
                "tls_expire": svc_info.get("tls_expire", ""),
            }
            host_info["open_ports"].append(port_data)
            if vuln:
                self.log(f"   ⚠  {service_name} [{vuln['risk']}] {vuln['cve']}", vuln["risk"])

        # ── UDP ──
        if udp and not self._stop_event.is_set():
            self.log("[*] UDP scan on top UDP ports…", "INFO")
            udp_targets = [53,67,68,69,123,137,138,161,162,500,514,520,623,1900,5353]
            for p in udp_targets:
                if self._stop_event.is_set(): break
                st = self.udp_scan(host, p, timeout)
                if st:
                    vuln = VULNERABLE_PORTS.get(p)
                    svc  = vuln["service"] if vuln else self._guess_service(p)
                    self.log(f"[+] UDP {p} {st}", "UDP")
                    host_info["open_ports"].append({
                        "port": p, "protocol": "udp", "state": st,
                        "service": svc, "banner": "",
                        "risk":      vuln["risk"] if vuln else "INFO",
                        "cve":       vuln["cve"]  if vuln else "N/A",
                        "vuln_desc": vuln["desc"] if vuln else "",
                        "tls": False, "tls_cn": "", "tls_expire": "",
                    })

        self.results[host] = host_info
        tcp_open = [p for p in host_info["open_ports"] if p["protocol"] == "tcp"]
        udp_open = [p for p in host_info["open_ports"] if p["protocol"] == "udp"]
        self.log(
            f"[✔] Scan complete — {len(tcp_open)} TCP  {len(udp_open)} UDP  "
            f"open across {len(host_info['open_ports'])} total", "SUCCESS"
        )
        return host_info

    def _guess_service(self, port):
        try:   return socket.getservbyport(port, "tcp")
        except: return f"unknown-{port}"


# ═══════════════════════════════════════════════════
#  REPORT GENERATOR
# ═══════════════════════════════════════════════════
class ReportGenerator:

    RISK_COLOUR = {
        "CRITICAL": "#ff2d55", "HIGH": "#ff9500",
        "MEDIUM": "#ffcc00",   "LOW":  "#34c759",
        "INFO":   "#636366",   "UDP":  "#5ac8fa",
    }

    @classmethod
    def generate_html(cls, results: dict) -> str:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rc = cls.RISK_COLOUR
        rows = ""
        totals = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}

        for host, data in results.items():
            for p in data["open_ports"]:
                risk  = p["risk"]
                col   = rc.get(risk, "#636366")
                badge = (f'<span style="background:{col};color:#000;padding:2px 8px;'
                         f'border-radius:4px;font-size:11px;font-weight:700">{risk}</span>')
                tls_badge = ('<span style="background:#34c759;color:#000;padding:1px 6px;'
                             'border-radius:3px;font-size:10px">TLS✓</span>'
                             if p.get("tls") else "")
                rows += f"""
                <tr>
                  <td>{host}</td><td>{data.get('hostname','')}</td>
                  <td><b>{p['port']}</b></td><td>{p['protocol'].upper()}</td>
                  <td>{p['service']} {tls_badge}</td><td>{p['state']}</td>
                  <td>{badge}</td>
                  <td style="font-size:11px;color:#aaa">{p['cve']}</td>
                  <td style="font-size:11px">{p['vuln_desc']}</td>
                  <td style="font-size:10px;max-width:220px;word-break:break-all;color:#888">{p['banner'][:100]}</td>
                </tr>"""
                if risk in totals: totals[risk] += 1

        host_sections = ""
        for host, data in results.items():
            tcp_c = len([p for p in data["open_ports"] if p["protocol"]=="tcp"])
            udp_c = len([p for p in data["open_ports"] if p["protocol"]=="udp"])
            host_sections += f"""
            <div class="host-card">
              <div class="host-title">🖥 {host}</div>
              <div class="host-meta">
                Hostname: <b>{data.get('hostname','')}</b> &nbsp;|&nbsp;
                OS: <b>{data.get('os','?')}</b> &nbsp;|&nbsp;
                MAC: <b>{data.get('mac','N/A')}</b> &nbsp;|&nbsp;
                Scan: <b>{data.get('scan_type','')}</b> &nbsp;|&nbsp;
                TCP open: <b>{tcp_c}</b> &nbsp;|&nbsp;
                UDP open: <b>{udp_c}</b> &nbsp;|&nbsp;
                Ports scanned: <b>{data.get('total_ports_scanned',0)}</b> &nbsp;|&nbsp;
                Time: <b>{data.get('scan_time','')}</b>
              </div>
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Advanced Port Scanner — Report</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600;800&display=swap');
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Inter',sans-serif;background:#080808;color:#e0e0e0;padding:40px}}
h1{{font-size:30px;font-weight:800;letter-spacing:-1.5px;color:#fff}}
.sub{{color:#555;font-size:13px;margin-bottom:36px;margin-top:4px}}
.cards{{display:flex;gap:14px;margin-bottom:36px;flex-wrap:wrap}}
.card{{flex:1;min-width:130px;background:#111;border-radius:14px;padding:22px 18px;border-top:3px solid}}
.card.crit{{border-color:#ff2d55}}.card.high{{border-color:#ff9500}}
.card.med{{border-color:#ffcc00}}.card.low{{border-color:#34c759}}
.card-num{{font-size:40px;font-weight:800;line-height:1}}
.card.crit .card-num{{color:#ff2d55}}.card.high .card-num{{color:#ff9500}}
.card.med .card-num{{color:#ffcc00}}.card.low .card-num{{color:#34c759}}
.card-label{{font-size:11px;color:#555;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;margin-top:6px}}
.host-card{{background:#111;border-radius:10px;padding:16px 20px;margin-bottom:12px;border-left:3px solid #00d4ff}}
.host-title{{font-size:16px;font-weight:700;color:#fff;margin-bottom:6px}}
.host-meta{{font-size:12px;color:#666;line-height:1.8}}
table{{width:100%;border-collapse:collapse;background:#111;border-radius:12px;overflow:hidden;font-size:12.5px;margin-top:24px}}
thead{{background:#0a0a0a}}
th{{padding:11px 13px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:#555;font-weight:700}}
td{{padding:10px 13px;border-bottom:1px solid #1a1a1a;vertical-align:middle}}
tr:hover td{{background:#161616}}
h2{{font-size:16px;font-weight:700;color:#888;margin-top:32px;letter-spacing:1px;text-transform:uppercase}}
footer{{margin-top:48px;text-align:center;color:#333;font-size:11px;padding-top:20px;border-top:1px solid #1a1a1a}}
.warn{{color:#ff3b30;font-weight:700}}
</style>
</head><body>
<h1>⚡ Advanced Port Scanner</h1>
<div class="sub">Generated: {ts} &nbsp;·&nbsp; Hosts: {len(results)} &nbsp;·&nbsp; <span class="warn">CONFIDENTIAL — AUTHORIZED USE ONLY</span></div>

<div class="cards">
  <div class="card crit"><div class="card-num">{totals['CRITICAL']}</div><div class="card-label">Critical</div></div>
  <div class="card high"><div class="card-num">{totals['HIGH']}</div><div class="card-label">High</div></div>
  <div class="card med"><div class="card-num">{totals['MEDIUM']}</div><div class="card-label">Medium</div></div>
  <div class="card low"><div class="card-num">{totals['LOW']}</div><div class="card-label">Low</div></div>
</div>

<h2>Host Overview</h2>
{host_sections}

<h2>Port Details</h2>
<table>
<thead><tr>
  <th>Host</th><th>Hostname</th><th>Port</th><th>Proto</th>
  <th>Service</th><th>State</th><th>Risk</th>
  <th>CVE</th><th>Description</th><th>Version / Banner</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>
<footer>Advanced Port Scanner v2.0 — For authorized penetration testing and security audits only.<br>
Unauthorized scanning may violate computer crime laws.</footer>
</body></html>"""

    @staticmethod
    def generate_json(results): return json.dumps(results, indent=2, default=str)

    @staticmethod
    def generate_csv(results):
        import io
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["Host","Hostname","OS","Port","Protocol","State",
                    "Service","Risk","CVE","Description","Banner","TLS","TLS_CN","TLS_Expire"])
        for host, data in results.items():
            for p in data["open_ports"]:
                w.writerow([host, data.get("hostname",""), data.get("os",""),
                            p["port"], p["protocol"], p["state"],
                            p["service"], p["risk"], p["cve"], p["vuln_desc"],
                            p["banner"], p.get("tls",""), p.get("tls_cn",""), p.get("tls_expire","")])
        return buf.getvalue()


# ═══════════════════════════════════════════════════
#  GUI
# ═══════════════════════════════════════════════════
BG      = "#0a0a0a"
CARD    = "#131313"
CARD2   = "#1a1a1a"
BORDER  = "#252525"
ACC     = "#00d4ff"
FG      = "#e0e0e0"
FG_DIM  = "#666"
RED     = "#ff3b30"
GREEN   = "#34c759"
ORANGE  = "#ff9500"
YELLOW  = "#ffcc00"

RISK_FG = {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": YELLOW,
           "LOW": GREEN, "INFO": "#8e8e93", "UDP": "#5ac8fa",
           "unfiltered": "#af87ff", "filtered": "#888"}


class AdvancedScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("⚡ Advanced Network & Port Scanner v2.0")
        self.root.geometry("1380x920")
        self.root.configure(bg=BG)
        self.root.minsize(1100, 720)

        self.engine = ScannerEngine(
            log_callback=self._enqueue_log,
            progress_callback=self._set_progress,
        )
        self.scan_thread = None
        self.log_queue   = queue.Queue()

        self._build_styles()
        self._build_ui()
        self._poll_log()

    # ────────────────────────────────────────────────
    #  STYLES
    # ────────────────────────────────────────────────
    def _build_styles(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure("TFrame",      background=BG)
        s.configure("Card.TFrame", background=CARD)
        s.configure("TLabel",      background=BG, foreground=FG, font=("Helvetica",11))
        s.configure("Head.TLabel", background=BG, foreground="#fff", font=("Helvetica",21,"bold"))
        s.configure("Sub.TLabel",  background=BG, foreground=FG_DIM, font=("Helvetica",10))
        s.configure("Dim.TLabel",  background=CARD, foreground=FG_DIM, font=("Helvetica",9))
        s.configure("TEntry",      fieldbackground=CARD2, foreground=FG,
                    insertcolor=FG, borderwidth=0, font=("Courier",11))
        s.configure("TCombobox",   fieldbackground=CARD2, foreground=FG,
                    selectbackground=CARD2, font=("Courier",11))
        s.configure("TCheckbutton", background=CARD, foreground=FG, font=("Helvetica",10))
        s.configure("TNotebook",   background=BG, borderwidth=0)
        s.configure("TNotebook.Tab", background=CARD2, foreground=FG_DIM,
                    font=("Helvetica",10,"bold"), padding=(14,7))
        s.map("TNotebook.Tab",
              background=[("selected", CARD)],
              foreground=[("selected", "#fff")])
        s.configure("Scan.TButton", background=ACC, foreground="#000",
                    font=("Helvetica",12,"bold"), padding=(22,9), borderwidth=0)
        s.map("Scan.TButton",
              background=[("active","#00b8d9"),("disabled","#222")],
              foreground=[("disabled","#555")])
        s.configure("Stop.TButton", background=RED, foreground="#fff",
                    font=("Helvetica",12,"bold"), padding=(22,9), borderwidth=0)
        s.map("Stop.TButton", background=[("active","#cc2f26")])
        s.configure("Sm.TButton", background=CARD2, foreground=FG,
                    font=("Helvetica",10), padding=(12,6), borderwidth=0)
        s.map("Sm.TButton", background=[("active",BORDER)])
        s.configure("Horizontal.TProgressbar",
                    troughcolor=CARD2, background=ACC, thickness=5, borderwidth=0)
        s.configure("Treeview", background=CARD, fieldbackground=CARD,
                    foreground=FG, rowheight=25, font=("Courier",10), borderwidth=0)
        s.configure("Treeview.Heading", background="#0d0d0d", foreground=FG_DIM,
                    font=("Helvetica",9,"bold"), relief="flat")
        s.map("Treeview", background=[("selected", CARD2)])

    # ────────────────────────────────────────────────
    #  BUILD UI
    # ────────────────────────────────────────────────
    def _build_ui(self):
        # ── Header ──
        hdr = tk.Frame(self.root, bg=BG, pady=14, padx=24)
        hdr.pack(fill="x")
        tk.Label(hdr, text="⚡ Advanced Network & Port Scanner",
                 bg=BG, fg="#fff", font=("Helvetica",21,"bold")).pack(side="left")
        tk.Label(hdr, text="  v2.0  |  Industry Security Assessment Tool",
                 bg=BG, fg=FG_DIM, font=("Helvetica",10)).pack(side="left", pady=4)

        # ── Config card ──
        cfg = tk.Frame(self.root, bg=CARD, padx=20, pady=16)
        cfg.pack(fill="x", padx=16, pady=(0,4))

        # Row A — target / scan type / profile / custom / threads / timeout
        ra = tk.Frame(cfg, bg=CARD)
        ra.pack(fill="x", pady=(0,10))

        fields_a = [
            ("Target  (IP / CIDR)", "target_var",   "192.168.1.1",    22),
            ("Scan Technique",      None,            None,             18),
            ("Port Profile",        None,            None,             18),
            ("Custom Ports / Range","custom_var",    "80,443,22,8080", 18),
            ("Threads",             "threads_var",   "200",             7),
            ("Timeout (s)",         "timeout_var",   "1.0",             7),
        ]
        for col, (label, attr, default, w) in enumerate(fields_a):
            self._cfg_label(ra, label).grid(row=0, column=col, sticky="w", padx=(0,14))

        # Target
        self.target_var = tk.StringVar(value="192.168.1.1")
        self._cfg_entry(ra, self.target_var, 22).grid(row=1, column=0, sticky="ew", padx=(0,14))

        # Scan technique combo
        self.scan_type_var = tk.StringVar(value="SYN")
        st_cb = ttk.Combobox(ra, textvariable=self.scan_type_var, width=16,
                             values=["SYN","TCP","NULL","FIN","XMAS","ACK","WIN"],
                             state="readonly")
        st_cb.grid(row=1, column=1, sticky="ew", padx=(0,14))
        st_cb.bind("<<ComboboxSelected>>", self._on_scan_type_change)

        # Profile
        self.profile_var = tk.StringVar(value="Common (1000+)")
        pr_cb = ttk.Combobox(ra, textvariable=self.profile_var, width=18,
                             values=["Common (1000+)","Top 100","Vulnerable Only",
                                     "Full (1-65535)","Custom"],
                             state="readonly")
        pr_cb.grid(row=1, column=2, sticky="ew", padx=(0,14))
        pr_cb.bind("<<ComboboxSelected>>", self._on_profile_change)

        # Custom ports
        self.custom_var = tk.StringVar(value="80,443,22,8080")
        self.custom_entry = self._cfg_entry(ra, self.custom_var, 18)
        self.custom_entry.grid(row=1, column=3, sticky="ew", padx=(0,14))
        self.custom_entry.configure(state="disabled")

        # Threads / timeout
        self.threads_var = tk.StringVar(value="200")
        self._cfg_entry(ra, self.threads_var, 7).grid(row=1, column=4, sticky="ew", padx=(0,14))
        self.timeout_var = tk.StringVar(value="1.0")
        self._cfg_entry(ra, self.timeout_var, 7).grid(row=1, column=5, sticky="ew")

        # Technique description label
        self.tech_desc_var = tk.StringVar(value=SCAN_DESCRIPTIONS["SYN"])
        tk.Label(ra, textvariable=self.tech_desc_var,
                 bg=CARD, fg="#4a9eff", font=("Helvetica",9,"italic"),
                 wraplength=900, justify="left").grid(
                     row=2, column=0, columnspan=6, sticky="w", pady=(6,0))

        # Row B — advanced options + rate limit + buttons
        rb = tk.Frame(cfg, bg=CARD)
        rb.pack(fill="x", pady=(6,0))

        self.udp_var      = tk.BooleanVar(value=False)
        self.net_disc_var = tk.BooleanVar(value=False)
        self.version_var  = tk.BooleanVar(value=True)
        self.rand_var     = tk.BooleanVar(value=False)

        for text, var in [
            ("UDP Scan",           self.udp_var),
            ("Network Discovery",  self.net_disc_var),
            ("Version Detection",  self.version_var),
            ("Randomise Ports",    self.rand_var),
        ]:
            ttk.Checkbutton(rb, text=text, variable=var,
                            style="TCheckbutton").pack(side="left", padx=(0,16))

        # Rate limit
        tk.Label(rb, text="Rate Limit (pps):", bg=CARD, fg=FG_DIM,
                 font=("Helvetica",9,"bold")).pack(side="left", padx=(8,4))
        self.pps_var = tk.StringVar(value="0")
        tk.Entry(rb, textvariable=self.pps_var, width=6,
                 bg=CARD2, fg=FG, insertbackground=FG,
                 relief="flat", font=("Courier",10),
                 highlightthickness=1, highlightbackground=BORDER,
                 highlightcolor=ACC).pack(side="left", padx=(0,4))
        tk.Label(rb, text="(0=unlimited)", bg=CARD, fg=FG_DIM,
                 font=("Helvetica",8)).pack(side="left", padx=(0,20))

        # Scope whitelist
        tk.Label(rb, text="Scope (CIDR):", bg=CARD, fg=FG_DIM,
                 font=("Helvetica",9,"bold")).pack(side="left", padx=(0,4))
        self.scope_var = tk.StringVar(value="")
        tk.Entry(rb, textvariable=self.scope_var, width=16,
                 bg=CARD2, fg=FG, insertbackground=FG, relief="flat",
                 font=("Courier",10), highlightthickness=1,
                 highlightbackground=BORDER, highlightcolor=ACC).pack(side="left", padx=(0,20))

        self.scan_btn = ttk.Button(rb, text="▶  START SCAN", style="Scan.TButton",
                                   command=self._start_scan)
        self.scan_btn.pack(side="right", padx=(8,0))
        self.stop_btn = ttk.Button(rb, text="■  STOP", style="Stop.TButton",
                                   command=self._stop_scan, state="disabled")
        self.stop_btn.pack(side="right", padx=(8,0))

        # ── Progress ──
        pf = tk.Frame(self.root, bg=BG, padx=16, pady=6)
        pf.pack(fill="x")
        self.progress_var = tk.DoubleVar()
        ttk.Progressbar(pf, variable=self.progress_var, maximum=100,
                        style="Horizontal.TProgressbar",
                        mode="determinate").pack(fill="x")
        self.status_var = tk.StringVar(value="Ready — configure target and press Start Scan")
        tk.Label(pf, textvariable=self.status_var,
                 bg=BG, fg=FG_DIM, font=("Helvetica",9)).pack(anchor="w", pady=(3,0))

        # ── Notebook ──
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=16, pady=(4,0))

        # Results tab
        res_tab = ttk.Frame(nb)
        nb.add(res_tab, text="  📊 Results  ")
        self._build_results_tab(res_tab)

        # Technique guide tab
        tech_tab = ttk.Frame(nb)
        nb.add(tech_tab, text="  📖 Technique Guide  ")
        self._build_technique_tab(tech_tab)

        # Log tab
        log_tab = ttk.Frame(nb)
        nb.add(log_tab, text="  📋 Live Log  ")
        self._build_log_tab(log_tab)

        # Report tab
        rep_tab = ttk.Frame(nb)
        nb.add(rep_tab, text="  📄 Report  ")
        self._build_report_tab(rep_tab)

        # ── Status bar ──
        sb = tk.Frame(self.root, bg="#0d0d0d", pady=5, padx=16)
        sb.pack(fill="x", side="bottom")
        libs = (f"scapy {'✓' if SCAPY_AVAILABLE else '✗'}  |  "
                f"nmap {'✓' if NMAP_AVAILABLE else '✗'}  |  "
                f"requests {'✓' if REQUESTS_AVAILABLE else '✗'}  |  "
                f"Python {platform.python_version()}  |  {platform.system()}")
        tk.Label(sb, text=libs, bg="#0d0d0d", fg="#333",
                 font=("Helvetica",9)).pack(side="left")
        tk.Label(sb, text="⚠  FOR AUTHORIZED USE ONLY — UNAUTHORIZED SCANNING IS ILLEGAL",
                 bg="#0d0d0d", fg=RED, font=("Helvetica",9,"bold")).pack(side="right")

    # ── Tab builders ─────────────────────────────────
    def _build_results_tab(self, parent):
        cols = ("Host","Port","Proto","Service","State","Risk","CVE","Version / Banner","TLS")
        tf = tk.Frame(parent, bg=BG)
        tf.pack(fill="both", expand=True)
        vsb = ttk.Scrollbar(tf, orient="vertical")
        hsb = ttk.Scrollbar(tf, orient="horizontal")
        self.tree = ttk.Treeview(tf, columns=cols, show="headings",
                                  yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)
        widths = [120,55,55,120,100,85,140,350,55]
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, minwidth=40)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tf.rowconfigure(0, weight=1); tf.columnconfigure(0, weight=1)
        for risk, col in RISK_FG.items():
            self.tree.tag_configure(risk, foreground=col)

        eb = tk.Frame(parent, bg="#0d0d0d", pady=8, padx=10)
        eb.pack(fill="x")
        tk.Label(eb, text="Export:", bg="#0d0d0d", fg=FG_DIM,
                 font=("Helvetica",10)).pack(side="left", padx=(0,8))
        for fmt in ("HTML","JSON","CSV"):
            ttk.Button(eb, text=fmt, style="Sm.TButton",
                       command=lambda f=fmt: self._export(f)).pack(side="left", padx=3)
        ttk.Button(eb, text="Clear", style="Sm.TButton",
                   command=self._clear_results).pack(side="right", padx=3)

    def _build_technique_tab(self, parent):
        txt = scrolledtext.ScrolledText(parent, bg="#080808", fg=FG,
                                        font=("Courier",10), relief="flat", wrap="word")
        txt.pack(fill="both", expand=True)
        guide = """
  ╔══════════════════════════════════════════════════════════════════════════════════╗
  ║          SCAN TECHNIQUE REFERENCE GUIDE  —  Advanced Port Scanner v2.0         ║
  ╚══════════════════════════════════════════════════════════════════════════════════╝

  All techniques require authorization from the system/network owner before use.

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  SYN SCAN  (Half-Open Scan)                                          ROOT REQ'd │
  ├─────────────────────────────────────────────────────────────────────────────────┤
  │  Mechanism : Sends a TCP SYN packet. If SYN-ACK returned → port OPEN.          │
  │              Immediately sends RST to tear down — never completes handshake.    │
  │  Detection : Low. Many firewalls/IDS track SYN floods; single-packet SYN is    │
  │              typically not logged by application-layer loggers.                 │
  │  Best for  : Fast, wide-range port enumeration on known targets.                │
  │  Limitation: Stateful firewalls may still log half-open attempts.               │
  └─────────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  TCP CONNECT SCAN  (Full Connect)                                  NO ROOT REQ │
  ├─────────────────────────────────────────────────────────────────────────────────┤
  │  Mechanism : Completes full 3-way handshake using OS socket API.                │
  │  Detection : HIGH. Every connection is logged by the application & firewall.    │
  │  Best for  : Environments where you cannot obtain root/administrator access.    │
  │  Limitation: Slowest; leaves the most forensic evidence.                        │
  └─────────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  NULL SCAN  (No Flags)                                               ROOT REQ'd │
  ├─────────────────────────────────────────────────────────────────────────────────┤
  │  Mechanism : Sends TCP packet with FLAGS = 0 (no flags set).                    │
  │              RFC 793: OPEN port → silently drops packet (no response).          │
  │                        CLOSED port → responds with RST+ACK.                    │
  │  Result    : No response = open|filtered. RST = closed. ICMP unreach = filtered.│
  │  Use case  : Bypass non-stateful packet filters / legacy ACLs.                  │
  │  Limitation: Unreliable against Windows (sends RST for all). Not routable       │
  │              through NAT.                                                       │
  └─────────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  FIN SCAN  (Finish Flag)                                             ROOT REQ'd │
  ├─────────────────────────────────────────────────────────────────────────────────┤
  │  Mechanism : Sends TCP packet with only FIN flag set.                            │
  │              Same RFC 793 semantics as NULL scan.                               │
  │  Result    : No response = open|filtered. RST = closed.                         │
  │  Use case  : Stealthier than SYN on BSD-derived OS; good for firewall testing.  │
  │  Limitation: Same as NULL — unreliable on Windows targets.                      │
  └─────────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  XMAS SCAN  (FIN + PSH + URG)                                        ROOT REQ'd │
  ├─────────────────────────────────────────────────────────────────────────────────┤
  │  Mechanism : Sets FIN, PSH, and URG flags simultaneously ("lit up like a tree").│
  │              RFC 793 semantics identical to NULL and FIN scans.                 │
  │  Result    : No response = open|filtered. RST = closed.                         │
  │  Use case  : Alternative stealth technique; some IDS signatures differ for      │
  │              FIN vs XMAS.                                                       │
  │  Limitation: Same Windows limitation; easily detected by modern NIDS.           │
  └─────────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  ACK SCAN  (Firewall Mapping)                                        ROOT REQ'd │
  ├─────────────────────────────────────────────────────────────────────────────────┤
  │  Mechanism : Sends ACK packet. Does NOT determine open/closed.                  │
  │              RST received = UNFILTERED (packet reached the host).               │
  │              No response / ICMP unreachable = FILTERED (firewall dropped it).   │
  │  Use case  : Map which ports are FILTERED vs UNFILTERED by a firewall.          │
  │              Determine stateful vs stateless firewall behaviour.                │
  │  NOTE      : This scan does NOT find open ports — use SYN/TCP for that.         │
  └─────────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  WINDOW SCAN  (TCP Window)                                           ROOT REQ'd │
  ├─────────────────────────────────────────────────────────────────────────────────┤
  │  Mechanism : ACK probe examining the TCP window field of the RST response.      │
  │              Non-zero window value → infers OPEN. Zero window → CLOSED.         │
  │  Use case  : OS-specific; works on some BSD and AIX systems.                    │
  │  Limitation: Accuracy varies significantly by OS implementation.                │
  └─────────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  ADVANCED OPTIONS                                                               │
  ├─────────────────────────────────────────────────────────────────────────────────┤
  │  Rate Limit (pps) : Throttle packets per second. 0 = unlimited.                 │
  │                     Use 100-500 for cautious scans; 0 for lab/CTF speed.        │
  │  Randomise Ports  : Shuffles port order before scanning to reduce IDS           │
  │                     sequential-scan signatures.                                 │
  │  Scope (CIDR)     : Enforce scan boundary. Tool will refuse targets outside     │
  │                     this CIDR — prevents accidental out-of-scope scanning.      │
  │  Version Detect   : Service-specific probes + TLS inspection for open ports.   │
  │  UDP Scan         : Probes top UDP service ports (DNS, SNMP, TFTP, NTP, etc.).  │
  └─────────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  RISK CLASSIFICATION                                                            │
  ├─────────────────────────────────────────────────────────────────────────────────┤
  │  CRITICAL  Remote code execution, unauthenticated access, active exploits.      │
  │  HIGH      Cleartext credentials, known CVEs with public PoC, weak auth.        │
  │  MEDIUM    Information disclosure, cleartext protocols with limited exposure.   │
  │  LOW       Encrypted services — verify TLS version and certificate validity.    │
  │  INFO      Non-vulnerable services with no known critical issues.               │
  └─────────────────────────────────────────────────────────────────────────────────┘
"""
        txt.insert("end", guide)
        txt.configure(state="disabled")

    def _build_log_tab(self, parent):
        self.log_text = scrolledtext.ScrolledText(
            parent, bg="#070707", fg=FG, font=("Courier",10),
            relief="flat", wrap="word", insertbackground=FG)
        self.log_text.pack(fill="both", expand=True)
        for tag, col in RISK_FG.items():
            self.log_text.tag_config(tag, foreground=col)
        for tag, col in [("INFO",FG_DIM),("SUCCESS",GREEN),("ERROR",RED),
                         ("WARNING",ORANGE),("HEADER",ACC),("UDP","#5ac8fa")]:
            self.log_text.tag_config(tag, foreground=col)
        bar = tk.Frame(parent, bg="#0d0d0d", pady=6, padx=8)
        bar.pack(fill="x")
        ttk.Button(bar, text="Clear Log", style="Sm.TButton",
                   command=lambda: self.log_text.delete("1.0","end")).pack(side="right")

    def _build_report_tab(self, parent):
        self.report_text = scrolledtext.ScrolledText(
            parent, bg="#070707", fg=FG, font=("Courier",10),
            relief="flat", wrap="word")
        self.report_text.pack(fill="both", expand=True)
        bar = tk.Frame(parent, bg="#0d0d0d", pady=6, padx=8)
        bar.pack(fill="x")
        ttk.Button(bar, text="Generate Report", style="Scan.TButton",
                   command=self._generate_text_report).pack(side="left", padx=4)
        ttk.Button(bar, text="Save HTML", style="Sm.TButton",
                   command=lambda: self._export("HTML")).pack(side="left", padx=4)
        ttk.Button(bar, text="Save JSON", style="Sm.TButton",
                   command=lambda: self._export("JSON")).pack(side="left", padx=4)
        ttk.Button(bar, text="Save CSV", style="Sm.TButton",
                   command=lambda: self._export("CSV")).pack(side="left", padx=4)

    # ── Widget helpers ────────────────────────────────
    def _cfg_label(self, p, text):
        return tk.Label(p, text=text, bg=CARD, fg=FG_DIM, font=("Helvetica",9,"bold"))

    def _cfg_entry(self, p, var, width):
        return tk.Entry(p, textvariable=var, width=width,
                        bg=CARD2, fg=FG, insertbackground=FG, relief="flat",
                        font=("Courier",11), highlightthickness=1,
                        highlightbackground=BORDER, highlightcolor=ACC)

    def _on_scan_type_change(self, _=None):
        st = self.scan_type_var.get()
        self.tech_desc_var.set(SCAN_DESCRIPTIONS.get(st, ""))

    def _on_profile_change(self, _=None):
        state = "normal" if self.profile_var.get() == "Custom" else "disabled"
        self.custom_entry.configure(state=state)

    # ── Port list ─────────────────────────────────────
    def _get_ports(self):
        p = self.profile_var.get()
        if p == "Top 100":           return list(TOP_100_PORTS)
        if p == "Vulnerable Only":   return sorted(VULNERABLE_PORTS.keys())
        if p == "Full (1-65535)":    return list(range(1, 65536))
        if p == "Custom":
            raw = self.custom_var.get()
            ports = []
            for part in raw.split(","):
                part = part.strip()
                if "-" in part:
                    a, b = part.split("-", 1)
                    try: ports.extend(range(int(a), int(b)+1))
                    except ValueError: pass
                elif part.isdigit():
                    ports.append(int(part))
            return sorted(set(ports))
        return list(COMMON_PORTS)   # default

    # ── Scope check ───────────────────────────────────
    def _in_scope(self, host):
        scope = self.scope_var.get().strip()
        if not scope:
            return True
        try:
            net = ipaddress.ip_network(scope, strict=False)
            return ipaddress.ip_address(host) in net
        except Exception:
            return True   # non-parseable scope = warn but allow

    # ── Scan control ──────────────────────────────────
    def _start_scan(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("No Target", "Please enter a target IP or hostname.")
            return

        # Scope enforcement
        scope = self.scope_var.get().strip()
        if scope and "/" not in target:
            if not self._in_scope(target):
                messagebox.showerror(
                    "Out of Scope",
                    f"Target {target} is outside the defined scope ({scope}).\n"
                    "Update scope or clear it to proceed."
                )
                return

        ports = self._get_ports()
        try:
            threads = int(self.threads_var.get())
            timeout = float(self.timeout_var.get())
            pps     = int(self.pps_var.get())
        except ValueError:
            messagebox.showerror("Invalid Input", "Threads, timeout, and PPS must be numeric.")
            return

        scan_type = self.scan_type_var.get()

        if scan_type in ("NULL","FIN","XMAS","ACK","WIN","SYN") and not SCAPY_AVAILABLE:
            if not messagebox.askyesno(
                "Scapy Not Available",
                f"{scan_type} scan requires Scapy (and root/admin).\n"
                "Fall back to TCP Connect scan instead?"
            ):
                return

        self.scan_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.progress_var.set(0)
        self.status_var.set(f"Scanning {target} with {scan_type} scan…")
        self._clear_tree()

        self._enqueue_log("═"*62, "HEADER")
        self._enqueue_log(f" SCAN START  |  Target: {target}  |  Type: {scan_type}  |  Ports: {len(ports)}", "HEADER")
        if pps > 0:
            self._enqueue_log(f" Rate Limit : {pps} pps", "HEADER")
        if self.rand_var.get():
            self._enqueue_log(" Port Order : RANDOMISED", "HEADER")
        self._enqueue_log("═"*62, "HEADER")

        def run():
            try:
                if self.net_disc_var.get() and "/" in target:
                    live = self.engine.discover_network(target)
                    for h in live:
                        if self.engine._stop_event.is_set(): break
                        if scope and not self._in_scope(h):
                            self._enqueue_log(f"[!] Skipping {h} — out of scope", "WARNING")
                            continue
                        self.engine.scan_host(
                            h, ports, scan_type, threads, timeout,
                            self.udp_var.get(), self.version_var.get(), pps, self.rand_var.get()
                        )
                else:
                    self.engine.scan_host(
                        target, ports, scan_type, threads, timeout,
                        self.udp_var.get(), self.version_var.get(), pps, self.rand_var.get()
                    )
                self.root.after(0, self._scan_done)
            except Exception as e:
                self._enqueue_log(f"[!] Fatal: {e}", "ERROR")
                self.root.after(0, self._scan_done)

        self.scan_thread = threading.Thread(target=run, daemon=True)
        self.scan_thread.start()
        self.root.after(600, self._refresh_tree_live)

    def _stop_scan(self):
        self.engine.stop()
        self.status_var.set("Scan stopped by user.")
        self._scan_done()

    def _scan_done(self):
        self.scan_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.progress_var.set(100)
        total = sum(len(d["open_ports"]) for d in self.engine.results.values())
        self.status_var.set(
            f"Complete — {total} port(s) open across {len(self.engine.results)} host(s)"
        )
        self._refresh_tree()
        self._generate_text_report()

    # ── Tree management ───────────────────────────────
    def _refresh_tree_live(self):
        if not self.engine._stop_event.is_set() and self.engine.results:
            self._refresh_tree()
            self.root.after(1500, self._refresh_tree_live)

    def _refresh_tree(self):
        self._clear_tree()
        for host, data in self.engine.results.items():
            for p in data["open_ports"]:
                risk = p["risk"] if p["state"] != "unfiltered" else "unfiltered"
                tls  = "✓" if p.get("tls") else ""
                self.tree.insert("", "end", values=(
                    host, p["port"], p["protocol"].upper(),
                    p["service"], p["state"], p["risk"],
                    p["cve"], p["banner"][:80], tls,
                ), tags=(risk,))

    def _clear_tree(self):
        for i in self.tree.get_children(): self.tree.delete(i)

    def _clear_results(self):
        self._clear_tree()
        self.engine.results.clear()
        self.report_text.delete("1.0","end")

    # ── Log queue ─────────────────────────────────────
    def _enqueue_log(self, msg, level="INFO"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_queue.put((f"[{ts}] {msg}\n", level))

    def _poll_log(self):
        try:
            while True:
                msg, level = self.log_queue.get_nowait()
                self.log_text.insert("end", msg, level)
                self.log_text.see("end")
        except queue.Empty:
            pass
        self.root.after(80, self._poll_log)

    def _set_progress(self, val):
        self.root.after(0, lambda: self.progress_var.set(val))

    # ── Text report ───────────────────────────────────
    def _generate_text_report(self):
        self.report_text.delete("1.0","end")
        if not self.engine.results:
            self.report_text.insert("end","No results yet.\n"); return

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        totals = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
        lines = [
            "═"*72,
            "        ADVANCED PORT SCANNER v2.0 — SECURITY ASSESSMENT REPORT",
            f"        Generated : {ts}",
            "        CONFIDENTIAL — AUTHORIZED USE ONLY",
            "═"*72,"",
        ]

        for host, data in self.engine.results.items():
            tcp_p = [p for p in data["open_ports"] if p["protocol"]=="tcp"]
            udp_p = [p for p in data["open_ports"] if p["protocol"]=="udp"]
            lines += [
                f"  HOST         : {host}",
                f"  Hostname     : {data.get('hostname','')}",
                f"  OS (guess)   : {data.get('os','Unknown')}",
                f"  MAC Address  : {data.get('mac','N/A')}",
                f"  Scan Type    : {data.get('scan_type','')}",
                f"  Scan Time    : {data.get('scan_time','')}",
                f"  Ports scanned: {data.get('total_ports_scanned',0)}",
                f"  TCP open     : {len(tcp_p)}",
                f"  UDP open/filt: {len(udp_p)}",
                "",
                f"  {'PORT':<7} {'PROTO':<5} {'STATE':<16} {'SERVICE':<16} {'RISK':<10} {'CVE':<20} DESCRIPTION",
                "  " + "─"*100,
            ]
            for p in data["open_ports"]:
                totals[p["risk"]] = totals.get(p["risk"],0) + 1
                tls = " [TLS]" if p.get("tls") else ""
                lines.append(
                    f"  {p['port']:<7} {p['protocol'].upper():<5} {p['state']:<16} "
                    f"{p['service']:<16} {p['risk']:<10} {p['cve']:<20} {p['vuln_desc'][:45]}"
                )
                if p["banner"]:
                    lines.append(f"  {'':7}   └ {p['banner'][:90]}{tls}")
            lines += ["","─"*72,""]

        lines += [
            "  VULNERABILITY SUMMARY",
            "  " + "─"*35,
            f"  CRITICAL  : {totals.get('CRITICAL',0):>4}  {'■'*min(totals.get('CRITICAL',0),30)}",
            f"  HIGH      : {totals.get('HIGH',0):>4}  {'■'*min(totals.get('HIGH',0),30)}",
            f"  MEDIUM    : {totals.get('MEDIUM',0):>4}  {'■'*min(totals.get('MEDIUM',0),30)}",
            f"  LOW       : {totals.get('LOW',0):>4}  {'■'*min(totals.get('LOW',0),30)}",
            f"  INFO      : {totals.get('INFO',0):>4}  {'■'*min(totals.get('INFO',0),30)}",
            "","─"*72,"  REMEDIATION RECOMMENDATIONS","  "+"─"*35,
        ]
        if totals.get("CRITICAL",0):
            lines.append("  [CRITICAL] Patch or disable these services IMMEDIATELY — active exploit risk.")
        if totals.get("HIGH",0):
            lines.append("  [HIGH]     Schedule urgent patching within 72 hours.")
        if totals.get("MEDIUM",0):
            lines.append("  [MEDIUM]   Plan remediation within next patch cycle.")
        lines += [
            "  [ALL]      Review firewall rules — restrict access to necessary source IPs only.",
            "  [ALL]      Disable services that serve no operational purpose.",
            "  [ALL]      Enforce TLS 1.2+ on all cleartext services.",
            "  [ALL]      Enable centralised logging and alerting for these ports.",
            "","═"*72,
            "  Advanced Port Scanner v2.0 — Authorized security testing use only.",
            "  Unauthorized scanning may violate local and international computer crime laws.",
            "═"*72,
        ]
        self.report_text.insert("end", "\n".join(lines))

    # ── Export ────────────────────────────────────────
    def _export(self, fmt):
        if not self.engine.results:
            messagebox.showwarning("No Data","No results to export."); return
        ext = {"HTML":".html","JSON":".json","CSV":".csv"}[fmt]
        ft  = {"HTML":[("HTML","*.html")],"JSON":[("JSON","*.json")],"CSV":[("CSV","*.csv")]}[fmt]
        path = filedialog.asksaveasfilename(
            defaultextension=ext, filetypes=ft,
            initialfile=f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        if not path: return
        gen = ReportGenerator()
        content = (gen.generate_html(self.engine.results) if fmt=="HTML" else
                   gen.generate_json(self.engine.results) if fmt=="JSON" else
                   gen.generate_csv(self.engine.results))
        with open(path,"w",encoding="utf-8") as f: f.write(content)
        self._enqueue_log(f"[✔] Exported {fmt}: {path}", "SUCCESS")
        messagebox.showinfo("Exported", f"Report saved:\n{path}")


# ═══════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════
def main():
    root = tk.Tk()
    AdvancedScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
