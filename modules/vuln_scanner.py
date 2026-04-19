import socket

# Severity: critical / high / medium / low / info
VULN_DB = {
    21: {
        'name': 'FTP',
        'severity': 'high',
        'issues': [
            'Anonymous login may be enabled — no credentials required',
            'Credentials transmitted in plaintext over the network',
            'FTP bounce attacks may be possible',
            'Directory traversal vulnerabilities in some implementations',
            'Active mode FTP can be used to bypass firewalls',
        ],
        'cves': [
            ('CVE-2015-3306', 'high',    'ProFTPD mod_copy — unauthorized file copy without authentication'),
            ('CVE-2011-4130', 'high',    'ProFTPD use-after-free in response pool handling'),
            ('CVE-2010-4221', 'high',    'ProFTPD mod_sql stack-based buffer overflow'),
            ('CVE-2011-2523', 'critical','vsftpd 2.3.4 backdoor — opens shell on port 6200'),
            ('CVE-2010-1938', 'critical','ProFTPD mod_sql format string vulnerability'),
            ('CVE-2006-5815', 'critical','ProFTPD sreplace() stack-based buffer overflow'),
        ],
        'default_creds': [('anonymous', 'anonymous'), ('anonymous', ''), ('ftp', 'ftp'), ('admin', 'admin'), ('admin', '')],
        'nmap_scripts': ['ftp-anon', 'ftp-bounce', 'ftp-brute', 'ftp-syst', 'ftp-vsftpd-backdoor'],
        'remediation': 'Replace FTP with SFTP or FTPS. Disable anonymous login. Restrict access by IP.',
        'active_check': 'anon_ftp',
        'service_keywords': ['ftp', 'vsftpd', 'proftpd', 'filezilla', 'pure-ftpd'],
    },
    22: {
        'name': 'SSH',
        'severity': 'medium',
        'issues': [
            'Password authentication may be enabled — susceptible to brute-force',
            'Root login may be permitted',
            'Weak ciphers / key-exchange algorithms may be supported',
            'Older OpenSSH versions have known critical vulnerabilities',
        ],
        'cves': [
            ('CVE-2024-6387', 'critical', 'regreSSHion — OpenSSH race condition pre-auth RCE (glibc systems)'),
            ('CVE-2023-38408', 'critical', 'OpenSSH ssh-agent remote code execution via PKCS#11 provider'),
            ('CVE-2023-48795', 'medium',   'Terrapin attack — SSH prefix truncation weakening integrity'),
            ('CVE-2021-41617', 'high',     'OpenSSH privilege escalation in AuthorizedKeysCommand'),
            ('CVE-2018-15473', 'medium',   'OpenSSH username enumeration via timing difference'),
            ('CVE-2016-0777',  'medium',   'OpenSSH information leak via roaming feature'),
            ('CVE-2016-6515',  'high',     'OpenSSH password authentication CPU exhaustion DoS'),
        ],
        'default_creds': [('root', 'root'), ('root', 'toor'), ('admin', 'admin'), ('pi', 'raspberry'), ('ubuntu', 'ubuntu'), ('vagrant', 'vagrant')],
        'nmap_scripts': ['ssh-auth-methods', 'ssh-brute', 'ssh-hostkey', 'ssh2-enum-algos', 'ssh-publickey-acceptance'],
        'remediation': 'Enforce key-based auth. Disable PasswordAuthentication and PermitRootLogin in sshd_config. Use fail2ban. Keep OpenSSH updated.',
        'active_check': None,
        'service_keywords': ['ssh', 'openssh', 'dropbear'],
    },
    23: {
        'name': 'Telnet',
        'severity': 'critical',
        'issues': [
            'All traffic including credentials is transmitted in plaintext',
            'Highly susceptible to man-in-the-middle attacks',
            'No integrity or confidentiality protection whatsoever',
            'Legacy protocol — should not be running on any modern system',
            'Commonly left open on IoT and embedded devices',
        ],
        'cves': [
            ('CVE-2020-10188', 'critical', 'GNU inetutils telnetd remote code execution'),
            ('CVE-2011-4862',  'critical', 'FreeBSD telnetd remote code execution via encryption key'),
            ('CVE-2001-0554',  'critical', 'BSD telnetd remote buffer overflow'),
        ],
        'default_creds': [('admin', 'admin'), ('root', 'root'), ('admin', ''), ('', ''), ('admin', '1234')],
        'nmap_scripts': ['telnet-brute', 'telnet-encryption', 'telnet-ntlm-info'],
        'remediation': 'Disable Telnet immediately. Replace with SSH.',
        'active_check': None,
        'service_keywords': ['telnet'],
    },
    25: {
        'name': 'SMTP',
        'severity': 'medium',
        'issues': [
            'Open relay may allow sending spam from this server',
            'VRFY/EXPN commands may allow user enumeration',
            'Banner may disclose server software and version',
            'Cleartext AUTH possible without STARTTLS',
        ],
        'cves': [
            ('CVE-2023-42115', 'critical', 'Exim out-of-bounds write in smtp_filter module'),
            ('CVE-2021-38371', 'high',     'Exim SPA authentication bypass'),
            ('CVE-2020-28017', 'critical', 'Exim heap overflow in receive_add_recipient()'),
            ('CVE-2020-7247',  'critical', 'OpenSMTPD remote code execution in MTA-STS'),
            ('CVE-2019-16928', 'critical', 'Exim heap overflow in string_vformat()'),
            ('CVE-2019-10149', 'critical', 'Exim remote command execution in deliver_message()'),
        ],
        'default_creds': [],
        'nmap_scripts': ['smtp-commands', 'smtp-enum-users', 'smtp-open-relay', 'smtp-vuln-cve2010-4344'],
        'remediation': 'Disable VRFY/EXPN. Enforce STARTTLS. Check for open relay. Keep Exim/Postfix updated.',
        'active_check': None,
        'service_keywords': ['smtp', 'postfix', 'exim', 'sendmail', 'haraka', 'mail'],
    },
    53: {
        'name': 'DNS',
        'severity': 'medium',
        'issues': [
            'Zone transfer (AXFR) may be unrestricted — leaks all DNS records',
            'DNS amplification attacks possible if recursion is open',
            'Cache poisoning if DNSSEC not implemented',
            'Version disclosure via BIND chaos query',
        ],
        'cves': [
            ('CVE-2023-50387', 'high',    'BIND KeyTrap — DoS via DNSSEC validation exhaustion'),
            ('CVE-2022-3080',  'high',    'BIND assertion failure via STALE cache option'),
            ('CVE-2021-25216', 'critical','ISC BIND TKEY remote code execution'),
            ('CVE-2020-8625',  'high',    'BIND TSIG hmac remote stack buffer overflow'),
            ('CVE-2020-8617',  'high',    'BIND TSIG tsig-request assertion failure DoS'),
        ],
        'default_creds': [],
        'nmap_scripts': ['dns-zone-transfer', 'dns-brute', 'dns-recursion', 'dns-cache-snoop', 'dns-service-discovery'],
        'remediation': 'Restrict zone transfers to authorised secondaries. Disable open recursion. Implement DNSSEC.',
        'active_check': None,
        'service_keywords': ['dns', 'bind', 'named', 'domain'],
    },
    69: {
        'name': 'TFTP',
        'severity': 'high',
        'issues': [
            'No authentication — any file can be read or written anonymously',
            'Often used to serve PXE boot images — may allow firmware tampering',
            'UDP-based — difficult to filter and log',
            'Can expose sensitive config files (router configs, passwords)',
        ],
        'cves': [
            ('CVE-2008-2161', 'high', 'tftpd-hpa directory traversal'),
            ('CVE-2002-0813', 'high', 'Cisco IOS TFTP server buffer overflow'),
        ],
        'default_creds': [],
        'nmap_scripts': ['tftp-enum'],
        'remediation': 'Disable TFTP if not required. Restrict to trusted IPs. Use authenticated file transfer instead.',
        'active_check': None,
        'service_keywords': ['tftp'],
    },
    80: {
        'name': 'HTTP',
        'severity': 'medium',
        'issues': [
            'All traffic transmitted in plaintext — no encryption',
            'Missing security headers (CSP, HSTS, X-Frame-Options)',
            'Server version disclosed in response headers',
            'Default pages or admin panels may be accessible',
        ],
        'cves': [
            ('CVE-2021-41773', 'critical', 'Apache 2.4.49 path traversal and RCE'),
            ('CVE-2021-42013', 'critical', 'Apache 2.4.49-50 path traversal bypass'),
            ('CVE-2021-26855', 'critical', 'Microsoft Exchange ProxyLogon SSRF pre-auth RCE'),
            ('CVE-2019-0211',  'high',     'Apache privilege escalation via mod_prefork'),
            ('CVE-2017-7679',  'critical', 'Apache mod_mime buffer overread'),
            ('CVE-2017-9798',  'high',     'Apache Optionsbleed — OPTIONS method memory leak'),
        ],
        'default_creds': [('admin', 'admin'), ('admin', 'password'), ('admin', ''), ('root', 'root')],
        'nmap_scripts': ['http-methods', 'http-headers', 'http-title', 'http-robots.txt', 'http-shellshock', 'http-vuln-*'],
        'remediation': 'Redirect to HTTPS. Implement security headers. Keep web server updated. Disable directory listing.',
        'active_check': 'http_info',
        'service_keywords': ['http', 'apache', 'nginx', 'iis', 'lighttpd', 'httpd', 'web'],
    },
    110: {
        'name': 'POP3',
        'severity': 'high',
        'issues': [
            'Credentials transmitted in plaintext without STARTTLS',
            'Susceptible to credential interception',
            'User enumeration via error messages',
        ],
        'cves': [
            ('CVE-2003-0161', 'critical', 'Sendmail address parsing remote overflow'),
            ('CVE-2007-1558', 'medium',   'APOP MD5 collision — authentication bypass'),
        ],
        'default_creds': [],
        'nmap_scripts': ['pop3-brute', 'pop3-capabilities', 'pop3-ntlm-info'],
        'remediation': 'Use POP3S (port 995) or enforce STARTTLS. Migrate to IMAPS.',
        'active_check': None,
        'service_keywords': ['pop3', 'pop', 'dovecot'],
    },
    111: {
        'name': 'RPCbind / Portmapper',
        'severity': 'high',
        'issues': [
            'Exposes all RPC services registered on the host',
            'Can be used to enumerate NFS exports and other services',
            'Amplification vector for UDP-based DDoS attacks',
            'Historically exploited for privilege escalation',
        ],
        'cves': [
            ('CVE-2017-8779', 'high', 'rpcbind memory exhaustion DoS via crafted UDP packet'),
        ],
        'default_creds': [],
        'nmap_scripts': ['rpcinfo', 'nfs-ls', 'nfs-showmount'],
        'remediation': 'Block port 111 at the firewall. Disable RPC services not in use.',
        'active_check': None,
        'service_keywords': ['rpcbind', 'rpc', 'portmapper', 'sunrpc'],
    },
    123: {
        'name': 'NTP',
        'severity': 'medium',
        'issues': [
            'NTP amplification — large responses to small requests enable DDoS reflection',
            'monlist command reveals recent clients (information disclosure)',
            'Time manipulation may affect security mechanisms (certs, Kerberos, MFA)',
        ],
        'cves': [
            ('CVE-2016-7434', 'high',   'ntpd remote DoS via crafted mrulist request'),
            ('CVE-2015-7704', 'high',   'ntpd denial of service via KoD packet'),
            ('CVE-2014-9295', 'critical','ntpd multiple stack overflows in crypto functions'),
        ],
        'default_creds': [],
        'nmap_scripts': ['ntp-info', 'ntp-monlist'],
        'remediation': 'Disable monlist. Use NTP authentication. Restrict to trusted peers. Apply latest ntpd patches.',
        'active_check': None,
        'service_keywords': ['ntp'],
    },
    139: {
        'name': 'NetBIOS',
        'severity': 'high',
        'issues': [
            'NetBIOS name enumeration may reveal host information',
            'Null sessions may allow unauthenticated enumeration',
            'Often paired with SMB — see port 445',
        ],
        'cves': [
            ('CVE-2017-0143', 'critical', 'EternalBlue SMB remote code execution (MS17-010)'),
            ('CVE-2008-4114', 'high',     'Windows NetBIOS header validation DoS'),
        ],
        'default_creds': [],
        'nmap_scripts': ['nbstat', 'smb-security-mode', 'smb-enum-shares'],
        'remediation': 'Block NetBIOS ports at the firewall. Disable NetBIOS over TCP/IP if not needed.',
        'active_check': None,
        'service_keywords': ['netbios', 'smb', 'samba', 'microsoft-ds', 'nbsession'],
    },
    143: {
        'name': 'IMAP',
        'severity': 'high',
        'issues': [
            'Credentials transmitted in plaintext without STARTTLS',
            'May allow user enumeration',
            'Susceptible to brute-force attacks',
        ],
        'cves': [
            ('CVE-2021-38371', 'high',   'Cyrus IMAP authentication bypass'),
            ('CVE-2019-19056', 'high',   'Dovecot null pointer dereference'),
            ('CVE-2017-15130', 'medium', 'Dovecot TLS SNI config lookup DoS'),
        ],
        'default_creds': [],
        'nmap_scripts': ['imap-brute', 'imap-capabilities', 'imap-ntlm-info'],
        'remediation': 'Use IMAPS (port 993) or enforce STARTTLS.',
        'active_check': None,
        'service_keywords': ['imap', 'dovecot', 'cyrus'],
    },
    161: {
        'name': 'SNMP',
        'severity': 'high',
        'issues': [
            'SNMPv1/v2c use community strings (default "public"/"private") instead of real auth',
            'Read access exposes full device configuration, routing tables, ARP cache',
            'Write access (private community) allows changing device config remotely',
            'UDP-based — amplification factor up to 650x for DDoS',
        ],
        'cves': [
            ('CVE-2017-6736', 'critical', 'Cisco IOS SNMP remote code execution'),
            ('CVE-2017-6742', 'high',     'Cisco IOS SNMP buffer overflow'),
            ('CVE-2002-0013', 'high',     'Multiple SNMP implementations buffer overflow in SNMPv1 trap handling'),
        ],
        'default_creds': [('public', ''), ('private', ''), ('community', ''), ('admin', '')],
        'nmap_scripts': ['snmp-info', 'snmp-brute', 'snmp-sysdescr', 'snmp-interfaces', 'snmp-netstat'],
        'remediation': 'Disable SNMPv1/v2c. Use SNMPv3 with AuthPriv. Change default community strings. Restrict to trusted hosts.',
        'active_check': None,
        'service_keywords': ['snmp'],
    },
    389: {
        'name': 'LDAP',
        'severity': 'high',
        'issues': [
            'Anonymous bind may allow unauthenticated directory enumeration',
            'Cleartext credentials transmitted without LDAPS or STARTTLS',
            'User and group information may be fully readable',
            'May expose Active Directory structure',
        ],
        'cves': [
            ('CVE-2021-44228', 'critical', 'Log4Shell — LDAP JNDI injection in Apache Log4j (Java apps)'),
            ('CVE-2017-8563',  'high',     'Windows LDAP elevation of privilege via LDAP relay'),
            ('CVE-2009-3231',  'high',     'OpenLDAP modrdn DoS via crafted request'),
        ],
        'default_creds': [('', ''), ('admin', 'admin'), ('cn=admin,dc=example,dc=com', 'admin')],
        'nmap_scripts': ['ldap-rootdse', 'ldap-brute', 'ldap-search', 'ldap-novell-getpass'],
        'remediation': 'Disable anonymous bind. Enforce LDAPS or STARTTLS. Restrict access by IP.',
        'active_check': None,
        'service_keywords': ['ldap', 'active directory', 'openldap'],
    },
    443: {
        'name': 'HTTPS',
        'severity': 'low',
        'issues': [
            'Weak TLS versions (TLS 1.0/1.1) may be supported',
            'Weak cipher suites may be offered',
            'Certificate may be self-signed or expired',
            'Missing security headers',
        ],
        'cves': [
            ('CVE-2022-0778',  'high',    'OpenSSL infinite loop in BN_mod_sqrt() — DoS'),
            ('CVE-2022-3602',  'critical','OpenSSL X.509 buffer overflow — potential RCE'),
            ('CVE-2021-3711',  'critical','OpenSSL SM2 buffer overflow'),
            ('CVE-2016-2107',  'high',    'OpenSSL AES-NI padding oracle attack'),
            ('CVE-2015-0204',  'high',    'FREAK — SSL/TLS export cipher downgrade'),
            ('CVE-2014-3566',  'high',    'POODLE — SSL 3.0 padding oracle attack'),
            ('CVE-2014-0160',  'high',    'Heartbleed — OpenSSL memory disclosure'),
        ],
        'default_creds': [],
        'nmap_scripts': ['ssl-heartbleed', 'ssl-poodle', 'ssl-ccs-injection', 'ssl-enum-ciphers', 'http-headers'],
        'remediation': 'Enforce TLS 1.2+. Disable weak ciphers. Use valid certificates. Implement HSTS.',
        'active_check': 'http_info',
        'service_keywords': ['https', 'http', 'apache', 'nginx', 'iis', 'ssl', 'tls', 'web'],
    },
    445: {
        'name': 'SMB',
        'severity': 'critical',
        'issues': [
            'EternalBlue (MS17-010) may be unpatched — leads to full RCE',
            'Null sessions may allow unauthenticated share enumeration',
            'SMBv1 may be enabled — multiple known critical vulnerabilities',
            'Relay attacks (NTLM relay) may be possible',
            'PrintNightmare and similar spooler exploits may apply',
        ],
        'cves': [
            ('CVE-2017-0143', 'critical', 'EternalBlue — SMBv1 remote code execution (WannaCry)'),
            ('CVE-2017-0144', 'critical', 'EternalBlue variant — SMB RCE'),
            ('CVE-2020-0796', 'critical', 'SMBGhost — SMBv3 compression RCE'),
            ('CVE-2021-36942','high',     'PetitPotam NTLM relay via EFSRPC'),
            ('CVE-2021-34527','high',     'PrintNightmare — Windows Print Spooler RCE'),
            ('CVE-2021-1675',  'high',    'Windows Print Spooler privilege escalation'),
        ],
        'default_creds': [('administrator', ''), ('guest', ''), ('admin', 'admin')],
        'nmap_scripts': ['smb-vuln-ms17-010', 'smb-vuln-ms08-067', 'smb-security-mode', 'smb-enum-shares', 'smb-enum-users'],
        'remediation': 'Patch MS17-010 immediately. Disable SMBv1. Enforce SMB signing. Block at firewall if not needed.',
        'active_check': None,
        'service_keywords': ['smb', 'samba', 'microsoft-ds', 'cifs', 'netbios'],
    },
    512: {
        'name': 'rexec',
        'severity': 'critical',
        'issues': [
            'Cleartext remote command execution — no encryption',
            'Authentication via username only — no password required in some configs',
            'Legacy Unix r-command — should never be exposed',
        ],
        'cves': [],
        'default_creds': [('root', ''), ('admin', '')],
        'nmap_scripts': ['rexec-brute'],
        'remediation': 'Disable all Berkeley r-commands immediately. Replace with SSH.',
        'active_check': None,
        'service_keywords': ['rexec', 'exec'],
    },
    513: {
        'name': 'rlogin',
        'severity': 'critical',
        'issues': [
            'Cleartext remote login — credentials transmitted in plaintext',
            'Trust-based authentication (.rhosts) may bypass passwords entirely',
            'Legacy Unix r-command — should never be exposed',
        ],
        'cves': [],
        'default_creds': [('root', ''), ('admin', '')],
        'nmap_scripts': ['rlogin-brute'],
        'remediation': 'Disable rlogin immediately. Replace with SSH.',
        'active_check': None,
        'service_keywords': ['rlogin', 'login'],
    },
    514: {
        'name': 'rsh / Syslog',
        'severity': 'critical',
        'issues': [
            'rsh allows remote command execution without encryption',
            '.rhosts-based trust can bypass all authentication',
            'Syslog on UDP 514 receives logs with no authentication',
        ],
        'cves': [],
        'default_creds': [],
        'nmap_scripts': ['rsh-brute'],
        'remediation': 'Disable rsh. Replace with SSH. Secure syslog with TLS (RFC 5425).',
        'active_check': None,
        'service_keywords': ['rsh', 'shell', 'syslog'],
    },
    873: {
        'name': 'rsync',
        'severity': 'critical',
        'issues': [
            'rsync daemon may allow anonymous read/write access',
            'Full filesystem access possible if misconfigured',
            'No encryption — data transferred in plaintext',
        ],
        'cves': [
            ('CVE-2014-9512', 'high', 'rsync file overwrite via symlink attack'),
        ],
        'default_creds': [('', ''), ('rsync', ''), ('backup', '')],
        'nmap_scripts': ['rsync-list-modules', 'rsync-brute'],
        'remediation': 'Require authentication for all modules. Restrict to trusted IPs. Use SSH-wrapped rsync.',
        'active_check': None,
        'service_keywords': ['rsync'],
    },
    993: {
        'name': 'IMAPS',
        'severity': 'medium',
        'issues': [
            'Weak TLS configuration may be present',
            'Susceptible to brute-force attacks',
            'Certificate may be self-signed or expired',
        ],
        'cves': [
            ('CVE-2021-38371', 'high', 'Cyrus IMAP authentication bypass'),
        ],
        'default_creds': [],
        'nmap_scripts': ['imap-brute', 'ssl-enum-ciphers'],
        'remediation': 'Enforce TLS 1.2+. Use strong cipher suites. Implement account lockout on repeated failures.',
        'active_check': None,
        'service_keywords': ['imaps', 'imap', 'dovecot'],
    },
    995: {
        'name': 'POP3S',
        'severity': 'medium',
        'issues': [
            'Weak TLS configuration may be present',
            'Susceptible to brute-force attacks',
        ],
        'cves': [],
        'default_creds': [],
        'nmap_scripts': ['pop3-brute', 'ssl-enum-ciphers'],
        'remediation': 'Enforce TLS 1.2+. Implement account lockout on repeated failures.',
        'active_check': None,
        'service_keywords': ['pop3s', 'pop3'],
    },
    1080: {
        'name': 'SOCKS Proxy',
        'severity': 'high',
        'issues': [
            'Open SOCKS proxy allows anyone to route traffic through this host',
            'Can be used to bypass firewalls and access internal networks',
            'Commonly abused for spam, DDoS, and data exfiltration',
        ],
        'cves': [],
        'default_creds': [('', ''), ('admin', 'admin')],
        'nmap_scripts': ['socks-open-proxy'],
        'remediation': 'Disable the SOCKS proxy or restrict to authenticated, trusted clients.',
        'active_check': None,
        'service_keywords': ['socks', 'proxy'],
    },
    1433: {
        'name': 'MSSQL',
        'severity': 'high',
        'issues': [
            'Database exposed directly to network',
            'sa (system admin) account may have weak password',
            'xp_cmdshell may be enabled — allows OS command execution',
            'MSSQL browser service may reveal instance names',
        ],
        'cves': [
            ('CVE-2020-0618', 'high',     'SQL Server Reporting Services remote code execution'),
            ('CVE-2019-1068', 'high',     'Microsoft SQL Server remote code execution'),
            ('CVE-2012-1823', 'critical', 'PHP CGI argument injection — often affects MSSQL apps'),
        ],
        'default_creds': [('sa', ''), ('sa', 'sa'), ('sa', 'password'), ('admin', 'admin')],
        'nmap_scripts': ['ms-sql-info', 'ms-sql-empty-password', 'ms-sql-xp-cmdshell', 'ms-sql-brute'],
        'remediation': 'Do not expose MSSQL to public internet. Use strong sa password. Disable xp_cmdshell.',
        'active_check': None,
        'service_keywords': ['mssql', 'sql server', 'microsoft sql', 'ms-sql'],
    },
    1521: {
        'name': 'Oracle DB',
        'severity': 'high',
        'issues': [
            'Oracle TNS listener may allow remote poisoning',
            'Default accounts may be present (scott/tiger, sys/change_on_install)',
            'SID enumeration possible via TNS listener',
            'Remote OS authentication may be enabled',
        ],
        'cves': [
            ('CVE-2012-1675', 'high',    'Oracle TNS Listener poisoning attack'),
            ('CVE-2009-1979', 'critical','Oracle Database server buffer overflow'),
            ('CVE-2006-0265', 'critical','Oracle Database multiple unspecified vulnerabilities'),
        ],
        'default_creds': [('scott', 'tiger'), ('sys', 'change_on_install'), ('system', 'manager'), ('dbsnmp', 'dbsnmp'), ('outln', 'outln')],
        'nmap_scripts': ['oracle-sid-brute', 'oracle-tns-version', 'oracle-brute'],
        'remediation': 'Change all default passwords. Restrict TNS listener access. Apply latest Oracle patches.',
        'active_check': None,
        'service_keywords': ['oracle', 'tns', 'tnslsnr'],
    },
    2049: {
        'name': 'NFS',
        'severity': 'critical',
        'issues': [
            'NFS exports may be world-readable or world-writable',
            'no_root_squash option allows remote root access to the share',
            'Data transferred in plaintext — no encryption',
            'Stale NFS file handles may allow unauthorized access',
        ],
        'cves': [
            ('CVE-2017-7895', 'critical', 'Linux kernel NFSv2/v3 buffer overflow via crafted request'),
            ('CVE-2006-3005', 'medium',   'NFS ACL bypass in Linux kernel'),
        ],
        'default_creds': [],
        'nmap_scripts': ['nfs-ls', 'nfs-showmount', 'nfs-statfs'],
        'remediation': 'Restrict NFS exports to specific IPs. Enable root_squash. Use NFSv4 with Kerberos. Block from public networks.',
        'active_check': None,
        'service_keywords': ['nfs', 'mountd'],
    },
    2181: {
        'name': 'ZooKeeper',
        'severity': 'critical',
        'issues': [
            'No authentication by default — full read/write to all znodes',
            'Stores sensitive cluster configuration and credentials',
            'Used by Kafka, Hadoop, Mesos — compromise affects the entire cluster',
        ],
        'cves': [
            ('CVE-2019-0201', 'high',   'Apache ZooKeeper information disclosure via getACL'),
            ('CVE-2017-5637', 'high',   'Apache ZooKeeper denial of service via watcher manipulation'),
        ],
        'default_creds': [('', '')],
        'nmap_scripts': ['zookeeper-info'],
        'remediation': 'Enable ZooKeeper auth (digest or Kerberos). Restrict to internal networks. Enable ACLs on all znodes.',
        'active_check': None,
        'service_keywords': ['zookeeper', 'zk'],
    },
    2375: {
        'name': 'Docker (Unauthenticated)',
        'severity': 'critical',
        'issues': [
            'Docker daemon exposed without TLS — full container management without auth',
            'Attacker can launch containers with host filesystem mounted',
            'Trivial privilege escalation to root on the host via container escape',
            'Actively exploited by cryptomining botnets',
        ],
        'cves': [
            ('CVE-2019-5736', 'critical', 'runc container escape — host root RCE'),
            ('CVE-2020-15257', 'high',    'containerd API exposure in host network mode'),
        ],
        'default_creds': [],
        'nmap_scripts': ['http-title'],
        'remediation': 'Never expose Docker daemon to public. Use TLS client certs. Use Docker socket proxy or rootless Docker.',
        'active_check': None,
        'service_keywords': ['docker'],
    },
    2376: {
        'name': 'Docker (TLS)',
        'severity': 'high',
        'issues': [
            'Docker daemon with TLS — still a high-value target',
            'Weak or self-signed certs may allow MITM',
            'Certificate theft provides full cluster access',
        ],
        'cves': [
            ('CVE-2019-5736', 'critical', 'runc container escape — host root RCE'),
        ],
        'default_creds': [],
        'nmap_scripts': ['ssl-enum-ciphers'],
        'remediation': 'Use strong TLS certificates. Rotate client certificates regularly. Restrict network access.',
        'active_check': None,
        'service_keywords': ['docker'],
    },
    3000: {
        'name': 'Grafana / Dev Server',
        'severity': 'high',
        'issues': [
            'Grafana default credentials admin/admin may be set',
            'Development servers (Node.js, Rails) may expose debug info',
            'Grafana datasources may grant database access',
        ],
        'cves': [
            ('CVE-2021-43798', 'critical', 'Grafana path traversal — read arbitrary files via plugin URL'),
            ('CVE-2022-21703', 'high',     'Grafana CSRF and privilege escalation'),
            ('CVE-2021-39226', 'critical', 'Grafana snapshot authentication bypass'),
        ],
        'default_creds': [('admin', 'admin'), ('admin', 'password'), ('grafana', 'grafana')],
        'nmap_scripts': ['http-title', 'http-auth-finder'],
        'remediation': 'Change default admin password. Disable anonymous access. Keep Grafana updated. Restrict network access.',
        'active_check': 'http_info',
        'service_keywords': ['grafana', 'http', 'node', 'rails', 'web'],
    },
    3306: {
        'name': 'MySQL',
        'severity': 'high',
        'issues': [
            'Database exposed directly to network',
            'Root account may have empty or weak password',
            'Anonymous users may be configured',
            'FILE privilege may allow reading arbitrary files',
            'INTO OUTFILE may allow writing files to the server',
        ],
        'cves': [
            ('CVE-2021-27928', 'high',    'MariaDB wsrep provider command execution'),
            ('CVE-2016-6662',  'critical','MySQL configuration file injection leads to RCE'),
            ('CVE-2012-2122',  'critical','MySQL authentication bypass via timing attack'),
            ('CVE-2016-6663',  'high',    'MySQL race condition privilege escalation'),
            ('CVE-2016-6664',  'high',    'MySQL root privilege escalation via error log'),
        ],
        'default_creds': [('root', ''), ('root', 'root'), ('root', 'password'), ('admin', 'admin'), ('mysql', 'mysql')],
        'nmap_scripts': ['mysql-info', 'mysql-empty-password', 'mysql-brute', 'mysql-enum', 'mysql-databases'],
        'remediation': 'Bind MySQL to 127.0.0.1. Use strong root password. Remove anonymous users. Run mysql_secure_installation.',
        'active_check': None,
        'service_keywords': ['mysql', 'mariadb'],
    },
    3389: {
        'name': 'RDP',
        'severity': 'critical',
        'issues': [
            'BlueKeep (CVE-2019-0708) may be unpatched — wormable RCE',
            'Susceptible to brute-force and credential stuffing attacks',
            'NLA (Network Level Authentication) may not be enforced',
            'DejaBlue and related vulnerabilities in older Windows versions',
            'Pass-the-hash attacks possible without NLA',
        ],
        'cves': [
            ('CVE-2019-0708', 'critical', 'BlueKeep — pre-auth RDP remote code execution (wormable)'),
            ('CVE-2019-1181', 'critical', 'DejaBlue — RDP heap overflow pre-authentication'),
            ('CVE-2019-1182', 'critical', 'DejaBlue variant — RDP remote code execution'),
            ('CVE-2022-21893','high',     'Windows RDP license manager elevation of privilege'),
            ('CVE-2023-35332','high',     'Windows RDP security feature bypass'),
        ],
        'default_creds': [('administrator', 'administrator'), ('administrator', 'password'), ('admin', 'admin')],
        'nmap_scripts': ['rdp-enum-encryption', 'rdp-vuln-ms12-020'],
        'remediation': 'Patch BlueKeep. Enforce NLA. Use VPN for RDP access. Enable account lockout. Use strong passwords.',
        'active_check': None,
        'service_keywords': ['rdp', 'remote desktop', 'ms-wbt-server', 'terminal services'],
    },
    4848: {
        'name': 'GlassFish Admin',
        'severity': 'critical',
        'issues': [
            'GlassFish admin console may use default credentials',
            'Admin access allows deploying arbitrary WAR files — RCE',
            'Often left exposed without authentication',
        ],
        'cves': [
            ('CVE-2011-1511', 'critical', 'GlassFish admin console authentication bypass'),
            ('CVE-2017-1000028', 'high',  'Oracle GlassFish Server path traversal'),
        ],
        'default_creds': [('admin', 'admin'), ('admin', 'adminadmin'), ('admin', '')],
        'nmap_scripts': ['http-title', 'http-auth-finder'],
        'remediation': 'Change default credentials. Restrict admin console to localhost. Disable if not required.',
        'active_check': 'http_info',
        'service_keywords': ['glassfish', 'http'],
    },
    5432: {
        'name': 'PostgreSQL',
        'severity': 'high',
        'issues': [
            'Database exposed directly to network',
            'Default postgres user may have weak or no password',
            'COPY TO/FROM PROGRAM may allow OS command execution',
            'pg_hba.conf may use trust authentication',
        ],
        'cves': [
            ('CVE-2023-2454',  'high',    'PostgreSQL schema manipulation allows privilege escalation'),
            ('CVE-2019-9193',  'high',    'PostgreSQL COPY TO/FROM PROGRAM arbitrary OS command execution'),
            ('CVE-2018-1058',  'high',    'PostgreSQL search_path schema injection'),
            ('CVE-2016-5423',  'high',    'PostgreSQL row security policy bypass'),
        ],
        'default_creds': [('postgres', 'postgres'), ('postgres', ''), ('postgres', 'password'), ('admin', 'admin')],
        'nmap_scripts': ['pgsql-brute'],
        'remediation': 'Bind to localhost only. Use strong passwords. Restrict pg_hba.conf. Disable superuser remote access.',
        'active_check': None,
        'service_keywords': ['postgres', 'postgresql'],
    },
    5601: {
        'name': 'Kibana',
        'severity': 'high',
        'issues': [
            'Kibana may expose all Elasticsearch data without authentication',
            'Timelion and Canvas features have had RCE vulnerabilities',
            'Prototype pollution vulnerabilities in older versions',
        ],
        'cves': [
            ('CVE-2019-7609', 'critical', 'Kibana Timelion RCE via prototype pollution'),
            ('CVE-2022-23707', 'medium',  'Kibana XSS in TSVB visualization'),
        ],
        'default_creds': [('elastic', 'changeme'), ('kibana', 'kibana'), ('admin', 'admin')],
        'nmap_scripts': ['http-title', 'http-auth-finder'],
        'remediation': 'Enable X-Pack security. Set strong passwords. Restrict to internal network. Keep Kibana updated.',
        'active_check': 'http_info',
        'service_keywords': ['kibana', 'http'],
    },
    5900: {
        'name': 'VNC',
        'severity': 'critical',
        'issues': [
            'Often configured with no or weak password',
            'Traffic may not be encrypted — full screen captured in transit',
            'Full graphical desktop access if compromised',
            'Actively targeted by botnets and ransomware operators',
        ],
        'cves': [
            ('CVE-2006-2369',  'critical', 'RealVNC authentication bypass — bypasses password entirely'),
            ('CVE-2019-15681', 'high',     'LibVNCServer memory leak — information disclosure'),
            ('CVE-2018-7225',  'critical', 'LibVNCServer out-of-bounds write RCE'),
            ('CVE-2020-29260', 'high',     'LibVNCClient memory corruption'),
        ],
        'default_creds': [('', ''), ('admin', 'admin'), ('password', 'password'), ('vnc', 'vnc')],
        'nmap_scripts': ['vnc-info', 'vnc-brute', 'vnc-title', 'realvnc-auth-bypass'],
        'remediation': 'Set a strong VNC password. Tunnel VNC over SSH. Restrict access by IP or firewall.',
        'active_check': None,
        'service_keywords': ['vnc', 'rfb'],
    },
    5984: {
        'name': 'CouchDB',
        'severity': 'critical',
        'issues': [
            'CouchDB may be accessible without authentication',
            'Admin party mode — any user is admin by default if not configured',
            '_utils (Fauxton) web admin accessible remotely',
            'All databases readable and writable without credentials',
        ],
        'cves': [
            ('CVE-2017-12635', 'critical', 'CouchDB privilege escalation via crafted JSON PUT request'),
            ('CVE-2017-12636', 'critical', 'CouchDB query server command injection — OS RCE'),
        ],
        'default_creds': [('', ''), ('admin', 'admin'), ('couchdb', 'couchdb')],
        'nmap_scripts': ['http-title'],
        'remediation': 'Set admin credentials immediately. Bind to localhost. Disable admin party mode.',
        'active_check': 'http_info',
        'service_keywords': ['couchdb', 'http'],
    },
    6000: {
        'name': 'X11',
        'severity': 'critical',
        'issues': [
            'X11 display server exposed — allows capturing the screen and injecting keystrokes',
            'No authentication if xhost + is set',
            'Full GUI control of the remote desktop possible',
        ],
        'cves': [
            ('CVE-2018-14665', 'critical', 'Xorg X11 privilege escalation via -modulepath flag'),
        ],
        'default_creds': [],
        'nmap_scripts': ['x11-access'],
        'remediation': 'Never expose X11 to the network. Use SSH X11 forwarding instead. Disable xhost + entirely.',
        'active_check': None,
        'service_keywords': ['x11', 'xorg', 'x-window'],
    },
    6379: {
        'name': 'Redis',
        'severity': 'critical',
        'issues': [
            'Redis is almost always configured with no authentication by default',
            'CONFIG SET can write files to disk — allows SSH key injection or cron-based RCE',
            'Exposed Redis instances are actively targeted by cryptominers and botnets',
            'SLAVEOF command can replicate data to attacker-controlled server',
        ],
        'cves': [
            ('CVE-2022-0543',  'critical', 'Lua sandbox escape in Redis — remote code execution'),
            ('CVE-2021-32761', 'high',     'Redis integer overflow in GETDEL command'),
            ('CVE-2021-32626', 'high',     'Redis Lua script heap overflow'),
            ('CVE-2021-32672', 'medium',   'Redis out-of-bounds read in RAND commands'),
        ],
        'default_creds': [('', ''), ('default', ''), ('redis', 'redis')],
        'nmap_scripts': ['redis-info', 'redis-brute'],
        'remediation': 'Require AUTH password. Bind to 127.0.0.1. Disable dangerous commands (CONFIG, SLAVEOF, DEBUG).',
        'active_check': 'redis_noauth',
        'service_keywords': ['redis'],
    },
    6443: {
        'name': 'Kubernetes API',
        'severity': 'critical',
        'issues': [
            'Kubernetes API server exposed — full cluster control if authenticated',
            'Anonymous access may be enabled',
            'RBAC misconfigurations may grant excessive permissions',
            'Service account tokens in pods may allow lateral movement',
        ],
        'cves': [
            ('CVE-2018-1002105', 'critical', 'Kubernetes API server privilege escalation via backend connection'),
            ('CVE-2019-11247',   'high',     'Kubernetes API server allows access to custom resources at wrong path'),
            ('CVE-2020-8558',    'high',     'Kubernetes node bypass — access to localhost services via route'),
        ],
        'default_creds': [],
        'nmap_scripts': ['ssl-enum-ciphers', 'http-title'],
        'remediation': 'Disable anonymous access. Enforce RBAC. Use network policies. Enable audit logging.',
        'active_check': None,
        'service_keywords': ['kubernetes', 'k8s', 'kube'],
    },
    7001: {
        'name': 'WebLogic',
        'severity': 'critical',
        'issues': [
            'WebLogic admin console may use default credentials',
            'Java deserialization vulnerabilities are extremely common in WebLogic',
            'IIOP and T3 protocols expose deserialization attack surface',
            'JNDI injection vulnerabilities present in multiple versions',
        ],
        'cves': [
            ('CVE-2023-21839', 'critical', 'Oracle WebLogic Server JNDI injection RCE'),
            ('CVE-2021-2109',  'high',     'Oracle WebLogic console JNDI injection'),
            ('CVE-2020-14882', 'critical', 'Oracle WebLogic console authentication bypass + RCE'),
            ('CVE-2019-2725',  'critical', 'Oracle WebLogic deserialization RCE via wls9_async'),
            ('CVE-2017-10271', 'critical', 'Oracle WebLogic WLS-WSAT deserialization RCE'),
        ],
        'default_creds': [('weblogic', 'weblogic'), ('weblogic', 'weblogic1'), ('system', 'weblogic')],
        'nmap_scripts': ['http-title', 'http-auth-finder'],
        'remediation': 'Apply Oracle CPU patches immediately. Disable T3/IIOP if not needed. Restrict admin console access.',
        'active_check': 'http_info',
        'service_keywords': ['weblogic', 'http', 'oracle'],
    },
    8009: {
        'name': 'AJP',
        'severity': 'critical',
        'issues': [
            'Ghostcat vulnerability allows reading any file from the web application',
            'AJP connector should never be exposed to the internet',
            'May allow RCE if file upload is enabled on the target',
        ],
        'cves': [
            ('CVE-2020-1938', 'critical', 'Apache Tomcat AJP Ghostcat — arbitrary file read and RCE'),
        ],
        'default_creds': [],
        'nmap_scripts': ['ajp-headers', 'ajp-request'],
        'remediation': 'Disable AJP connector in server.xml if not required. Use secret attribute if AJP is needed.',
        'active_check': None,
        'service_keywords': ['ajp', 'tomcat'],
    },
    8080: {
        'name': 'HTTP-Alt',
        'severity': 'medium',
        'issues': [
            'Admin panels (Tomcat Manager, Jenkins, etc.) often on this port',
            'Development servers may expose debug endpoints',
            'No TLS encryption',
            'Jenkins may allow unauthenticated script console access',
        ],
        'cves': [
            ('CVE-2020-1938', 'critical', 'Apache Tomcat AJP Ghostcat — file read and RCE'),
            ('CVE-2019-0232', 'critical', 'Apache Tomcat CGI Servlet RCE on Windows'),
            ('CVE-2019-1003000','critical','Jenkins sandbox bypass — remote code execution'),
            ('CVE-2018-1000861','critical','Jenkins Stapler web framework RCE'),
        ],
        'default_creds': [('admin', 'admin'), ('tomcat', 'tomcat'), ('admin', 'password'), ('manager', 'manager'), ('jenkins', 'jenkins')],
        'nmap_scripts': ['http-methods', 'http-title', 'http-auth-finder', 'http-default-accounts'],
        'remediation': 'Restrict access. Change default credentials. Keep application server updated.',
        'active_check': 'http_info',
        'service_keywords': ['http', 'apache', 'nginx', 'tomcat', 'jetty', 'web', 'httpd', 'jenkins'],
    },
    8161: {
        'name': 'ActiveMQ',
        'severity': 'critical',
        'issues': [
            'ActiveMQ web console uses default admin/admin credentials',
            'Java deserialization vulnerabilities are critical in ActiveMQ',
            'Unauthenticated access to message queues may expose sensitive data',
        ],
        'cves': [
            ('CVE-2023-46604', 'critical', 'Apache ActiveMQ RCE via ClassInfo OpenWire protocol — actively exploited'),
            ('CVE-2016-3088',  'critical', 'Apache ActiveMQ fileserver REST API arbitrary file write'),
            ('CVE-2015-5254',  'high',     'Apache ActiveMQ Java deserialization RCE'),
        ],
        'default_creds': [('admin', 'admin'), ('user', 'user')],
        'nmap_scripts': ['http-title', 'http-auth-finder'],
        'remediation': 'Patch to latest ActiveMQ. Change default credentials. Restrict web console access.',
        'active_check': 'http_info',
        'service_keywords': ['activemq', 'http'],
    },
    8443: {
        'name': 'HTTPS-Alt',
        'severity': 'medium',
        'issues': [
            'Management interfaces (Kubernetes, VMware, etc.) often on this port',
            'Weak TLS configuration may be present',
            'Admin panels may use default credentials',
        ],
        'cves': [
            ('CVE-2021-21985', 'critical', 'VMware vCenter Server RCE via vSAN Health Check plugin'),
            ('CVE-2021-22005', 'critical', 'VMware vCenter arbitrary file upload RCE'),
            ('CVE-2021-21972', 'critical', 'VMware vCenter vROps plugin unauthenticated file upload RCE'),
        ],
        'default_creds': [('admin', 'admin'), ('administrator', 'password')],
        'nmap_scripts': ['ssl-enum-ciphers', 'http-auth-finder', 'http-title'],
        'remediation': 'Restrict management port access. Apply vendor patches. Enforce strong TLS.',
        'active_check': 'http_info',
        'service_keywords': ['https', 'http', 'ssl', 'tls', 'web'],
    },
    8500: {
        'name': 'Consul / Vault',
        'severity': 'critical',
        'issues': [
            'HashiCorp Consul HTTP API may be unauthenticated',
            'Consul service mesh allows registering arbitrary services and executing commands',
            'Vault unsealed without auth allows reading all secrets',
        ],
        'cves': [
            ('CVE-2021-37219', 'high', 'HashiCorp Consul privilege escalation via token manipulation'),
            ('CVE-2020-13170', 'high', 'HashiCorp Consul ACL bypass via intent propagation'),
        ],
        'default_creds': [('', ''), ('root', '')],
        'nmap_scripts': ['http-title'],
        'remediation': 'Enable ACLs in Consul. Use Vault auto-unseal carefully. Restrict API to internal network only.',
        'active_check': 'http_info',
        'service_keywords': ['consul', 'vault', 'http'],
    },
    9000: {
        'name': 'SonarQube / PHP-FPM',
        'severity': 'high',
        'issues': [
            'SonarQube may allow unauthenticated access to code analysis results',
            'PHP-FPM exposed to network allows direct code execution',
            'Default SonarQube credentials admin/admin may be set',
        ],
        'cves': [
            ('CVE-2021-44228', 'critical', 'Log4Shell — JNDI injection (affects SonarQube using Log4j)'),
            ('CVE-2020-27955', 'high',     'SonarQube authentication bypass in token validation'),
        ],
        'default_creds': [('admin', 'admin'), ('sonar', 'sonar')],
        'nmap_scripts': ['http-title', 'http-auth-finder'],
        'remediation': 'Change default credentials. Restrict access. Disable PHP-FPM external access.',
        'active_check': 'http_info',
        'service_keywords': ['sonarqube', 'sonar', 'http', 'php-fpm'],
    },
    9042: {
        'name': 'Cassandra',
        'severity': 'critical',
        'issues': [
            'Cassandra may be configured with no authentication',
            'All keyspaces readable/writable without credentials',
            'Default superuser cassandra/cassandra may be active',
        ],
        'cves': [
            ('CVE-2020-17514', 'high', 'Apache Cassandra auth bypass in some configurations'),
        ],
        'default_creds': [('cassandra', 'cassandra'), ('admin', 'admin')],
        'nmap_scripts': ['cassandra-info', 'cassandra-brute'],
        'remediation': 'Enable authentication and authorisation. Change default superuser. Bind to internal network.',
        'active_check': None,
        'service_keywords': ['cassandra'],
    },
    9092: {
        'name': 'Apache Kafka',
        'severity': 'high',
        'issues': [
            'Kafka brokers often have no authentication configured',
            'All topics readable and writable without credentials',
            'Sensitive data streams may be intercepted',
            'Consumer group manipulation may cause application disruption',
        ],
        'cves': [
            ('CVE-2023-25194', 'high',   'Apache Kafka Connect JNDI injection RCE'),
            ('CVE-2018-17196', 'medium', 'Apache Kafka authorization bypass in topic ACLs'),
        ],
        'default_creds': [],
        'nmap_scripts': ['kafka-info'],
        'remediation': 'Enable SASL authentication. Configure ACLs. Enable TLS for in-transit encryption.',
        'active_check': None,
        'service_keywords': ['kafka'],
    },
    9200: {
        'name': 'Elasticsearch',
        'severity': 'critical',
        'issues': [
            'Elasticsearch has no authentication by default in older versions',
            'All data is readable without credentials',
            'Groovy/Painless script execution may allow RCE',
            'Massively exploited by ransomware groups',
            'Snapshot/restore APIs can be abused for data exfiltration',
        ],
        'cves': [
            ('CVE-2021-22145', 'medium',  'Elasticsearch sensitive information disclosure in logs'),
            ('CVE-2015-1427',  'critical', 'Elasticsearch Groovy sandbox escape — RCE'),
            ('CVE-2014-3120',  'critical', 'Elasticsearch dynamic script RCE'),
        ],
        'default_creds': [('', ''), ('elastic', 'changeme'), ('elastic', 'elastic')],
        'nmap_scripts': ['http-title', 'http-auth-finder'],
        'remediation': 'Enable X-Pack security. Set strong elastic password. Bind to localhost. Never expose to internet.',
        'active_check': 'http_info',
        'service_keywords': ['elasticsearch', 'elastic'],
    },
    10250: {
        'name': 'Kubernetes Kubelet',
        'severity': 'critical',
        'issues': [
            'Kubelet API may allow unauthenticated pod listing and exec',
            '/exec endpoint allows running commands in any pod on the node',
            '/logs endpoint may expose sensitive container logs',
            'Node compromise enables lateral movement across the cluster',
        ],
        'cves': [
            ('CVE-2019-11248', 'high', 'Kubernetes kubelet /debug/pprof exposed without authentication'),
            ('CVE-2018-1002103','high', 'Minikube dashboard proxy accessible to all local IPs'),
        ],
        'default_creds': [],
        'nmap_scripts': ['http-title', 'ssl-enum-ciphers'],
        'remediation': 'Enable Kubelet authentication and authorisation. Disable anonymous access. Use network policies.',
        'active_check': None,
        'service_keywords': ['kubelet', 'kubernetes', 'k8s'],
    },
    11211: {
        'name': 'Memcached',
        'severity': 'critical',
        'issues': [
            'Memcached has no authentication — all cached data accessible without credentials',
            'Used for amplification DDoS attacks — up to 51,000x amplification',
            'Sensitive application data (sessions, tokens) may be cached and readable',
            'flush_all command can wipe all cached data causing application outage',
        ],
        'cves': [
            ('CVE-2022-48571', 'high',    'Memcached NULL pointer dereference DoS'),
            ('CVE-2018-1000115','critical','Memcached UDP amplification — publicly exposed instances'),
        ],
        'default_creds': [],
        'nmap_scripts': ['memcached-info'],
        'remediation': 'Bind to 127.0.0.1. Enable SASL authentication. Block UDP port 11211 at firewall.',
        'active_check': None,
        'service_keywords': ['memcached'],
    },
    27017: {
        'name': 'MongoDB',
        'severity': 'critical',
        'issues': [
            'MongoDB has no authentication enabled by default',
            'All databases accessible without credentials',
            'Billions of records have been exposed via misconfigured MongoDB',
            'Actively targeted by ransomware wipers',
        ],
        'cves': [
            ('CVE-2021-32036', 'medium', 'MongoDB denial of service via crafted aggregation request'),
            ('CVE-2019-2386',  'medium', 'MongoDB auth bypass in SCRAM-SHA-256 mechanism'),
            ('CVE-2013-2132',  'high',   'MongoDB denial of service via invalid regular expression'),
        ],
        'default_creds': [('', ''), ('admin', 'admin'), ('root', 'root')],
        'nmap_scripts': ['mongodb-info', 'mongodb-databases', 'mongodb-brute'],
        'remediation': 'Enable --auth. Create admin users. Bind to 127.0.0.1. Enable TLS. Never expose to internet.',
        'active_check': None,
        'service_keywords': ['mongodb', 'mongo'],
    },
    50000: {
        'name': 'SAP / Jenkins',
        'severity': 'critical',
        'issues': [
            'SAP Management Console — exposes instance information without auth',
            'Jenkins may run on port 50000 (JNLP agent port)',
            'SAP ICM or Message Server may be accessible',
        ],
        'cves': [
            ('CVE-2020-6287', 'critical', 'SAP NetWeaver RECON — unauthenticated admin user creation'),
            ('CVE-2018-1000861','critical','Jenkins Stapler RCE via crafted URL'),
        ],
        'default_creds': [('admin', 'admin'), ('SAP*', '06071992'), ('DDIC', '19920706')],
        'nmap_scripts': ['http-title', 'http-sap-netweaver-leak'],
        'remediation': 'Apply SAP patches immediately. Restrict agent port. Change default SAP credentials.',
        'active_check': 'http_info',
        'service_keywords': ['sap', 'jenkins', 'http'],
    },
    50070: {
        'name': 'Hadoop NameNode',
        'severity': 'critical',
        'issues': [
            'Hadoop web UI typically requires no authentication',
            'Full visibility into HDFS file system including sensitive data files',
            'May allow browsing and downloading HDFS files',
            'YARN Resource Manager may allow arbitrary code execution via job submission',
        ],
        'cves': [
            ('CVE-2017-7669', 'high', 'Apache Hadoop path traversal in HDFS web UI'),
        ],
        'default_creds': [('', '')],
        'nmap_scripts': ['http-title'],
        'remediation': 'Enable Kerberos authentication. Enable HDFS encryption. Restrict Hadoop services to internal network.',
        'active_check': 'http_info',
        'service_keywords': ['hadoop', 'hdfs', 'http'],
    },
    61616: {
        'name': 'ActiveMQ OpenWire',
        'severity': 'critical',
        'issues': [
            'ActiveMQ OpenWire protocol port — actively exploited for RCE',
            'CVE-2023-46604 is trivially exploitable with public PoC',
            'No authentication required in default configurations',
        ],
        'cves': [
            ('CVE-2023-46604', 'critical', 'Apache ActiveMQ RCE via ClassInfo OpenWire — actively exploited in the wild'),
            ('CVE-2015-5254',  'high',     'Apache ActiveMQ Java deserialization RCE'),
        ],
        'default_creds': [],
        'nmap_scripts': ['activemq-info'],
        'remediation': 'Patch to ActiveMQ 5.15.16 / 5.16.7 / 5.17.6 / 5.18.3 or later immediately. Restrict port to internal network.',
        'active_check': None,
        'service_keywords': ['activemq'],
    },
}

SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}


def _service_matches(detected_service, banner, keywords):
    combined = (detected_service + ' ' + banner).lower()
    if not combined.strip():
        return True  # No info — assume match
    return any(kw in combined for kw in keywords)


def check(ip, port, service, state, live=False):
    port = int(port)
    db_entry = VULN_DB.get(port)

    result = {
        'port': port,
        'service': service,
        'ip': ip,
        'banner': '',
        'in_database': db_entry is not None,
        'severity': 'info',
        'issues': [],
        'cves': [],
        'default_creds': [],
        'nmap_scripts': [],
        'remediation': '',
        'active_findings': [],
        'has_active_check': False,
        'service_match': True,
        'match_warning': '',
    }

    # Always grab banner first (needed for service matching)
    result['banner'] = _grab_banner(ip, port)

    if db_entry:
        result['severity']       = db_entry['severity']
        result['issues']         = db_entry['issues']
        result['cves']           = [{'id': c[0], 'severity': c[1], 'description': c[2]} for c in db_entry['cves']]
        result['default_creds']  = [{'user': c[0], 'pass': c[1]} for c in db_entry['default_creds']]
        result['nmap_scripts']   = db_entry['nmap_scripts']
        result['remediation']    = db_entry['remediation']
        result['has_active_check'] = db_entry.get('active_check') is not None

        # Service matching — only show CVEs/attack surface when service confirms it
        keywords = db_entry.get('service_keywords', [db_entry['name'].lower()])
        match = _service_matches(service, result['banner'], keywords)
        result['service_match'] = match
        if not match:
            result['match_warning'] = (
                f"Detected service '{service}' may not match expected '{db_entry['name']}'. "
                f"CVEs and attack surface shown for reference — verify manually."
            )

        # Active checks only when explicitly requested
        if live:
            active = db_entry.get('active_check')
            if active == 'anon_ftp':
                result['active_findings'].extend(_check_anon_ftp(ip, port))
            elif active == 'http_info':
                result['active_findings'].extend(_check_http(ip, port))
            elif active == 'redis_noauth':
                result['active_findings'].extend(_check_redis(ip, port))
    else:
        result['issues'] = [f'Port {port} ({service}) has no specific vulnerability data in the local database.']
        result['remediation'] = 'Investigate the service manually. Ensure it is intentionally exposed and up to date.'

    return result


def _grab_banner(ip, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        probes = {
            80:   b'HEAD / HTTP/1.0\r\n\r\n',
            8080: b'HEAD / HTTP/1.0\r\n\r\n',
            8443: b'HEAD / HTTP/1.0\r\n\r\n',
            9200: b'GET / HTTP/1.0\r\n\r\n',
        }
        if port in probes:
            s.send(probes[port])
        banner = s.recv(512).decode('utf-8', errors='ignore').strip()
        s.close()
        return banner[:300]
    except Exception:
        return ''


def _check_anon_ftp(ip, port):
    findings = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((ip, port))
        banner = s.recv(256).decode('utf-8', errors='ignore').strip()
        s.send(b'USER anonymous\r\n')
        r1 = s.recv(256).decode('utf-8', errors='ignore').strip()
        s.send(b'PASS anonymous@\r\n')
        r2 = s.recv(256).decode('utf-8', errors='ignore').strip()
        s.close()
        if r2.startswith('230'):
            findings.append({'type': 'critical', 'msg': 'ANONYMOUS LOGIN ENABLED — FTP accessible without credentials'})
        else:
            findings.append({'type': 'info', 'msg': 'Anonymous login rejected'})
    except Exception as e:
        findings.append({'type': 'info', 'msg': f'FTP active check failed: {e}'})
    return findings


def _check_http(ip, port):
    findings = []
    try:
        import requests
        import urllib3
        urllib3.disable_warnings()
        scheme = 'https' if port in (443, 8443) else 'http'
        url = f'{scheme}://{ip}:{port}'
        r = requests.get(url, timeout=5, verify=False, allow_redirects=True)
        server = r.headers.get('Server', '')
        powered = r.headers.get('X-Powered-By', '')
        if server:
            findings.append({'type': 'medium', 'msg': f'Server header discloses: {server}'})
        if powered:
            findings.append({'type': 'medium', 'msg': f'X-Powered-By discloses: {powered}'})
        if r.status_code == 200:
            findings.append({'type': 'info', 'msg': f'HTTP {r.status_code} — {len(r.content)} bytes returned'})
        for path in ['/manager/html', '/admin', '/wp-admin', '/phpmyadmin', '/.git/HEAD', '/actuator', '/console']:
            try:
                pr = requests.get(url + path, timeout=3, verify=False, allow_redirects=False)
                if pr.status_code in (200, 401, 403):
                    findings.append({'type': 'high', 'msg': f'Interesting path found: {path} → HTTP {pr.status_code}'})
            except Exception:
                pass
    except Exception as e:
        findings.append({'type': 'info', 'msg': f'HTTP active check failed: {e}'})
    return findings


def _check_redis(ip, port):
    findings = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, port))
        s.send(b'PING\r\n')
        r = s.recv(64).decode('utf-8', errors='ignore').strip()
        s.close()
        if '+PONG' in r:
            findings.append({'type': 'critical', 'msg': 'REDIS RESPONDS WITHOUT AUTHENTICATION — full read/write access'})
        else:
            findings.append({'type': 'info', 'msg': 'Redis requires authentication (NOAUTH response)'})
    except Exception as e:
        findings.append({'type': 'info', 'msg': f'Redis active check failed: {e}'})
    return findings
