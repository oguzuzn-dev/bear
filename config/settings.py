import os
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent

HONEYPOT_CONFIG = {
    'ssh': {
        'enabled': True,
        'host': '127.0.0.1',
        'port': 2222,  
        'banner': 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5',
        'host_key': BASE_DIR / 'keys' / 'ssh_host_key',
        'max_connections': 100,
        'connection_timeout': 300,  
    },
    
    'telnet': {
        'enabled': True,
        'host': '127.0.0.1',
        'port': 2323,  
        'banner': 'Ubuntu 20.04.5 LTS',
        'max_connections': 100,
        'connection_timeout': 300,  
    },
    
    'shell': {
        'prompt_format': '{user}@{hostname}:{path}$ ',
        'hostname': 'server01',
        'initial_path': '/home',
        'command_delay': 0.1,  
        'max_command_length': 1000,
    },
    
    'logging': {
        'log_dir': BASE_DIR / 'logs',
        'log_level': 'INFO',
        'max_file_size': 10 * 1024 * 1024,  
        'backup_count': 5,
        'log_format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        'date_format': '%Y-%m-%d %H:%M:%S',
    },
    
    'security': {
        'max_login_attempts': 3,
        'rate_limit': {
            'enabled': True,
            'max_connections_per_ip': 5,
            'time_window': 60,  
        },
        'blocked_ips': [],  
        'allowed_ips': [],   #if its empty everybody can try
    },
    
    'database': {
        'enabled': False,
        'type': 'sqlite',  
        'path': BASE_DIR / 'data' / 'honeypot.db',
        'host': 'localhost',
        'port': 5432,
        'name': 'honeypot',
        'user': 'honeypot',
        'password': 'password',
    }
}

FAKE_USERS = {
    'root': 'toor',
    'admin': 'admin',
    'user': 'password',
    'test': 'test',
    'guest': 'guest',
    'ubuntu': 'ubuntu',
    'pi': 'raspberry',
    'operator': '123456',
    'manager': 'manager',
    'service': 'service123'
}

FAKE_FILESYSTEM = {
    '/': ['bin', 'boot', 'dev', 'etc', 'home', 'lib', 'media', 'mnt', 'opt', 'proc', 'root', 'run', 'sbin', 'srv', 'sys', 'tmp', 'usr', 'var'],
    '/home': ['user', 'admin', 'guest'],
    '/etc': ['passwd', 'shadow', 'hosts', 'fstab', 'crontab', 'ssh'],
    '/var': ['log', 'www', 'lib', 'tmp'],
    '/var/log': ['auth.log', 'syslog', 'messages', 'secure'],
    '/usr': ['bin', 'lib', 'local', 'share'],
    '/usr/bin': ['ls', 'cat', 'grep', 'ps', 'top', 'netstat', 'wget', 'curl'],
    '/bin': ['sh', 'bash', 'ls', 'cat', 'cp', 'mv', 'rm', 'mkdir', 'rmdir'],
    '/sbin': ['ifconfig', 'iptables', 'service', 'systemctl'],
}

FAKE_COMMAND_OUTPUTS = {
    'ls': 'Documents  Downloads  Music  Pictures  Videos',
    'pwd': '/home/user',
    'whoami': 'user',
    'id': 'uid=1000(user) gid=1000(user) groups=1000(user)',
    'uname -a': 'Linux server01 5.4.0-74-generic #83-Ubuntu SMP Sat May 8 02:35:39 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux',
    'ps aux': '''USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 169424  2048 ?        Ss   10:00   0:01 /sbin/init
root         2  0.0  0.0      0     0 ?        S    10:00   0:00 [kthreadd]
user      1234  0.0  0.2  21308  4096 pts/0    Ss   10:30   0:00 -bash''',
    'netstat -an': '''Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN''',
    'ifconfig': '''eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255
        ether 00:0c:29:12:34:56  txqueuelen 1000  (Ethernet)''',
    'df -h': '''Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        20G  8.5G   11G  44% /
tmpfs           2.0G     0  2.0G   0% /dev/shm''',
    'free -m': '''              total        used        free      shared  buff/cache   available
Mem:           3936        1024        1548          12        1364        2648
Swap:          2047           0        2047''',
    'cat /etc/passwd': '''root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
user:x:1000:1000:User:/home/user:/bin/bash''',
}

ENVIRONMENT_VARS = {
    'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    'HOME': '/home/user',
    'USER': 'user',
    'SHELL': '/bin/bash',
    'TERM': 'xterm-256color',
    'LANG': 'en_US.UTF-8',
    'PWD': '/home/user',
}