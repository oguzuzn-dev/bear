import asyncio
import asyncssh
import logging
from pathlib import Path
from typing import Optional

from config.settings import HONEYPOT_CONFIG, FAKE_USERS
from core.fake_shell import FakeShell
from utils.logger import setup_logger
from utils.session_manager import SessionManager


class SSHSession(asyncssh.SSHServerSession):
    
    def __init__(self, client_ip: str, session_manager: SessionManager):
        super().__init__()
        self.client_ip = client_ip
        self.session_manager = session_manager
        self.shell = None
        self.logger = setup_logger(f'ssh_session_{client_ip}')
        self.authenticated = False
        self.username = None
        
    def connection_made(self, chan):
        self.logger.info(f"SSH oturumu başlatıldı - IP: {self.client_ip}")
        self._chan = chan
        
    def shell_requested(self):
        if self.authenticated:
            self.shell = FakeShell(
                client_ip=self.client_ip,
                protocol='SSH',
                username=self.username,
                session_manager=self.session_manager
            )
            return True
        return False
        
    def session_started(self):
        if self.shell:
            self.shell.start_session(self._chan)
            
    def data_received(self, data, datatype):
        if self.shell:
            self.shell.handle_input(data)
            
    def connection_lost(self, exc):
        self.logger.info(f"SSH oturumu sonlandı - IP: {self.client_ip}")
        if self.shell:
            self.shell.end_session()


class SSHServer(asyncssh.SSHServer):
    
    def __init__(self, session_manager: SessionManager):
        self.session_manager = session_manager
        self.logger = setup_logger('ssh_server')
        
    def connection_made(self, conn):
        client_ip = conn.get_extra_info('peername')[0]
        self.logger.info(f"Yeni SSH bağlantısı - IP: {client_ip}")
        
        if not self.session_manager.can_connect(client_ip):
            self.logger.warning(f"Bağlantı reddedildi (rate limit) - IP: {client_ip}")
            conn.close()
            return
            
        self.session_manager.add_connection(client_ip)
        
    def connection_lost(self, conn):
        client_ip = conn.get_extra_info('peername')[0]
        self.session_manager.remove_connection(client_ip)
        
    def begin_auth(self, username):
        return True
        
    def password_auth_supported(self):
        return True
        
    def validate_password(self, username, password):
        client_ip = self.session_manager.get_current_ip()
        
        # bütün girişleri loglama
        self.logger.info(f"SSH giriş denemesi - IP: {client_ip}, User: {username}, Pass: {password}")
        
        if username in FAKE_USERS and FAKE_USERS[username] == password:
            self.logger.info(f"SSH girişi başarılı - IP: {client_ip}, User: {username}")
            return True
        else:
            self.logger.info(f"SSH girişi başarısız - IP: {client_ip}, User: {username}")
            return False
            
    def session_requested(self):
        client_ip = self.session_manager.get_current_ip()
        return SSHSession(client_ip, self.session_manager)


class SSHHoneypot:
    
    def __init__(self):
        self.server = None
        self.session_manager = SessionManager()
        self.logger = setup_logger('ssh_honeypot')
        
    async def generate_host_key(self):
        key_path = HONEYPOT_CONFIG['ssh']['host_key']
        
        key_path.parent.mkdir(parents=True, exist_ok=True)
        
        if not key_path.exists():
            self.logger.info("SSH host key oluşturuluyor...")
            key = asyncssh.generate_private_key('ssh-rsa', key_size=2048)
            key.write_private_key(str(key_path))
            self.logger.info(f"SSH host key oluşturuldu: {key_path}")
            
    async def start(self):
        try:
            await self.generate_host_key()
            
            self.server = await asyncssh.create_server(
                lambda: SSHServer(self.session_manager),
                host=HONEYPOT_CONFIG['ssh']['host'],
                port=HONEYPOT_CONFIG['ssh']['port'],
                server_host_keys=[str(HONEYPOT_CONFIG['ssh']['host_key'])],
                server_version=HONEYPOT_CONFIG['ssh']['banner']
            )
            
            self.logger.info(f"SSH Honeypot başlatıldı - {HONEYPOT_CONFIG['ssh']['host']}:{HONEYPOT_CONFIG['ssh']['port']}")
            
        except Exception as e:
            self.logger.error(f"SSH sunucu başlatma hatası: {e}")
            raise
            
    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.logger.info("SSH sunucu durduruldu")