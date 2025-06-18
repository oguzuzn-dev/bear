import asyncio
import logging
from typing import Optional

from config.settings import HONEYPOT_CONFIG, FAKE_USERS
from core.fake_shell import FakeShell
from utils.logger import setup_logger
from utils.session_manager import SessionManager


class TelnetSession:
    
    def __init__(self, reader, writer, client_ip: str, session_manager: SessionManager):
        self.reader = reader
        self.writer = writer
        self.client_ip = client_ip
        self.session_manager = session_manager
        self.logger = setup_logger(f'telnet_session_{client_ip}')
        self.authenticated = False
        self.username = None
        self.shell = None
        self.login_attempts = 0
        
    async def send_data(self, data: str):
        try:
            self.writer.write(data.encode('utf-8'))
            await self.writer.drain()
        except Exception as e:
            self.logger.error(f"Veri gönderme hatası: {e}")
            
    async def receive_data(self) -> str:
        try:
            data = await self.reader.readline()
            return data.decode('utf-8').strip()
        except Exception as e:
            self.logger.error(f"Veri alma hatası: {e}")
            return ""
            
    async def authenticate(self):
        await self.send_data(f"\r\n{HONEYPOT_CONFIG['telnet']['banner']}\r\n")
        await self.send_data("login: ")
        
        while not self.authenticated and self.login_attempts < 3:
            try:
                username = await asyncio.wait_for(self.receive_data(), timeout=30)
                if not username:
                    break
                    
                await self.send_data("Password: ")
                
                password = await asyncio.wait_for(self.receive_data(), timeout=30)
                if not password:
                    break
                    
                self.logger.info(f"Telnet giriş denemesi - IP: {self.client_ip}, User: {username}, Pass: {password}")
                
                if username in FAKE_USERS and FAKE_USERS[username] == password:
                    self.authenticated = True
                    self.username = username
                    self.logger.info(f"Telnet girişi başarılı - IP: {self.client_ip}, User: {username}")
                    await self.send_data(f"\r\nWelcome to {HONEYPOT_CONFIG['shell']['hostname']}!\r\n")
                else:
                    self.login_attempts += 1
                    self.logger.info(f"Telnet girişi başarısız - IP: {self.client_ip}, User: {username}")
                    await self.send_data("\r\nLogin incorrect\r\n")
                    if self.login_attempts < 3:
                        await self.send_data("login: ")
                        
            except asyncio.TimeoutError:
                self.logger.warning(f"Telnet kimlik doğrulama zaman aşımı - IP: {self.client_ip}")
                break
            except Exception as e:
                self.logger.error(f"Telnet kimlik doğrulama hatası: {e}")
                break
                
        if not self.authenticated:
            await self.send_data("\r\nToo many login attempts. Connection closed.\r\n")
            
    async def start_shell(self):
        if self.authenticated:
            self.shell = FakeShell(
                client_ip=self.client_ip,
                protocol='Telnet',
                username=self.username,
                session_manager=self.session_manager
            )
            
            await self.shell.start_telnet_session(self.reader, self.writer)
            
    async def handle_session(self):
        try:
            self.logger.info(f"Telnet oturumu başlatıldı - IP: {self.client_ip}")
            
            await self.authenticate()
            
            if self.authenticated:
                await self.start_shell()
                
        except Exception as e:
            self.logger.error(f"Telnet oturum hatası: {e}")
        finally:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except:
                pass
            self.logger.info(f"Telnet oturumu sonlandı - IP: {self.client_ip}")


class TelnetHoneypot:
    
    def __init__(self):
        self.server = None
        self.session_manager = SessionManager()
        self.logger = setup_logger('telnet_honeypot')
        
    async def handle_client(self, reader, writer):
        client_address = writer.get_extra_info('peername')
        client_ip = client_address[0] if client_address else 'unknown'
        
        self.logger.info(f"Yeni Telnet bağlantısı - IP: {client_ip}")
        
        if not self.session_manager.can_connect(client_ip):
            self.logger.warning(f"Telnet bağlantısı reddedildi (rate limit) - IP: {client_ip}")
            writer.close()
            await writer.wait_closed()
            return
            
        self.session_manager.add_connection(client_ip)
        session = TelnetSession(reader, writer, client_ip, self.session_manager)
        
        try:
            await session.handle_session()
        finally:
            self.session_manager.remove_connection(client_ip)
            
    async def start(self):
        try:
            self.server = await asyncio.start_server(
                self.handle_client,
                host=HONEYPOT_CONFIG['telnet']['host'],
                port=HONEYPOT_CONFIG['telnet']['port']
            )
            
            self.logger.info(f"Telnet Honeypot başlatıldı - {HONEYPOT_CONFIG['telnet']['host']}:{HONEYPOT_CONFIG['telnet']['port']}")
            
        except Exception as e:
            self.logger.error(f"Telnet sunucu başlatma hatası: {e}")
            raise
            
    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.logger.info("Telnet sunucu durduruldu")