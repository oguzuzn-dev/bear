import asyncio
import logging
import signal
import sys
from pathlib import Path

from config.settings import HONEYPOT_CONFIG
from core.ssh_server import SSHHoneypot
from core.telnet_server import TelnetHoneypot
from utils.logger import setup_logger


class HoneypotManager:
    
    def __init__(self):
        self.ssh_server = None
        self.telnet_server = None
        self.running = False
        self.logger = setup_logger('honeypot_manager')
        
    async def start_services(self):
        try:
            self.logger.info("Honeypot servisleri başlatılıyor...")
            
            if HONEYPOT_CONFIG['ssh']['enabled']:
                self.ssh_server = SSHHoneypot()
                await self.ssh_server.start()
                self.logger.info(f"SSH Honeypot başlatıldı - Port: {HONEYPOT_CONFIG['ssh']['port']}")
            
            if HONEYPOT_CONFIG['telnet']['enabled']:
                self.telnet_server = TelnetHoneypot()
                await self.telnet_server.start()
                self.logger.info(f"Telnet Honeypot başlatıldı - Port: {HONEYPOT_CONFIG['telnet']['port']}")
            
            self.running = True
            self.logger.info("Tüm honeypot servisleri aktif")
            
        except Exception as e:
            self.logger.error(f"Servis başlatma hatası: {e}")
            await self.stop_services()
            
    async def stop_services(self):
        self.logger.info("Honeypot servisleri durduruluyor...")
        self.running = False
        
        if self.ssh_server:
            await self.ssh_server.stop()
            self.logger.info("SSH Honeypot durduruldu")
            
        if self.telnet_server:
            await self.telnet_server.stop()
            self.logger.info("Telnet Honeypot durduruldu")
            
    def setup_signal_handlers(self):
        def signal_handler(signum, frame):
            self.logger.info(f"Sinyal alındı: {signum}")
            asyncio.create_task(self.stop_services())
            
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
    async def run(self):
        self.setup_signal_handlers()
        await self.start_services()
        
        try:
            while self.running:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt alındı")
        finally:
            await self.stop_services()


async def main():
    Path(HONEYPOT_CONFIG['logging']['log_dir']).mkdir(parents=True, exist_ok=True)
    
    manager = HoneypotManager()
    await manager.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nHoneypot durduruldu.")
        sys.exit(0)
    except Exception as e:
        print(f"Kritik hata: {e}")
        sys.exit(1)