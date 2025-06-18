import time
from collections import defaultdict, deque
from typing import Dict, Set
from threading import Lock

from config.settings import HONEYPOT_CONFIG
from utils.logger import setup_logger


class SessionManager:
    
    def __init__(self):
        self.logger = setup_logger('session_manager')
        self.lock = Lock()
        
        self.active_connections: Dict[str, int] = defaultdict(int)
        
        self.connection_times: Dict[str, deque] = defaultdict(deque)
        
        self.blocked_ips: Set[str] = set(HONEYPOT_CONFIG['security']['blocked_ips'])
        
        self.allowed_ips: Set[str] = set(HONEYPOT_CONFIG['security']['allowed_ips'])
        
        self.current_ip = None
        
    def set_current_ip(self, ip: str):
        self.current_ip = ip
        
    def get_current_ip(self) -> str:
        return self.current_ip
        
    def is_ip_allowed(self, ip: str) -> bool:
        if ip in self.blocked_ips:
            self.logger.warning(f"Yasaklı IP bağlantı denemesi: {ip}")
            return False
            
        if self.allowed_ips and ip not in self.allowed_ips:
            self.logger.warning(f"İzin verilmeyen IP bağlantı denemesi: {ip}")
            return False
            
        return True
        
    def check_rate_limit(self, ip: str) -> bool:
        if not HONEYPOT_CONFIG['security']['rate_limit']['enabled']:
            return True
            
        current_time = time.time()
        time_window = HONEYPOT_CONFIG['security']['rate_limit']['time_window']
        max_connections = HONEYPOT_CONFIG['security']['rate_limit']['max_connections_per_ip']
        
        with self.lock:
            while (self.connection_times[ip] and 
                   current_time - self.connection_times[ip][0] > time_window):
                self.connection_times[ip].popleft()
                
            if len(self.connection_times[ip]) >= max_connections:
                self.logger.warning(f"Rate limit aşıldı - IP: {ip}, Bağlantı sayısı: {len(self.connection_times[ip])}")
                return False
                
            self.connection_times[ip].append(current_time)
            
        return True
        
    def can_connect(self, ip: str) -> bool:
        self.set_current_ip(ip)
        
        if not self.is_ip_allowed(ip):
            return False
            
        if not self.check_rate_limit(ip):
            return False
            
        max_connections = HONEYPOT_CONFIG['ssh']['max_connections']
        total_connections = sum(self.active_connections.values())
        
        if total_connections >= max_connections:
            self.logger.warning(f"Maksimum bağlantı sayısı aşıldı: {total_connections}")
            return False
            
        return True
        
    def add_connection(self, ip: str):
        with self.lock:
            self.active_connections[ip] += 1
            total = sum(self.active_connections.values())
            self.logger.info(f"Bağlantı eklendi - IP: {ip}, Bu IP'den: {self.active_connections[ip]}, Toplam: {total}")
            
    def remove_connection(self, ip: str):
        with self.lock:
            if ip in self.active_connections:
                self.active_connections[ip] -= 1
                if self.active_connections[ip] <= 0:
                    del self.active_connections[ip]
                    
            total = sum(self.active_connections.values())
            self.logger.info(f"Bağlantı kaldırıldı - IP: {ip}, Kalan toplam: {total}")
            
    def get_connection_stats(self) -> Dict:
        with self.lock:
            total_connections = sum(self.active_connections.values())
            unique_ips = len(self.active_connections)
            
            return {
                'total_connections': total_connections,
                'unique_ips': unique_ips,
                'connections_per_ip': dict(self.active_connections),
                'blocked_ips_count': len(self.blocked_ips),
                'allowed_ips_count': len(self.allowed_ips) if self.allowed_ips else 'unlimited'
            }
            
    def block_ip(self, ip: str, reason: str = "Manual block"):
        with self.lock:
            self.blocked_ips.add(ip)
            self.logger.warning(f"IP yasaklandı - IP: {ip}, Sebep: {reason}")
            
    def unblock_ip(self, ip: str):
        with self.lock:
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
                self.logger.info(f"IP yasağı kaldırıldı: {ip}")
                
    def cleanup_old_records(self):
        current_time = time.time()
        time_window = HONEYPOT_CONFIG['security']['rate_limit']['time_window']
        
        with self.lock:
            for ip in list(self.connection_times.keys()):
                while (self.connection_times[ip] and 
                       current_time - self.connection_times[ip][0] > time_window):
                    self.connection_times[ip].popleft()
                    
                if not self.connection_times[ip]:
                    del self.connection_times[ip]