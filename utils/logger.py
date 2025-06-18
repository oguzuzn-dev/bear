import logging
import logging.handlers
import json
import time
from pathlib import Path
from typing import Dict, Any

from config.settings import HONEYPOT_CONFIG


class HoneypotFormatter(logging.Formatter):
    
    def format(self, record):
        log_entry = {
            'timestamp': time.time(),
            'datetime': self.formatTime(record),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }
        
        if hasattr(record, 'client_ip'):
            log_entry['client_ip'] = record.client_ip
        if hasattr(record, 'username'):
            log_entry['username'] = record.username
        if hasattr(record, 'command'):
            log_entry['command'] = record.command
        if hasattr(record, 'protocol'):
            log_entry['protocol'] = record.protocol
        if hasattr(record, 'session_id'):
            log_entry['session_id'] = record.session_id
            
        return json.dumps(log_entry, ensure_ascii=False)


def setup_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    
    if logger.handlers:
        return logger
        
    logger.setLevel(getattr(logging, HONEYPOT_CONFIG['logging']['log_level']))
    
    log_dir = Path(HONEYPOT_CONFIG['logging']['log_dir'])
    log_dir.mkdir(parents=True, exist_ok=True)
    
    json_handler = logging.handlers.RotatingFileHandler(
        filename=log_dir / f"{name}.json",
        maxBytes=HONEYPOT_CONFIG['logging']['max_file_size'],
        backupCount=HONEYPOT_CONFIG['logging']['backup_count'],
        encoding='utf-8'
    )
    json_handler.setFormatter(HoneypotFormatter())
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter(
        HONEYPOT_CONFIG['logging']['log_format'],
        HONEYPOT_CONFIG['logging']['date_format']
    )
    console_handler.setFormatter(console_formatter)
    
    logger.addHandler(json_handler)
    logger.addHandler(console_handler)
    
    return logger


def log_attack_attempt(client_ip: str, protocol: str, username: str, 
                      password: str, success: bool = False):
    logger = setup_logger('attack_attempts')
    
    log_data = {
        'client_ip': client_ip,
        'protocol': protocol,
        'username': username,
        'password': password,
        'success': success,
        'timestamp': time.time()
    }
    
    if success:
        logger.warning(f"Başarılı giriş - {protocol} - {client_ip} - {username}:{password}")
    else:
        logger.info(f"Başarısız giriş - {protocol} - {client_ip} - {username}:{password}")


def log_command_execution(client_ip: str, protocol: str, username: str, 
                         command: str, output: str = ""):
    logger = setup_logger('commands')
    
    dangerous_commands = ['rm', 'rmdir', 'wget', 'curl', 'nc', 'python', 'bash', 'sh']
    is_dangerous = any(cmd in command.lower() for cmd in dangerous_commands)
    
    log_level = logging.WARNING if is_dangerous else logging.INFO
    
    logger.log(log_level, f"Komut çalıştırıldı - {protocol} - {client_ip} - {username} - {command}")
    
    if output and len(output) > 100:  
        output_logger = setup_logger('command_outputs')
        output_logger.info(f"Çıktı - {client_ip} - {command} - {output[:500]}...")


def log_session_summary(client_ip: str, protocol: str, username: str, 
                       duration: float, command_count: int, commands: list):
    logger = setup_logger('sessions')
    
    logger.info(f"Oturum özeti - {protocol} - {client_ip} - {username} - "
                f"Süre: {duration:.2f}s - Komut sayısı: {command_count}")
    
    if commands:
        logger.info(f"Komut listesi - {client_ip} - {', '.join(commands[:20])}")


class SecurityLogger:
    
    def __init__(self):
        self.logger = setup_logger('security')
        
    def log_rate_limit_exceeded(self, client_ip: str, connection_count: int):
        self.logger.warning(f"Rate limit aşıldı - IP: {client_ip}, Bağlantı: {connection_count}")
        
    def log_ip_blocked(self, client_ip: str, reason: str):
        self.logger.warning(f"IP yasaklandı - IP: {client_ip}, Sebep: {reason}")
        
    def log_suspicious_activity(self, client_ip: str, activity: str, details: Dict[str, Any]):
        self.logger.error(f"Şüpheli aktivite - IP: {client_ip}, Aktivite: {activity}, "
                         f"Detaylar: {json.dumps(details)}")
        
    def log_multiple_failed_logins(self, client_ip: str, attempt_count: int, time_window: int):
        self.logger.warning(f"Çoklu başarısız giriş - IP: {client_ip}, "
                           f"Deneme: {attempt_count}, Süre: {time_window}s")


security_logger = SecurityLogger()