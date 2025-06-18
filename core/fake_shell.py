import asyncio
import time
import random
from typing import Dict, List, Optional

from config.settings import (
    HONEYPOT_CONFIG, FAKE_FILESYSTEM, FAKE_COMMAND_OUTPUTS, 
    ENVIRONMENT_VARS
)
from utils.logger import setup_logger
from utils.session_manager import SessionManager


class FakeShell:
    
    def __init__(self, client_ip: str, protocol: str, username: str, session_manager: SessionManager):
        self.client_ip = client_ip
        self.protocol = protocol
        self.username = username
        self.session_manager = session_manager
        self.logger = setup_logger(f'shell_{protocol.lower()}_{client_ip}')
        
        self.current_path = ENVIRONMENT_VARS['HOME']
        self.hostname = HONEYPOT_CONFIG['shell']['hostname']
        self.env_vars = ENVIRONMENT_VARS.copy()
        self.command_history = []
        self.session_start_time = time.time()
        
        self.channel = None  
        self.reader = None   
        self.writer = None  
        
    def get_prompt(self) -> str:
        path_display = self.current_path.replace(self.env_vars['HOME'], '~')
        return HONEYPOT_CONFIG['shell']['prompt_format'].format(
            user=self.username,
            hostname=self.hostname,
            path=path_display
        )
        
    async def send_output(self, data: str):
        if self.protocol == 'SSH' and self.channel:
            self.channel.write(data)
        elif self.protocol == 'Telnet' and self.writer:
            try:
                self.writer.write(data.encode('utf-8'))
                await self.writer.drain()
            except Exception as e:
                self.logger.error(f"Telnet çıktı gönderme hatası: {e}")
                
    def parse_command(self, command_line: str) -> tuple:
        parts = command_line.strip().split()
        if not parts:
            return "", []
        return parts[0], parts[1:]
        
    def resolve_path(self, path: str) -> str:
        if path.startswith('/'):
            return path
        elif path == '~':
            return self.env_vars['HOME']
        elif path.startswith('~/'):
            return path.replace('~', self.env_vars['HOME'])
        elif path == '..':
            if self.current_path == '/':
                return '/'
            return '/'.join(self.current_path.split('/')[:-1]) or '/'
        elif path == '.':
            return self.current_path
        else:
            return f"{self.current_path.rstrip('/')}/{path}"
            
    def list_directory(self, path: str) -> List[str]:
        path = path.rstrip('/')
        if path == '':
            path = '/'
            
        if path in FAKE_FILESYSTEM:
            return FAKE_FILESYSTEM[path]
        else:
            fake_files = ['file1.txt', 'file2.log', 'data.conf', 'backup.tar.gz']
            return random.sample(fake_files, random.randint(1, len(fake_files)))
            
    async def execute_command(self, command: str, args: List[str]) -> str:
        full_command = f"{command} {' '.join(args)}".strip()
        
        await asyncio.sleep(HONEYPOT_CONFIG['shell']['command_delay'])
        
        self.logger.info(f"Komut çalıştırıldı - IP: {self.client_ip}, User: {self.username}, Cmd: {full_command}")
        
        if command == 'ls':
            path = args[0] if args else self.current_path
            resolved_path = self.resolve_path(path)
            files = self.list_directory(resolved_path)
            return '  '.join(files)
            
        elif command == 'cd':
            if not args:
                self.current_path = self.env_vars['HOME']
                return ""
            new_path = self.resolve_path(args[0])
            if new_path in FAKE_FILESYSTEM or new_path.startswith('/'):
                self.current_path = new_path
                self.env_vars['PWD'] = new_path
                return ""
            else:
                return f"cd: {args[0]}: No such file or directory"
                
        elif command == 'pwd':
            return self.current_path
            
        elif command == 'whoami':
            return self.username
            
        elif command == 'cat':
            if not args:
                return "cat: missing file operand"
            filename = args[0]
            if filename in ['/etc/passwd', 'passwd']:
                return FAKE_COMMAND_OUTPUTS['cat /etc/passwd']
            elif filename.endswith('.txt'):
                return f"This is the content of {filename}\nSample text file content."
            else:
                return f"cat: {filename}: No such file or directory"
                
        elif command == 'echo':
            return ' '.join(args)
            
        elif command == 'history':
            output = []
            for i, cmd in enumerate(self.command_history[-20:], 1):
                output.append(f"  {i}  {cmd}")
            return '\n'.join(output)
            
        elif command == 'env':
            output = []
            for key, value in self.env_vars.items():
                output.append(f"{key}={value}")
            return '\n'.join(output)
            
        elif command == 'clear':
            return '\033[2J\033[H' 
            
        elif command == 'exit' or command == 'logout':
            return "EXIT_SHELL"
            
        elif full_command in FAKE_COMMAND_OUTPUTS:
            return FAKE_COMMAND_OUTPUTS[full_command]
            
        elif command in ['ps', 'top', 'htop']:
            return FAKE_COMMAND_OUTPUTS['ps aux']
            
        elif command in ['netstat', 'ss']:
            return FAKE_COMMAND_OUTPUTS['netstat -an']
            
        elif command in ['ifconfig', 'ip']:
            return FAKE_COMMAND_OUTPUTS['ifconfig']
            
        elif command in ['df', 'du']:
            return FAKE_COMMAND_OUTPUTS['df -h']
            
        elif command in ['free', 'vmstat']:
            return FAKE_COMMAND_OUTPUTS['free -m']
            
        elif command in ['uname']:
            return FAKE_COMMAND_OUTPUTS['uname -a']
            
        elif command in ['rm', 'rmdir', 'del', 'delete']:
            self.logger.warning(f"TEHLIKELI KOMUT - IP: {self.client_ip}, Cmd: {full_command}")
            if args and '-rf' in ' '.join(args):
                return f"rm: cannot remove '{args[-1]}': Operation not permitted"
            return f"rm: cannot remove '{args[0] if args else 'file'}': No such file or directory"
            
        elif command in ['wget', 'curl', 'download']:
            self.logger.warning(f"İNDİRME KOMUTU - IP: {self.client_ip}, Cmd: {full_command}")
            return f"wget: unable to resolve host address"
            
        elif command in ['nc', 'netcat', 'ncat']:
            self.logger.warning(f"NETWORK KOMUT - IP: {self.client_ip}, Cmd: {full_command}")
            return f"nc: connection refused"
            
        elif command in ['python', 'python3', 'perl', 'php', 'bash', 'sh']:
            self.logger.warning(f"SCRIPT ÇALIŞTIRMA - IP: {self.client_ip}, Cmd: {full_command}")
            return f"{command}: command not found"
            
        else:
            return f"{command}: command not found"
            
    async def handle_input(self, data: str):
        """Girdi işle"""
        if not data:
            return
            
        command_line = data.strip()
        if command_line and command_line not in ['', 'history']:
            self.command_history.append(command_line)
            
        command, args = self.parse_command(command_line)
        
        if command:
            try:
                output = await self.execute_command(command, args)
                
                if output == "EXIT_SHELL":
                    await self.send_output("\r\nGoodbye!\r\n")
                    await self.end_session()
                    return
                    
                if output:
                    await self.send_output(f"\r\n{output}\r\n")
                    
            except Exception as e:
                self.logger.error(f"Komut çalıştırma hatası: {e}")
                await self.send_output(f"\r\nError: {str(e)}\r\n")
                
        await self.send_output(self.get_prompt())
        
    def start_session(self, channel):
        self.channel = channel
        self.logger.info(f"Shell oturumu başlatıldı - IP: {self.client_ip}, Protocol: {self.protocol}")
        
        welcome_msg = f"Last login: {time.strftime('%a %b %d %H:%M:%S %Y')}\r\n"
        self.channel.write(welcome_msg)
        self.channel.write(self.get_prompt())
        
    async def start_telnet_session(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.logger.info(f"Shell oturumu başlatıldı - IP: {self.client_ip}, Protocol: {self.protocol}")
        
        await self.send_output(self.get_prompt())
        
        try:
            while True:
                try:
                    data = await asyncio.wait_for(self.reader.readline(), timeout=300)
                    if not data:
                        break
                    command_line = data.decode('utf-8').strip()
                    await self.handle_input(command_line)
                except asyncio.TimeoutError:
                    self.logger.info(f"Telnet oturum zaman aşımı - IP: {self.client_ip}")
                    break
                except Exception as e:
                    self.logger.error(f"Telnet input hatası: {e}")
                    break
        finally:
            await self.end_session()
            
    async def end_session(self):
        session_duration = time.time() - self.session_start_time
        
        self.logger.info(f"Shell oturumu sonlandı - IP: {self.client_ip}, Süre: {session_duration:.2f}s, Komut sayısı: {len(self.command_history)}")
        
        if self.command_history:
            self.logger.info(f"Komut özeti - IP: {self.client_ip}, Komutlar: {', '.join(self.command_history[:10])}")
            
        if self.protocol == 'SSH' and self.channel:
            try:
                self.channel.close()
            except:
                pass
        elif self.protocol == 'Telnet' and self.writer:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except:
                pass