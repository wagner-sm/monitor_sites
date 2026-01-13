"""
Website Monitor - Versão com Anti-Bot Protection
Melhorias para contornar bloqueios 403
"""

import os
import sys
import json
import logging
import hashlib
import re
import signal
import threading
import time
import random
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from zoneinfo import ZoneInfo
from email.header import Header
from email.utils import formataddr

LOCAL_TZ = ZoneInfo("America/Sao_Paulo")

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logging.error("Requests library not available. Cannot continue.")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    logging.warning("BeautifulSoup not available. Content extraction will be limited.")

from difflib import SequenceMatcher


@dataclass
class MonitorResult:
    """Resultado do monitoramento de um site"""
    url: str
    success: bool
    content: str = ""
    error: str = ""
    response_time: float = 0.0
    status_code: int = 0
    content_length: int = 0


@dataclass
class ChangeDetection:
    """Informações sobre mudança detectada"""
    url: str
    old_hash: str
    new_hash: str
    change_ratio: float
    is_significant: bool
    diff_content: str
    timestamp: datetime


class ConfigManager:
    """Gerenciador de configurações com validação"""
    
    REQUIRED_KEYS = ['URLS', 'EMAIL_RECIPIENTS', 'HASH_FILE']
    DEFAULT_CONFIG = {
        'MAX_WORKERS': 5,
        'MAX_RETRIES': 3,
        'REQUEST_TIMEOUT': 30,
        'MIN_CONTENT_LENGTH': 100,
        'MIN_SIMILARITY_THRESHOLD': 0.95,
        'MIN_SIZE_CHANGE_RATIO': 0.02,
        'DELETE_HASH_ON_START': False,
        'RATE_LIMIT_DELAY': 1.0,
        'USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'EMAIL_RATE_LIMIT': 10,
        'LOG_LEVEL': 'INFO',
        'NORMALIZE_CASE': True,
        'SORT_CONTENT_LINES': True,
        'USE_ROTATING_USER_AGENTS': True,
        'RANDOM_DELAY_MIN': 2,
        'RANDOM_DELAY_MAX': 5
    }
    
    @classmethod
    def load_config(cls, path: str) -> Dict:
        """Carrega e valida configuração"""
        config_path = Path(os.getenv('MONITOR_CONFIG_PATH', path))
        
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in config file: {e}")
        except IOError as e:
            raise IOError(f"Error reading config file: {e}")
        
        # Validar chaves obrigatórias
        for key in cls.REQUIRED_KEYS:
            if key not in config:
                raise KeyError(f"Missing required config key: {key}")
        
        # Aplicar valores padrão
        for key, default_value in cls.DEFAULT_CONFIG.items():
            config.setdefault(key, default_value)
        
        # Validações específicas
        cls._validate_config(config)
        
        # Converter caminhos relativos para absolutos
        cls._resolve_paths(config)
        
        return config
    
    @classmethod
    def _validate_config(cls, config: Dict):
        """Valida configurações específicas"""
        if not isinstance(config['URLS'], list) or not config['URLS']:
            raise ValueError("URLS must be a non-empty list")
        
        if not isinstance(config['EMAIL_RECIPIENTS'], list) or not config['EMAIL_RECIPIENTS']:
            raise ValueError("EMAIL_RECIPIENTS must be a non-empty list")
        
        # Validar URLs
        for url in config['URLS']:
            if not isinstance(url, str) or not url.startswith(('http://', 'https://')):
                raise ValueError(f"Invalid URL: {url}")
        
        # Validar thresholds
        if not 0 <= config.get('MIN_SIMILARITY_THRESHOLD', 0.95) <= 1:
            raise ValueError("MIN_SIMILARITY_THRESHOLD must be between 0 and 1")
        
        if not 0 <= config.get('MIN_SIZE_CHANGE_RATIO', 0.02) <= 1:
            raise ValueError("MIN_SIZE_CHANGE_RATIO must be between 0 and 1")
    
    @classmethod
    def _resolve_paths(cls, config: Dict):
        """Resolve caminhos relativos para absolutos"""
        base_dir = Path(__file__).parent.absolute()
        
        for key in ['HASH_FILE', 'CONTENT_FILE', 'LOG_FILE']:
            if key in config and not Path(config[key]).is_absolute():
                config[key] = str(base_dir / config[key])


class UserAgentRotator:
    """Rotacionador de User-Agents realistas"""
    
    USER_AGENTS = [
        # Chrome on Windows
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        
        # Firefox on Windows
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
        
        # Edge on Windows
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
        
        # Chrome on Mac
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        
        # Safari on Mac
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
        
        # Chrome on Linux
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    ]
    
    @classmethod
    def get_random(cls) -> str:
        """Retorna um User-Agent aleatório"""
        return random.choice(cls.USER_AGENTS)


class ContentNormalizer:
    """Normalizador de conteúdo ultra-robusto para evitar falsos positivos"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.patterns = [
            # Timestamps completos e variações
            (re.compile(r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}(?:\s+\d{1,2}:\d{2}(?::\d{2})?)?\b'), ''),
            (re.compile(r'\b\d{4}[/-]\d{1,2}[/-]\d{1,2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)?\b'), ''),
            (re.compile(r'\b\d{1,2}:\d{2}(?::\d{2})?(?:\s*[AP]M)?\b', re.I), ''),
            
            # Timestamps Unix e milissegundos
            (re.compile(r'\b\d{10,13}\b'), ''),
            
            # IDs, hashes e tokens longos
            (re.compile(r'\b[a-fA-F0-9]{16,}\b'), ''),
            (re.compile(r'\b[A-Z0-9]{20,}\b'), ''),
            
            # Parâmetros de URL dinâmicos
            (re.compile(r'[?&](_|t|v|ts|cache|rand|random|sid|session|sessionid|token|csrf|nonce|timestamp|version|rev|build|_t|_v)=[^&\s]*', re.I), ''),
            
            # GUIDs e UUIDs
            (re.compile(r'\b[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\b'), ''),
            
            # Números de versão dinâmicos
            (re.compile(r'\bv?\d+\.\d+\.\d+(?:\.\d+)?\b'), ''),
            
            # Contadores e visualizações
            (re.compile(r'\b\d+\s*(?:views?|visualizações|visualizacoes|acessos|clicks?|curtidas?|likes?|shares?|comentários?|comments?)\b', re.I), 'N_COUNT'),
            (re.compile(r'\b(?:views?|visualizações|visualizacoes|acessos|clicks?):\s*\d+\b', re.I), 'COUNT:N'),
            
            # Datas relativas
            (re.compile(r'\b(?:hoje|ontem|amanhã|yesterday|today|tomorrow|há|ago|\d+\s*(?:segundo|minuto|hora|dia|semana|mes|ano|second|minute|hour|day|week|month|year)s?(?:\s+(?:atrás|ago))?)\b', re.I), 'TIMEREF'),
            
            # Scripts inline e dados JSON
            (re.compile(r'<script[^>]*>.*?</script>', re.DOTALL | re.I), ''),
            (re.compile(r'<style[^>]*>.*?</style>', re.DOTALL | re.I), ''),
            
            # Comentários HTML
            (re.compile(r'<!--.*?-->', re.DOTALL), ''),
            
            # Atributos dinâmicos comuns
            (re.compile(r'\s(?:data-id|data-key|data-index|data-timestamp|data-token|data-session)="[^"]*"', re.I), ''),
            
            # Números de sessão/token
            (re.compile(r'(?:token|csrf|session)[_-]?\w*[=:]\w+', re.I), 'TOKEN'),
            
            # Espaços múltiplos e tabulações
            (re.compile(r'\s+'), ' '),
            
            # Linhas vazias múltiplas
            (re.compile(r'\n\s*\n+'), '\n'),
        ]
        
        # Cache para performance
        self._cache: Dict[str, str] = {}
        self._cache_max_size = 500
    
    def normalize(self, text: str) -> str:
        """Normaliza texto de forma ultra-agressiva"""
        if not text:
            return ""
        
        # Verificar cache
        text_hash = hashlib.md5(text.encode()).hexdigest()[:12]
        if text_hash in self._cache:
            return self._cache[text_hash]
        
        # Passo 1: Aplicar todos os padrões
        normalized = text
        for pattern, replacement in self.patterns:
            normalized = pattern.sub(replacement, normalized)
        
        # Passo 2: Normalizar quebras de linha e espaços
        normalized = normalized.strip()
        
        # Passo 3: Filtrar linhas válidas
        lines = []
        seen_lines = set()
        
        for line in normalized.split('\n'):
            line = line.strip()
            
            if len(line) < 5 or self._is_noise_line(line):
                continue
            
            clean_line = self._normalize_line(line)
            
            if clean_line and clean_line not in seen_lines:
                seen_lines.add(clean_line)
                lines.append(clean_line)
        
        # Passo 4: Ordenar linhas
        if self.config.get('SORT_CONTENT_LINES', True):
            lines.sort()
        
        result = '\n'.join(lines)
        
        # Adicionar ao cache
        if len(self._cache) < self._cache_max_size:
            self._cache[text_hash] = result
        
        return result
    
    def _normalize_line(self, line: str) -> str:
        """Normaliza uma linha individual"""
        line = re.sub(r'[^\w\s\-]', ' ', line)
        line = re.sub(r'\s+', ' ', line).strip()
        
        if self.config.get('NORMALIZE_CASE', True):
            line = line.lower()
        
        return line
    
    def _is_noise_line(self, line: str) -> bool:
        """Identifica linhas que são ruído"""
        noise_patterns = [
            r'^[\s\-_=•·]+$',
            r'^\d+$',
            r'^[^\w\s]+$',
            r'^(loading|carregando|aguarde|wait|please wait)\.{3,}$',
            r'^(página|page|pag)\s*\d+$',
            r'^(copyright|©|®|™)',
            r'^(cookie|privacidade|privacy|política|policy)',
            r'^\s*$',
            r'^(menu|search|buscar|busca|login|entrar|sair|logout)$',
        ]
        
        line_lower = line.lower()
        for pattern in noise_patterns:
            if re.match(pattern, line_lower, re.I):
                return True
        
        return False


class EmailNotifier:
    """Sistema de notificação por email"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.email_count = 0
        self.max_emails = config.get('EMAIL_RATE_LIMIT', 10)
        self.last_email_time = {}
        self.min_email_interval = timedelta(minutes=5)
    
    def can_send_email(self, url: str) -> bool:
        """Verifica se pode enviar email (rate limiting)"""
        if self.email_count >= self.max_emails:
            logging.warning(f"Email rate limit reached ({self.max_emails})")
            return False
        
        last_time = self.last_email_time.get(url)
        if last_time and datetime.now(LOCAL_TZ) - last_time < self.min_email_interval:
            logging.info(f"Email cooldown active for {url}")
            return False
        
        return True
    
    def send_notification(self, change: ChangeDetection) -> bool:
        """Envia notificação de mudança"""
        if not self.can_send_email(change.url):
            return False
        
        try:
            success = self._send_email(change)
            if success:
                self.email_count += 1
                self.last_email_time[change.url] = datetime.now(LOCAL_TZ)
                logging.info(f"✅ Email sent for {change.url}")
            return success
        except Exception as e:
            logging.error(f"❌ Email error for {change.url}: {e}")
            return False
    
    def _send_email(self, change: ChangeDetection) -> bool:
        """Envia email com encoding UTF-8"""
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        
        smtp_user = os.getenv("GMAIL_USER", self.config.get("GMAIL_USER"))
        smtp_password = os.getenv("GMAIL_APP_PASSWORD", self.config.get("GMAIL_APP_PASSWORD"))
        
        if not smtp_user or not smtp_password:
            logging.error("Gmail credentials not provided")
            return False
        
        try:
            msg = MIMEMultipart("alternative")
            msg["From"] = formataddr((str(Header("Website Monitor", "utf-8")), smtp_user))
            recipients = self.config["EMAIL_RECIPIENTS"]
            msg["To"] = ", ".join(recipients)
            subject = f"🚨 Mudança Detectada no Site"
            msg["Subject"] = Header(subject, "utf-8")
            
            html_content = self._generate_html_content(change)
            html_part = MIMEText(html_content, "html", "utf-8")
            msg.attach(html_part)
            
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(smtp_user, smtp_password)
                server.sendmail(smtp_user, recipients, msg.as_string())
            
            return True
        
        except Exception as e:
            logging.error(f"Error sending email: {e}")
            return False
    
    def _generate_html_content(self, change: ChangeDetection) -> str:
        """Gera conteúdo HTML do email"""
        detected_at = change.timestamp.strftime('%d/%m/%Y %H:%M:%S')
        display_diff = change.diff_content
        if len(display_diff) > 3000:
            display_diff = f"{display_diff[:3000]}...\n\n<i>(Conteúdo truncado)</i>"
        
        return f"""
        <html>
        <head>
        <meta charset="UTF-8">
        <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background: #f5f5f5; }}
        .container {{ max-width: 800px; margin: 20px auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 25px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 24px; }}
        .content {{ padding: 25px; }}
        .info-card {{ background: #f8f9fa; border-left: 4px solid #007bff; padding: 20px; margin: 15px 0; border-radius: 8px; }}
        .info-card h3 {{ margin-top: 0; color: #495057; }}
        .diff-container {{ background: #f1f3f4; border-radius: 8px; padding: 20px; margin: 20px 0; max-height: 500px; overflow-y: auto; }}
        .diff-content {{ font-family: 'Consolas', 'Monaco', monospace; white-space: pre-wrap; font-size: 13px; line-height: 1.4; }}
        .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .stat {{ text-align: center; padding: 15px; background: #e9ecef; border-radius: 8px; flex: 1; margin: 0 5px; }}
        .stat-value {{ font-size: 24px; font-weight: bold; color: #007bff; }}
        .stat-label {{ font-size: 12px; color: #6c757d; text-transform: uppercase; }}
        .footer {{ background: #6c757d; color: white; padding: 15px; text-align: center; font-size: 14px; }}
        .url-link {{ color: #007bff; text-decoration: none; word-break: break-all; }}
        </style>
        </head>
        <body>
        <div class="container">
        <div class="header">
        <h1>🔔 Mudança Detectada</h1>
        </div>
        <div class="content">
        <div class="info-card">
        <h3>📋 Informações</h3>
        <p><strong>🌐 Site:</strong> <a href="{change.url}" class="url-link">{change.url}</a></p>
        <p><strong>🕐 Data/Hora:</strong> {detected_at}</p>
        </div>
        <div class="stats">
        <div class="stat">
        <div class="stat-value">{change.change_ratio:.1%}</div>
        <div class="stat-label">Diferença</div>
        </div>
        </div>
        <div class="info-card">
        <h3>📝 Mudanças</h3>
        <div class="diff-container">
        <div class="diff-content">{display_diff}</div>
        </div>
        </div>
        </div>
        <div class="footer">
        🤖 Website Monitor
        </div>
        </div>
        </body>
        </html>
        """


class WebsiteMonitor:
    """Monitor de websites com anti-bot protection"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.setup_logging()
        
        self.content_normalizer = ContentNormalizer(config)
        self.email_notifier = EmailNotifier(config)
        
        self.hash_file = Path(config['HASH_FILE'])
        self.content_file = Path(config.get('CONTENT_FILE', 'last_contents.json'))
        
        for file_path in [self.hash_file, self.content_file]:
            file_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.last_hashes = self._load_json_file(self.hash_file)
        self.last_contents = self._load_json_file(self.content_file)
        
        self._stop_event = threading.Event()
        self._setup_signal_handlers()
        self.session = self._create_session()
        
        self.stats = {
            'sites_checked': 0,
            'changes_detected': 0,
            'false_positives_avoided': 0,
            'emails_sent': 0,
            'errors': 0,
            'start_time': datetime.now(LOCAL_TZ)
        }
    
    def setup_logging(self):
        """Configura logging"""
        log_level = getattr(logging, self.config.get('LOG_LEVEL', 'INFO').upper())
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger = logging.getLogger()
        logger.setLevel(log_level)
        logger.handlers.clear()
        logger.addHandler(console_handler)
    
    def _setup_signal_handlers(self):
        """Configura handlers para sinais"""
        def signal_handler(signum, frame):
            logging.info(f"Received signal {signum}, shutting down...")
            self._stop_event.set()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def _create_session(self) -> requests.Session:
        """Cria sessão HTTP com anti-bot protection"""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=self.config['MAX_RETRIES'],
            backoff_factor=2,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Headers mais realistas
        session.headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0'
        })
        
        return session
    
    def _load_json_file(self, file_path: Path) -> Dict:
        """Carrega arquivo JSON"""
        if not file_path.exists():
            return {}
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logging.error(f"Error loading {file_path}: {e}")
            return {}
    
    def _save_json_file(self, file_path: Path, data: Dict):
        """Salva arquivo JSON"""
        try:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logging.debug(f"✅ Saved {file_path.name}: {len(data)} entries")
        except Exception as e:
            logging.error(f"❌ Error saving {file_path}: {e}")
    
    def get_page_content(self, url: str) -> MonitorResult:
        """Obtém conteúdo com anti-bot protection"""
        start_time = time.time()
        
        try:
            # User-Agent rotativo
            if self.config.get('USE_ROTATING_USER_AGENTS', True):
                self.session.headers['User-Agent'] = UserAgentRotator.get_random()
            
            # Delay aleatório para parecer mais humano
            delay = random.uniform(
                self.config.get('RANDOM_DELAY_MIN', 2),
                self.config.get('RANDOM_DELAY_MAX', 5)
            )
            time.sleep(delay)
            
            # Adicionar Referer para parecer navegação natural
            self.session.headers['Referer'] = url.rsplit('/', 1)[0] + '/'
            
            response = self.session.get(
                url,
                timeout=self.config['REQUEST_TIMEOUT'],
                allow_redirects=True
            )
            
            response.raise_for_status()
            
            return MonitorResult(
                url=url,
                success=True,
                content=response.text,
                status_code=response.status_code,
                content_length=len(response.text),
                response_time=time.time() - start_time
            )
        
        except requests.RequestException as e:
            return MonitorResult(
                url=url,
                success=False,
                error=str(e),
                response_time=time.time() - start_time
            )
    
    def extract_relevant_content(self, url: str, html_content: str) -> str:
        """Extrai conteúdo relevante"""
        if not html_content:
            return ""
        
        try:
            if "cartaometrocard.com.br" in url:
                return self._extract_linhas_info(html_content)
            elif "urbs.curitiba.pr.gov.br" in url:
                return self._extract_urbs_content(html_content)
            return self._extract_standard_content(html_content)
        except Exception as e:
            logging.error(f"Error extracting content from {url}: {e}")
            return ""
    
    def _extract_urbs_content(self, html: str) -> str:
        """Extração específica para URBS"""
        if not BS4_AVAILABLE:
            return self._extract_content_regex(html)
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Remover elementos dinâmicos
            for element in soup(['script', 'style', 'meta', 'link', 'iframe', 'noscript', 'nav', 'footer', 'header']):
                element.decompose()
            
            content_parts = []
            
            # Extrair títulos principais
            for heading in soup.find_all(['h1', 'h2', 'h3']):
                text = heading.get_text(strip=True)
                if text and len(text) > 5:
                    content_parts.append(f"TITLE: {text}")
            
            # Extrair parágrafos
            for p in soup.find_all('p'):
                text = p.get_text(strip=True)
                if text and len(text) > 20:
                    content_parts.append(text)
            
            # Extrair tabelas
            for table in soup.find_all('table'):
                for row in table.find_all('tr'):
                    cells = row.find_all(['td', 'th'])
                    if cells:
                        row_text = ' | '.join(cell.get_text(strip=True) for cell in cells if cell.get_text(strip=True))
                        if row_text:
                            content_parts.append(f"TABLE: {row_text}")
            
            combined = '\n'.join(content_parts)
            return self.content_normalizer.normalize(combined)
        
        except Exception as e:
            logging.error(f"Error extracting URBS content: {e}")
            return self._extract_content_regex(html)
    
    def _extract_standard_content(self, html: str) -> str:
        """Extração padrão de conteúdo"""
        if not BS4_AVAILABLE:
            return self._extract_content_regex(html)
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            for element in soup(['script', 'style', 'meta', 'link', 'iframe', 'noscript', 'nav', 'footer', 'header', 'aside']):
                element.decompose()
            
            content_parts = []
            seen_texts = set()
            
            for element in soup.find_all(['h1', 'h2', 'h3', 'h4', 'p', 'li', 'td', 'th']):
                text = element.get_text(strip=True)
                
                if not text or len(text) < 10:
                    continue
                
                text_key = text[:100].lower()
                if text_key in seen_texts:
                    continue
                
                seen_texts.add(text_key)
                content_parts.append(text)
            
            combined = '\n'.join(content_parts)
            return self.content_normalizer.normalize(combined)
        
        except Exception as e:
            logging.error(f"Error in standard content extraction: {e}")
            return self._extract_content_regex(html)
    
    def _extract_content_regex(self, html: str) -> str:
        """Extração usando regex (fallback)"""
        html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
        html = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL | re.IGNORECASE)
        text_content = re.sub(r'<[^>]+>', ' ', html)
        return self.content_normalizer.normalize(text_content)
    
    def _extract_linhas_info(self, html: str) -> str:
        """Extração para sites de transporte"""
        if not BS4_AVAILABLE:
            return self._extract_content_regex(html)
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            rows = soup.select('table tbody tr, table tr')[:15]
            
            results = []
            for row in rows:
                cells = row.find_all(['td', 'th'])
                if len(cells) >= 2:
                    tipo = (cells[0].get_text(strip=True) if cells[0] else "N/A") or "N/A"
                    linha = (cells[1].get_text(strip=True) if cells[1] else "N/A") or "N/A"
                    link_el = row.find('a')
                    href = (link_el.get('href') if link_el and link_el.get('href') else "") or ""
                    results.append(f"{tipo}-{linha}-{href}")
            
            return self.content_normalizer.normalize('\n'.join(results))
        
        except Exception as e:
            logging.error(f"Error extracting linhas info: {e}")
            return ""
    
    def calculate_content_hash(self, content: str) -> str:
        """Calcula hash do conteúdo"""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()
    
    def detect_change(self, url: str, new_content: str) -> Optional[ChangeDetection]:
        """Detecta mudanças significativas"""
        if not new_content or len(new_content) < self.config['MIN_CONTENT_LENGTH']:
            logging.warning(f"⚠️ Content too short for {url}: {len(new_content)} chars")
            return None
        
        new_hash = self.calculate_content_hash(new_content)
        old_hash = self.last_hashes.get(url, "")
        old_content = self.last_contents.get(url, "")
        
        self.last_contents[url] = new_content
        
        if not old_hash:
            self.last_hashes[url] = new_hash
            logging.info(f"🆕 First check for {url}, storing initial hash")
            return None
        
        if new_hash == old_hash:
            logging.debug(f"✅ No change for {url}")
            return None
        
        logging.info(f"🔍 Hash changed for {url}, validating...")
        
        similarity = self._calculate_similarity(old_content, new_content)
        logging.info(f"   📊 Similarity: {similarity:.2%}")
        
        similarity_threshold = self.config.get('MIN_SIMILARITY_THRESHOLD', 0.95)
        if similarity > similarity_threshold:
            logging.info(f"   ✋ Too similar ({similarity:.2%}), ignoring")
            self.stats['false_positives_avoided'] += 1
            self.last_hashes[url] = new_hash
            return None
        
        if len(new_content) < len(old_content) * 0.3:
            logging.warning(f"   ⚠️ New content too short, ignoring")
            return None
        
        size_diff = abs(len(new_content) - len(old_content))
        size_ratio = size_diff / len(old_content) if old_content else 1
        
        logging.info(f"   📏 Size change: {size_diff} chars ({size_ratio:.2%})")
        
        size_threshold = self.config.get('MIN_SIZE_CHANGE_RATIO', 0.02)
        if size_ratio < size_threshold and similarity > 0.90:
            logging.info(f"   ✋ Change too small, ignoring")
            self.stats['false_positives_avoided'] += 1
            self.last_hashes[url] = new_hash
            return None
        
        logging.info(f"   ✅ Significant change confirmed!")
        
        diff_content = self._generate_diff(old_content, new_content)
        self.last_hashes[url] = new_hash
        
        return ChangeDetection(
            url=url,
            old_hash=old_hash,
            new_hash=new_hash,
            change_ratio=1.0 - similarity,
            is_significant=True,
            diff_content=diff_content,
            timestamp=datetime.now(LOCAL_TZ)
        )
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calcula similaridade entre textos"""
        if not text1 or not text2:
            return 0.0
        try:
            matcher = SequenceMatcher(None, text1, text2)
            return matcher.ratio()
        except Exception as e:
            logging.error(f"Error calculating similarity: {e}")
            return 0.0
    
    def _generate_diff(self, old_content: str, new_content: str, max_lines: int = 30) -> str:
        """Gera diff entre conteúdos"""
        try:
            old_lines = old_content.split('\n')[:max_lines]
            new_lines = new_content.split('\n')[:max_lines]
            
            diff_lines = []
            matcher = SequenceMatcher(None, old_lines, new_lines)
            
            for tag, i1, i2, j1, j2 in matcher.get_opcodes():
                if tag == 'delete':
                    for line in old_lines[i1:i2]:
                        diff_lines.append(f"- {line}")
                elif tag == 'insert':
                    for line in new_lines[j1:j2]:
                        diff_lines.append(f"+ {line}")
                elif tag == 'replace':
                    for line in old_lines[i1:i2]:
                        diff_lines.append(f"- {line}")
                    for line in new_lines[j1:j2]:
                        diff_lines.append(f"+ {line}")
            
            return '\n'.join(diff_lines[:100])
        
        except Exception as e:
            logging.error(f"Error generating diff: {e}")
            return "Erro ao gerar comparação"
    
    def monitor_sites(self):
        """Executa monitoramento de todos os sites"""
        logging.info("🚀 Starting website monitoring (anti-bot protection)...")
        logging.info(f"🔍 Monitoring {len(self.config['URLS'])} sites")
        
        try:
            with ThreadPoolExecutor(max_workers=self.config['MAX_WORKERS']) as executor:
                future_to_url = {
                    executor.submit(self.monitor_single_site, url): url 
                    for url in self.config['URLS']
                }
                
                for future in as_completed(future_to_url):
                    if self._stop_event.is_set():
                        break
                    
                    url = future_to_url[future]
                    try:
                        result = future.result()
                        if result:
                            self.stats['changes_detected'] += 1
                            if self.email_notifier.send_notification(result):
                                self.stats['emails_sent'] += 1
                        
                        self.stats['sites_checked'] += 1
                    
                    except Exception as e:
                        logging.error(f"Error processing {url}: {e}")
                        self.stats['errors'] += 1
                    
                    time.sleep(self.config['RATE_LIMIT_DELAY'])
            
            self._save_data()
            self._log_statistics()
        
        except KeyboardInterrupt:
            logging.info("⏹️ Monitoring stopped by user")
        except Exception as e:
            logging.error(f"❌ Monitoring error: {e}")
            self.stats['errors'] += 1
    
    def monitor_single_site(self, url: str) -> Optional[ChangeDetection]:
        """Monitora um site específico"""
        logging.info(f"🔍 Checking {url}")
        
        try:
            result = self.get_page_content(url)
            
            if not result.success:
                logging.warning(f"⚠️ Failed to fetch {url}: {result.error}")
                return None
            
            relevant_content = self.extract_relevant_content(url, result.content)
            
            if not relevant_content:
                logging.warning(f"⚠️ No content extracted from {url}")
                return None
            
            logging.debug(f"   📄 Extracted {len(relevant_content)} chars")
            
            change = self.detect_change(url, relevant_content)
            
            if change:
                logging.info(f"🔔 Change detected in {url}")
                return change
            else:
                logging.info(f"✅ No changes in {url}")
                return None
        
        except Exception as e:
            logging.error(f"❌ Error monitoring {url}: {e}")
            return None
    
    def _save_data(self):
        """Salva dados de hash e conteúdo"""
        try:
            logging.info("💾 Saving data...")
            self._save_json_file(self.hash_file, self.last_hashes)
            self._save_json_file(self.content_file, self.last_contents)
            logging.info("✅ Data saved successfully")
        except Exception as e:
            logging.error(f"❌ Error saving data: {e}")
    
    def _log_statistics(self):
        """Log de estatísticas"""
        duration = datetime.now(LOCAL_TZ) - self.stats['start_time']
        
        logging.info("")
        logging.info("=" * 60)
        logging.info("📊 Monitoring Statistics:")
        logging.info(f"   ⏱️  Duration: {duration}")
        logging.info(f"   🌐 Sites checked: {self.stats['sites_checked']}")
        logging.info(f"   🔔 Changes detected: {self.stats['changes_detected']}")
        logging.info(f"   🛡️  False positives avoided: {self.stats['false_positives_avoided']}")
        logging.info(f"   📧 Emails sent: {self.stats['emails_sent']}")
        logging.info(f"   ❌ Errors: {self.stats['errors']}")
        logging.info("=" * 60)


def main():
    """Função principal"""
    try:
        config = ConfigManager.load_config('config.json')
        
        if config.get('DELETE_HASH_ON_START', False):
            for file_path in [config['HASH_FILE'], config.get('CONTENT_FILE', '')]:
                if file_path and Path(file_path).exists():
                    Path(file_path).unlink()
                    logging.info(f"🗑️ Deleted {file_path}")
        
        monitor = WebsiteMonitor(config)
        monitor.monitor_sites()
    
    except (FileNotFoundError, ValueError, KeyError, IOError) as e:
        logging.critical(f"❌ Configuration error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logging.info("⏹️ Monitoring stopped by user")
    except Exception as e:
        logging.critical(f"❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
