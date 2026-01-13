"""
Website Monitor - Versão Corrigida (Anti Falsos Positivos)
Monitor de mudanças em websites com notificações por email
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
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

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
        'SORT_CONTENT_LINES': True
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
            
            # Parâmetros de URL dinâmicos (mais completo)
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
        seen_lines = set()  # Evitar duplicatas
        
        for line in normalized.split('\n'):
            line = line.strip()
            
            # Ignorar linhas muito curtas ou ruído
            if len(line) < 5 or self._is_noise_line(line):
                continue
            
            # Normalizar a linha individualmente
            clean_line = self._normalize_line(line)
            
            # Evitar duplicatas
            if clean_line and clean_line not in seen_lines:
                seen_lines.add(clean_line)
                lines.append(clean_line)
        
        # Passo 4: Ordenar linhas para ignorar mudanças de ordem (se configurado)
        if self.config.get('SORT_CONTENT_LINES', True):
            lines.sort()
        
        result = '\n'.join(lines)
        
        # Adicionar ao cache
        if len(self._cache) < self._cache_max_size:
            self._cache[text_hash] = result
        
        return result
    
    def _normalize_line(self, line: str) -> str:
        """Normaliza uma linha individual"""
        # Remover pontuação excessiva
        line = re.sub(r'[^\w\s\-]', ' ', line)
        
        # Normalizar espaços
        line = re.sub(r'\s+', ' ', line).strip()
        
        # Converter para lowercase para ignorar mudanças de capitalização (se configurado)
        if self.config.get('NORMALIZE_CASE', True):
            line = line.lower()
        
        return line
    
    def _is_noise_line(self, line: str) -> bool:
        """Identifica linhas que são ruído"""
        noise_patterns = [
            r'^[\s\-_=•·]+$',  # Apenas caracteres de separação
            r'^\d+$',          # Apenas números
            r'^[^\w\s]+$',     # Apenas símbolos
            r'^(loading|carregando|aguarde|wait|please wait)\.{3,}$',  # Mensagens de loading
            r'^(página|page|pag)\s*\d+$',  # Números de página
            r'^(copyright|©|®|™)',  # Informações de copyright
            r'^(cookie|privacidade|privacy|política|policy)',  # Avisos comuns
            r'^\s*$',  # Linhas vazias
            r'^(menu|search|buscar|busca|login|entrar|sair|logout)$',  # Navegação comum
        ]
        
        line_lower = line.lower()
        for pattern in noise_patterns:
            if re.match(pattern, line_lower, re.I):
                return True
        
        return False


class EmailNotifier:
    """Sistema de notificação por email melhorado"""
    
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
                logging.info(f"? Email sent for {change.url}")
            return success
        except Exception as e:
            logging.error(f"? Email error for {change.url}: {e}")
            return False
    
    def _send_email(self, change: ChangeDetection) -> bool:
        """Envia email usando Gmail"""
        smtp_server = 'smtp.gmail.com'
        smtp_port = 587
        
        smtp_user = os.getenv('GMAIL_USER', self.config.get('GMAIL_USER'))
        smtp_password = os.getenv('GMAIL_APP_PASSWORD', self.config.get('GMAIL_APP_PASSWORD'))
        
        if not smtp_user or not smtp_password:
            logging.error("Gmail credentials not provided")
            return False
        
        # Criar mensagem
        msg = MIMEMultipart('alternative')
        msg['From'] = smtp_user
        msg['To'] = ", ".join(self.config["EMAIL_RECIPIENTS"])
        msg['Subject'] = f"?? Mudança Detectada: {change.url}"
        
        # Gerar conteúdo HTML
        html_content = self._generate_html_content(change)
        msg.attach(MIMEText(html_content, 'html', 'utf-8'))
        
        # Enviar
        try:
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_password)
                server.sendmail(smtp_user, self.config["EMAIL_RECIPIENTS"], msg.as_string())
            return True
        except Exception as e:
            logging.error(f"SMTP error: {e}")
            return False
    
    def _generate_html_content(self, change: ChangeDetection) -> str:
        """Gera conteúdo HTML do email"""
        detected_at = change.timestamp.strftime('%d/%m/%Y %H:%M:%S')
        
        # Truncar diff se muito longo
        display_diff = change.diff_content
        if len(display_diff) > 3000:
            display_diff = f"{display_diff[:3000]}...\n\n<i>(Conteúdo truncado - mudança muito extensa)</i>"
        
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
        .url-link:hover {{ text-decoration: underline; }}
        </style>
        </head>
        <body>
        <div class="container">
        <div class="header">
        <h1>?? Mudança Significativa Detectada</h1>
        </div>
        
        <div class="content">
        <div class="info-card">
        <h3>?? Informações da Detecção</h3>
        <p><strong>?? Site:</strong> <a href="{change.url}" class="url-link" target="_blank">{change.url}</a></p>
        <p><strong>?? Data/Hora:</strong> {detected_at}</p>
        <p><strong>?? Hash Anterior:</strong> <code>{change.old_hash[:16]}...</code></p>
        <p><strong>?? Hash Atual:</strong> <code>{change.new_hash[:16]}...</code></p>
        </div>
        
        <div class="stats">
        <div class="stat">
        <div class="stat-value">{change.change_ratio:.1%}</div>
        <div class="stat-label">Diferença</div>
        </div>
        <div class="stat">
        <div class="stat-value">{'SIM' if change.is_significant else 'NÃO'}</div>
        <div class="stat-label">Significativa</div>
        </div>
        </div>
        
        <div class="info-card">
        <h3>?? Mudanças Detectadas</h3>
        <div class="diff-container">
        <div class="diff-content">{display_diff}</div>
        </div>
        </div>
        </div>
        
        <div class="footer">
        ?? Website Monitor - Versão Anti Falsos Positivos<br>
        <small>Não responda este e-mail</small>
        </div>
        </div>
        </body>
        </html>
        """


class WebsiteMonitor:
    """Monitor de websites com detecção avançada de mudanças"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.setup_logging()
        
        # Inicializar componentes
        self.content_normalizer = ContentNormalizer(config)
        self.email_notifier = EmailNotifier(config)
        
        # Arquivos de dados
        self.hash_file = Path(config['HASH_FILE'])
        self.content_file = Path(config.get('CONTENT_FILE', 'last_contents.json'))
        
        # Criar diretórios se necessário
        for file_path in [self.hash_file, self.content_file]:
            file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Carregar dados existentes
        self.last_hashes = self._load_json_file(self.hash_file)
        self.last_contents = self._load_json_file(self.content_file)
        
        # Controle de execução
        self._stop_event = threading.Event()
        self._setup_signal_handlers()
        
        # Configurar sessão HTTP
        self.session = self._create_session()
        
        # Estatísticas
        self.stats = {
            'sites_checked': 0,
            'changes_detected': 0,
            'false_positives_avoided': 0,
            'emails_sent': 0,
            'errors': 0,
            'start_time': datetime.now(LOCAL_TZ)
        }
    
    def setup_logging(self):
        """Configura logging melhorado"""
        log_level = getattr(logging, self.config.get('LOG_LEVEL', 'INFO').upper())
        
        # Configurar formato
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Handler para console
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        
        # Configurar logger principal
        logger = logging.getLogger()
        logger.setLevel(log_level)
        logger.handlers.clear()
        logger.addHandler(console_handler)
    
    def _setup_signal_handlers(self):
        """Configura handlers para sinais do sistema"""
        def signal_handler(signum, frame):
            logging.info(f"Received signal {signum}, shutting down gracefully...")
            self._stop_event.set()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def _create_session(self) -> requests.Session:
        """Cria sessão HTTP configurada"""
        session = requests.Session()
        
        # Configurar retry strategy
        retry_strategy = Retry(
            total=self.config['MAX_RETRIES'],
            backoff_factor=2,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Headers padrão
        session.headers.update({
            'User-Agent': self.config['USER_AGENT'],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        return session
    
    def _load_json_file(self, file_path: Path) -> Dict:
        """Carrega arquivo JSON com tratamento de erro"""
        if not file_path.exists():
            return {}
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logging.error(f"Error loading {file_path}: {e}")
            return {}
    
    def _save_json_file(self, file_path: Path, data: Dict):
        """Salva arquivo JSON com tratamento de erro"""
        try:
            # Garantir que o diretório existe
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            # DEBUG: Ver o que está sendo salvo
            logging.info(f"?? Attempting to save {file_path.name}: {len(data)} entries")
            
            if not data:
                logging.warning(f"?? Data is empty for {file_path.name}!")
            
            # Tentar serializar primeiro (para detectar erros antes de escrever)
            try:
                json_str = json.dumps(data, indent=2, ensure_ascii=False)
                logging.info(f"   Serialized successfully: {len(json_str)} chars")
            except (TypeError, ValueError) as e:
                logging.error(f"? Cannot serialize data for {file_path.name}: {e}")
                logging.error(f"   Data type: {type(data)}")
                logging.error(f"   First key sample: {list(data.keys())[0] if data else 'N/A'}")
                if data:
                    first_url = list(data.keys())[0]
                    first_value = data[first_url]
                    logging.error(f"   First value type: {type(first_value)}")
                    logging.error(f"   First value length: {len(first_value) if isinstance(first_value, str) else 'N/A'}")
                raise
            
            # Salvar com encoding UTF-8
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(json_str)
            
            # Verificar se salvou corretamente
            file_size = file_path.stat().st_size
            logging.info(f"   ? Saved {file_path.name} ({file_size} bytes)")
            
            # Ler de volta para confirmar
            with open(file_path, 'r', encoding='utf-8') as f:
                verified = json.load(f)
                logging.info(f"   ? Verified: {len(verified)} entries read back")
            
        except IOError as e:
            logging.error(f"? IO Error saving {file_path}: {e}")
            raise
        except Exception as e:
            logging.error(f"? Unexpected error saving {file_path}: {e}")
            import traceback
            logging.error(traceback.format_exc())
            raise
    
    def get_page_content(self, url: str) -> MonitorResult:
        """Obtém conteúdo de uma página"""
        start_time = time.time()
        
        try:
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
        """Extrai conteúdo relevante baseado no tipo de site"""
        if not html_content:
            return ""
        
        try:
            # Estratégias específicas por domínio
            if "cartaometrocard.com.br" in url:
                return self._extract_linhas_info(html_content)
            
            if any(domain in url for domain in self.config.get('SPECIAL_DOMAINS', [])):
                return self._extract_gallery_content(html_content)
            
            # Extração padrão
            return self._extract_standard_content(html_content)
        
        except Exception as e:
            logging.error(f"Error extracting content from {url}: {e}")
            return ""
    
    def _extract_standard_content(self, html: str) -> str:
        """Extração padrão de conteúdo - versão melhorada"""
        if not BS4_AVAILABLE:
            return self._extract_content_regex(html)
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Remover elementos dinâmicos e irrelevantes (lista expandida)
            for element in soup([
                'script', 'style', 'meta', 'link', 'iframe', 'noscript',
                'nav', 'footer', 'header', 'aside', 'svg', 'canvas',
                'ins',  # Ads
                'form',  # Formulários (podem ter tokens CSRF)
                'button',  # Botões (podem ter IDs dinâmicos)
            ]):
                element.decompose()
            
            # Remover elementos com classes/IDs que indicam conteúdo dinâmico
            dynamic_indicators = [
                'ad', 'advertisement', 'banner', 'tracking', 'analytics',
                'cookie', 'popup', 'modal', 'notification', 'toast',
                'counter', 'timer', 'clock', 'date', 'time',
                'social', 'share', 'comment', 'disqus', 'widget',
                'sidebar', 'related', 'recommended'
            ]
            
            for element in soup.find_all(True):
                element_class = ' '.join(element.get('class') or []).lower()
                element_id = (element.get('id') or "").lower()
                
                # Verificar se contém indicadores dinâmicos
                if any(indicator in element_class or indicator in element_id 
                    for indicator in dynamic_indicators):
                    element.decompose()
                    continue
                
                # Remover atributos dinâmicos do elemento
                for attr in ['data-id', 'data-key', 'data-index', 'data-timestamp', 
                            'data-token', 'id', 'class', 'style', 'onclick']:
                    if attr in element.attrs:
                        del element.attrs[attr]
            
            # Extrair conteúdo relevante
            content_parts = []
            seen_texts = set()  # Evitar duplicatas
            
            # Priorizar elementos semânticos importantes
            for element in soup.find_all(['h1', 'h2', 'h3', 'h4', 'p', 'li', 'td', 'th', 'article', 'section']):
                text = element.get_text(strip=True)
                
                # Filtros de qualidade
                if not text or len(text) < 10:
                    continue
                
                # Ignorar textos muito comuns/genéricos
                if text.lower() in ['menu', 'search', 'buscar', 'entrar', 'login', 'cadastro', 
                                    'register', 'sign in', 'sign up']:
                    continue
                
                # Evitar duplicatas
                text_key = text[:100].lower()  # Usar primeiros 100 chars como chave
                if text_key in seen_texts:
                    continue
                
                seen_texts.add(text_key)
                content_parts.append(text)
            
            # Extrair apenas links importantes (não navegação)
            for link in soup.find_all('a', href=True):
                href = link.get('href', '')
                text = link.get_text(strip=True)
                
                # Ignorar links de navegação, âncoras e javascript
                if (not text or not href or len(text) < 5 or
                    href.startswith(('#', 'javascript:', 'mailto:')) or
                    any(nav_word in text.lower() for nav_word in 
                        ['menu', 'home', 'página', 'próximo', 'anterior', 'next', 'prev', 'voltar', 'back'])):
                    continue
                
                content_parts.append(f"{text} -> {href}")
            
            # Juntar e normalizar
            combined = '\n'.join(content_parts)
            return self.content_normalizer.normalize(combined)
        
        except Exception as e:
            logging.error(f"Error in standard content extraction: {e}")
            return self._extract_content_regex(html)
    
    def _extract_content_regex(self, html: str) -> str:
        """Extração de conteúdo usando regex (fallback)"""
        # Remover scripts e styles
        html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
        html = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL | re.IGNORECASE)
        
        # Extrair texto entre tags
        text_content = re.sub(r'<[^>]+>', ' ', html)
        
        # Limpar e normalizar
        return self.content_normalizer.normalize(text_content)
    
    def _extract_linhas_info(self, html: str) -> str:
        """Extração específica para sites de transporte"""
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
    
    def _extract_gallery_content(self, html: str) -> str:
        """Extração específica para galerias"""
        if not BS4_AVAILABLE:
            return self._extract_content_regex(html)
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            gallery_info = []
            
            # Títulos de galeria
            title_selectors = [
                'h1', 'h2', 'h3', '.portfolio-title', '.gallery-title',
                '.album-title', '.work-title', 'figcaption h3'
            ]
            
            seen_titles = set()
            for selector in title_selectors:
                for element in soup.select(selector):
                    text = element.get_text(strip=True)
                    if (text and 5 < len(text) < 100 and 
                        text not in seen_titles):
                        seen_titles.add(text)
                        gallery_info.append(f"Título: {text}")
            
            # Contagem de imagens
            images = soup.find_all('img')
            real_images = [img for img in images 
                          if not img.get('src', '').startswith('data:image/svg')]
            gallery_info.append(f"Total de imagens: {len(real_images)}")
            
            return self.content_normalizer.normalize('\n'.join(gallery_info))
        
        except Exception as e:
            logging.error(f"Error extracting gallery content: {e}")
            return ""
    
    def calculate_content_hash(self, content: str) -> str:
        """Calcula hash do conteúdo"""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()
    
    def detect_change(self, url: str, new_content: str) -> Optional[ChangeDetection]:
        """Detecta mudanças com validação adicional para evitar falsos positivos"""
        if not new_content or len(new_content) < self.config['MIN_CONTENT_LENGTH']:
            logging.warning(f"?? Content too short for {url}: {len(new_content)} chars")
            return None
        
        new_hash = self.calculate_content_hash(new_content)
        old_hash = self.last_hashes.get(url, "")
        old_content = self.last_contents.get(url, "")

        self.last_contents[url] = new_content
        self._content_updated = True
        logging.debug(f"Updated content for {url}: {len(new_content)} chars")
        
        # Primeira verificação - apenas armazenar
        if not old_hash:
            self.last_hashes[url] = new_hash
            self._content_updated = True
            
            # DEBUG CRÍTICO
            logging.info(f"? First check for {url}, storing initial hash")
            logging.info(f"   Content stored: {len(new_content)} chars")
            logging.info(f"   Content preview: {new_content[:100]}...")
            logging.info(f"   Total in memory now: {len(self.last_contents)} contents")
            logging.info(f"   Dict keys: {list(self.last_contents.keys())}")
            return None
                
        # Se hash é idêntico, sem mudança
        if new_hash == old_hash:
            logging.debug(f"? No hash change for {url}")
            return None
        
        # Hash diferente - verificar se mudança é significativa
        logging.info(f"?? Hash changed for {url}, validating significance...")
        
        # Validação 1: Verificar similaridade de conteúdo
        similarity = self._calculate_similarity(old_content, new_content)
        logging.info(f"   ?? Similarity: {similarity:.2%}")
        
        # Se similaridade é muito alta, provavelmente é falso positivo
        similarity_threshold = self.config.get('MIN_SIMILARITY_THRESHOLD', 0.95)
        if similarity > similarity_threshold:
            logging.info(f"   ? Content too similar ({similarity:.2%} > {similarity_threshold:.2%}), ignoring change")
            self.stats['false_positives_avoided'] += 1
            # Atualizar hash mas não notificar
            self.last_hashes[url] = new_hash
            self._content_updated = True
            return None
        
        # Validação 2: Verificar se conteúdo novo é válido
        if len(new_content) < len(old_content) * 0.3:
            logging.warning(f"   ? New content is too short (possible error), ignoring")
            return None
        
        # Validação 3: Verificar diferença absoluta de tamanho
        size_diff = abs(len(new_content) - len(old_content))
        size_ratio = size_diff / len(old_content) if old_content else 1
        
        logging.info(f"   ?? Size change: {size_diff} chars ({size_ratio:.2%})")
        
        # Se mudança é menor que threshold do tamanho, pode ser ruído
        size_threshold = self.config.get('MIN_SIZE_CHANGE_RATIO', 0.02)
        if size_ratio < size_threshold and similarity > 0.90:
            logging.info(f"   ? Change too small ({size_ratio:.2%} < {size_threshold:.2%}), ignoring")
            self.stats['false_positives_avoided'] += 1
            self.last_hashes[url] = new_hash
            self._content_updated = True
            return None
        
        # Mudança é significativa - gerar notificação
        logging.info(f"   ? Significant change confirmed!")
        
        diff_content = self._generate_diff(old_content, new_content)
        
        # Atualizar dados
        self.last_hashes[url] = new_hash
        self._content_updated = True
        
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
        """Calcula similaridade entre dois textos"""
        if not text1 or not text2:
            return 0.0
        
        try:
            # Usar SequenceMatcher para calcular similaridade
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
                        diff_lines.append(f"? {line}")
                elif tag == 'insert':
                    for line in new_lines[j1:j2]:
                        diff_lines.append(f"? {line}")
                elif tag == 'replace':
                    for line in old_lines[i1:i2]:
                        diff_lines.append(f"? {line}")
                    for line in new_lines[j1:j2]:
                        diff_lines.append(f"? {line}")
            
            return '\n'.join(diff_lines[:100])
        
        except Exception as e:
            logging.error(f"Error generating diff: {e}")
            return "Erro ao gerar comparação de mudanças"
    
    def monitor_sites(self):
        """Executa monitoramento de todos os sites"""
        logging.info("?? Starting website monitoring (anti false positives)...")
        logging.info(f"?? Monitoring {len(self.config['URLS'])} sites")
        logging.info(f"??  Similarity threshold: {self.config.get('MIN_SIMILARITY_THRESHOLD', 0.95):.2%}")
        logging.info(f"??  Size change threshold: {self.config.get('MIN_SIZE_CHANGE_RATIO', 0.02):.2%}")
        
        try:
            # Usar ThreadPoolExecutor para paralelização
            with ThreadPoolExecutor(max_workers=self.config['MAX_WORKERS']) as executor:
                # Submeter todas as tarefas
                future_to_url = {
                    executor.submit(self.monitor_single_site, url): url 
                    for url in self.config['URLS']
                }
                
                # Processar resultados conforme completam
                for future in as_completed(future_to_url):
                    if self._stop_event.is_set():
                        break
                    
                    url = future_to_url[future]
                    try:
                        result = future.result()
                        if result:
                            self.stats['changes_detected'] += 1
                            
                            # Enviar notificação
                            if self.email_notifier.send_notification(result):
                                self.stats['emails_sent'] += 1
                        
                        self.stats['sites_checked'] += 1
                    
                    except Exception as e:
                        logging.error(f"Error processing {url}: {e}")
                        self.stats['errors'] += 1
                    
                    # Rate limiting
                    time.sleep(self.config['RATE_LIMIT_DELAY'])
            
            # Salvar dados
            self._save_data()

            logging.info("="*60)
            logging.info("?? FINAL VERIFICATION BEFORE EXIT")
            logging.info(f"   Contents in memory: {len(self.last_contents)}")
            
            if self.content_file.exists():
                with open(self.content_file, 'r') as f:
                    final_check = json.load(f)
                    logging.info(f"   Contents in file: {len(final_check)}")
                    if len(final_check) != len(self.last_contents):
                        logging.error(f"   ? MISMATCH! Memory={len(self.last_contents)}, File={len(final_check)}")
            else:
                logging.error(f"   ? File {self.content_file} doesn't exist!")
            
            logging.info("="*60)
            
            # Log de estatísticas
            self._log_statistics()
        
        except KeyboardInterrupt:
            logging.info("?? Monitoring stopped by user")
        except Exception as e:
            logging.error(f"? Monitoring error: {e}")
            self.stats['errors'] += 1
    
    def monitor_single_site(self, url: str) -> Optional[ChangeDetection]:
        """Monitora um site específico"""
        logging.info(f"?? Checking {url}")
        
        try:
            # Obter conteúdo
            result = self.get_page_content(url)
            
            if not result.success:
                logging.warning(f"?? Failed to fetch {url}: {result.error}")
                return None
            
            # Extrair conteúdo relevante
            relevant_content = self.extract_relevant_content(url, result.content)
            
            if not relevant_content:
                logging.warning(f"?? No relevant content extracted from {url}")
                return None
            
            logging.debug(f"   ?? Extracted {len(relevant_content)} chars")
            
            # Detectar mudanças
            change = self.detect_change(url, relevant_content)
            
            if change:
                logging.info(f"?? Significant change detected in {url}")
                return change
            else:
                logging.info(f"? No significant changes in {url}")
                return None
        
        except Exception as e:
            logging.error(f"? Error monitoring {url}: {e}")
            return None
    
    def _save_data(self):
        """Salva dados de hash e conteúdo"""
        try:
            logging.info("="*60)
            logging.info("?? SAVING DATA - START")
            logging.info(f"   Hashes in memory: {len(self.last_hashes)}")
            logging.info(f"   Contents in memory: {len(self.last_contents)}")
            
            if self.last_contents:
                logging.info(f"   Sample URLs with content:")
                for i, url in enumerate(list(self.last_contents.keys())[:3]):
                    content_len = len(self.last_contents[url])
                    logging.info(f"      [{i+1}] {url}: {content_len} chars")
            else:
                logging.error("   ?? WARNING: last_contents is EMPTY!")
            
            # Salvar hashes
            logging.info(f"?? Saving hashes to {self.hash_file}...")
            self._save_json_file(self.hash_file, self.last_hashes)
            
            # Salvar contents
            logging.info(f"?? Saving contents to {self.content_file}...")
            self._save_json_file(self.content_file, self.last_contents)
            
            # Verificar após salvar
            logging.info("?? Verifying saved files...")
            
            if self.hash_file.exists():
                size = self.hash_file.stat().st_size
                logging.info(f"   ? {self.hash_file.name}: {size} bytes")
            else:
                logging.error(f"   ? {self.hash_file.name}: FILE NOT FOUND")
            
            if self.content_file.exists():
                size = self.content_file.stat().st_size
                logging.info(f"   ? {self.content_file.name}: {size} bytes")
                
                # Ler de volta
                with open(self.content_file, 'r') as f:
                    saved_data = json.load(f)
                    logging.info(f"   ?? Read back: {len(saved_data)} entries")
                    
                    if len(saved_data) == 0 and len(self.last_contents) > 0:
                        logging.error("   ? CRITICAL: File is empty but memory had data!")
                        logging.error(f"   Memory had: {list(self.last_contents.keys())[:3]}")
            else:
                logging.error(f"   ? {self.content_file.name}: FILE NOT FOUND")
            
            logging.info("?? SAVING DATA - END")
            logging.info("="*60)
        
        except Exception as e:
            logging.error(f"? Error in _save_data: {e}")
            import traceback
            logging.error(traceback.format_exc())
    
    def _log_statistics(self):
        """Log de estatísticas da execução"""
        duration = datetime.now(LOCAL_TZ) - self.stats['start_time']
        
        logging.info("")
        logging.info("=" * 60)
        logging.info("?? Monitoring Statistics:")
        logging.info(f"   ??  Duration: {duration}")
        logging.info(f"   ?? Sites checked: {self.stats['sites_checked']}")
        logging.info(f"   ?? Significant changes detected: {self.stats['changes_detected']}")
        logging.info(f"   ???  False positives avoided: {self.stats['false_positives_avoided']}")
        logging.info(f"   ?? Emails sent: {self.stats['emails_sent']}")
        logging.info(f"   ? Errors: {self.stats['errors']}")
        logging.info("=" * 60)


def main():
    """Função principal"""
    try:
        # Carregar configuração
        config = ConfigManager.load_config('config.json')
        
        # Limpar dados se solicitado
        if config.get('DELETE_HASH_ON_START', False):
            for file_path in [config['HASH_FILE'], config.get('CONTENT_FILE', '')]:
                if file_path and Path(file_path).exists():
                    Path(file_path).unlink()
                    logging.info(f"??? Deleted {file_path}")
        
        # Inicializar e executar monitor
        monitor = WebsiteMonitor(config)
        monitor.monitor_sites()
    
    except (FileNotFoundError, ValueError, KeyError, IOError) as e:
        logging.critical(f"? Configuration error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logging.info("?? Monitoring stopped by user")
    except Exception as e:
        logging.critical(f"? Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
