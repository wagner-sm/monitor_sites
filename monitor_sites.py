"""
Website Monitor - Versão Ultra Otimizada (Anti Falsos Positivos)
Monitor de mudanças em websites com detecção inteligente de mudanças reais
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
from typing import Dict, Optional, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from collections import Counter

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
    structural_change: bool = False
    semantic_change: bool = False


@dataclass
class ContentFingerprint:
    """Fingerprint estrutural do conteúdo para detecção mais precisa"""
    word_count: int
    unique_words: int
    sentence_count: int
    paragraph_count: int
    link_count: int
    heading_count: int
    structure_signature: str
    top_keywords: List[Tuple[str, int]]
    
    def similarity_to(self, other: 'ContentFingerprint') -> float:
        """Calcula similaridade estrutural com outro fingerprint"""
        if not other:
            return 0.0
        
        scores = []
        
        # Comparar contagens (peso maior para estrutura)
        for attr in ['word_count', 'sentence_count', 'paragraph_count', 'link_count', 'heading_count']:
            old_val = getattr(self, attr)
            new_val = getattr(other, attr)
            if old_val > 0:
                ratio = min(old_val, new_val) / max(old_val, new_val)
                scores.append(ratio)
        
        # Comparar assinatura estrutural
        if self.structure_signature and other.structure_signature:
            struct_sim = SequenceMatcher(None, self.structure_signature, other.structure_signature).ratio()
            scores.append(struct_sim * 1.5)  # Peso maior
        
        # Comparar keywords principais
        if self.top_keywords and other.top_keywords:
            old_words = set(word for word, _ in self.top_keywords[:20])
            new_words = set(word for word, _ in other.top_keywords[:20])
            if old_words and new_words:
                keyword_overlap = len(old_words & new_words) / len(old_words | new_words)
                scores.append(keyword_overlap * 1.2)  # Peso moderado
        
        return sum(scores) / len(scores) if scores else 0.0


class ConfigManager:
    """Gerenciador de configurações com validação"""
    
    REQUIRED_KEYS = ['URLS', 'EMAIL_RECIPIENTS', 'HASH_FILE']
    DEFAULT_CONFIG = {
        'MAX_WORKERS': 5,
        'MAX_RETRIES': 3,
        'REQUEST_TIMEOUT': 30,
        'MIN_CONTENT_LENGTH': 100,
        'MIN_SIMILARITY_THRESHOLD': 0.95,
        'MIN_STRUCTURAL_SIMILARITY': 0.90,
        'MIN_SIZE_CHANGE_RATIO': 0.03,
        'MIN_WORD_CHANGE_RATIO': 0.05,
        'REQUIRE_MULTIPLE_CHANGES': True,
        'MIN_CONSECUTIVE_CHANGES': 2,
        'DELETE_HASH_ON_START': False,
        'RATE_LIMIT_DELAY': 1.0,
        'USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'EMAIL_RATE_LIMIT': 10,
        'LOG_LEVEL': 'INFO',
        'NORMALIZE_CASE': True,
        'SORT_CONTENT_LINES': True,
        'USE_STRUCTURAL_ANALYSIS': True,
        'USE_SEMANTIC_ANALYSIS': True,
        'IGNORE_MINOR_WORD_CHANGES': True,
        'STABLE_CHECK_INTERVAL': 300,
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
        
        for key in cls.REQUIRED_KEYS:
            if key not in config:
                raise KeyError(f"Missing required config key: {key}")
        
        for key, default_value in cls.DEFAULT_CONFIG.items():
            config.setdefault(key, default_value)
        
        cls._validate_config(config)
        cls._resolve_paths(config)
        
        return config
    
    @classmethod
    def _validate_config(cls, config: Dict):
        """Valida configurações específicas"""
        if not isinstance(config['URLS'], list) or not config['URLS']:
            raise ValueError("URLS must be a non-empty list")
        
        if not isinstance(config['EMAIL_RECIPIENTS'], list) or not config['EMAIL_RECIPIENTS']:
            raise ValueError("EMAIL_RECIPIENTS must be a non-empty list")
        
        for url in config['URLS']:
            if not isinstance(url, str) or not url.startswith(('http://', 'https://')):
                raise ValueError(f"Invalid URL: {url}")
        
        if not 0 <= config.get('MIN_SIMILARITY_THRESHOLD', 0.95) <= 1:
            raise ValueError("MIN_SIMILARITY_THRESHOLD must be between 0 and 1")
        
        if not 0 <= config.get('MIN_SIZE_CHANGE_RATIO', 0.02) <= 1:
            raise ValueError("MIN_SIZE_CHANGE_RATIO must be between 0 and 1")
    
    @classmethod
    def _resolve_paths(cls, config: Dict):
        """Resolve caminhos relativos para absolutos"""
        base_dir = Path(__file__).parent.absolute()
        
        for key in ['HASH_FILE', 'CONTENT_FILE', 'LOG_FILE', 'FINGERPRINT_FILE', 'CHANGE_HISTORY_FILE']:
            if key in config and not Path(config[key]).is_absolute():
                config[key] = str(base_dir / config[key])


class ContentNormalizer:
    """Normalizador de conteúdo ultra-robusto"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.patterns = [
            # Timestamps e datas (expandido)
            (re.compile(r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}(?:\s+\d{1,2}:\d{2}(?::\d{2})?)?\b'), 'DATE'),
            (re.compile(r'\b\d{4}[/-]\d{1,2}[/-]\d{1,2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)?\b'), 'DATETIME'),
            (re.compile(r'\b\d{1,2}:\d{2}(?::\d{2})?(?:\s*[AP]M)?\b', re.I), 'TIME'),
            (re.compile(r'\b\d{10,13}\b'), 'TIMESTAMP'),
            
            # IDs e tokens
            (re.compile(r'\b[a-fA-F0-9]{16,}\b'), 'HEX_ID'),
            (re.compile(r'\b[A-Z0-9]{20,}\b'), 'TOKEN'),
            (re.compile(r'\b[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\b'), 'UUID'),
            
            # Parâmetros dinâmicos de URL
            (re.compile(r'[?&](_|t|v|ts|cache|rand|random|sid|session|sessionid|token|csrf|nonce|timestamp|version|rev|build|_t|_v|utm_[^&\s]*)=[^&\s]*', re.I), ''),
            
            # Versões
            (re.compile(r'\bv?\d+\.\d+\.\d+(?:\.\d+)?\b'), 'VERSION'),
            
            # Contadores e métricas
            (re.compile(r'\b\d+\s*(?:views?|visualizações|visualizacoes|acessos|clicks?|curtidas?|likes?|shares?|comentários?|comments?)\b', re.I), 'METRIC'),
            (re.compile(r'\b(?:views?|visualizações|acessos|clicks?):\s*\d+\b', re.I), 'METRIC'),
            
            # Números grandes (possivelmente contadores)
            (re.compile(r'\b\d{4,}\b'), 'NUMBER'),
            
            # Datas relativas
            (re.compile(r'\b(?:hoje|ontem|amanhã|yesterday|today|tomorrow|há|ago|\d+\s*(?:segundo|minuto|hora|dia|semana|mes|mês|ano|second|minute|hour|day|week|month|year)s?(?:\s+(?:atrás|ago))?)\b', re.I), 'RELATIVE_TIME'),
            
            # Scripts e styles
            (re.compile(r'<script[^>]*>.*?</script>', re.DOTALL | re.I), ''),
            (re.compile(r'<style[^>]*>.*?</style>', re.DOTALL | re.I), ''),
            (re.compile(r'<!--.*?-->', re.DOTALL), ''),
            
            # Atributos dinâmicos
            (re.compile(r'\s(?:data-id|data-key|data-index|data-timestamp|data-token|data-session|id|class)="[^"]*"', re.I), ''),
            
            # Tokens em texto
            (re.compile(r'(?:token|csrf|session)[_-]?\w*[=:]\w+', re.I), 'AUTH_TOKEN'),
            
            # Espaços
            (re.compile(r'\s+'), ' '),
            (re.compile(r'\n\s*\n+'), '\n'),
        ]
        
        # Stop words para análise semântica
        self.stop_words = {
            'o', 'a', 'os', 'as', 'de', 'da', 'do', 'das', 'dos', 'em', 'no', 'na', 'nos', 'nas',
            'por', 'para', 'com', 'sem', 'sob', 'sobre', 'um', 'uma', 'uns', 'umas',
            'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with',
            'is', 'are', 'was', 'were', 'be', 'been', 'being', 'have', 'has', 'had',
        }
        
        self._cache: Dict[str, str] = {}
        self._cache_max_size = 1000
    
    def normalize(self, text: str) -> str:
        """Normaliza texto de forma ultra-agressiva"""
        if not text:
            return ""
        
        text_hash = hashlib.md5(text.encode()).hexdigest()[:12]
        if text_hash in self._cache:
            return self._cache[text_hash]
        
        normalized = text
        for pattern, replacement in self.patterns:
            normalized = pattern.sub(replacement, normalized)
        
        normalized = normalized.strip()
        
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
        
        if self.config.get('SORT_CONTENT_LINES', True):
            lines.sort()
        
        result = '\n'.join(lines)
        
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
            r'^(menu|search|buscar|busca|login|entrar|sair|logout|home|início)$',
            r'^(DATE|TIME|DATETIME|TIMESTAMP|METRIC|VERSION|NUMBER|TOKEN)$',
        ]
        
        line_lower = line.lower()
        for pattern in noise_patterns:
            if re.match(pattern, line_lower, re.I):
                return True
        
        return False
    
    def extract_keywords(self, text: str, top_n: int = 50) -> List[Tuple[str, int]]:
        """Extrai palavras-chave mais relevantes do texto"""
        words = re.findall(r'\b\w{4,}\b', text.lower())
        
        # Filtrar stop words e tokens normalizados
        filtered_words = [
            w for w in words 
            if w not in self.stop_words 
            and not w.startswith(('date', 'time', 'metric', 'token', 'version'))
        ]
        
        word_freq = Counter(filtered_words)
        return word_freq.most_common(top_n)


class StructuralAnalyzer:
    """Analisa estrutura do conteúdo para detectar mudanças significativas"""
    
    def __init__(self, config: Dict):
        self.config = config
    
    def create_fingerprint(self, html: str, normalized_text: str) -> ContentFingerprint:
        """Cria fingerprint estrutural do conteúdo"""
        try:
            # Análise de texto normalizado
            lines = normalized_text.split('\n')
            words = re.findall(r'\b\w+\b', normalized_text.lower())
            sentences = re.split(r'[.!?]+', normalized_text)
            
            word_count = len(words)
            unique_words = len(set(words))
            sentence_count = len([s for s in sentences if len(s.strip()) > 10])
            paragraph_count = len([l for l in lines if len(l) > 50])
            
            # Análise estrutural HTML
            link_count = 0
            heading_count = 0
            structure_sig = []
            
            if BS4_AVAILABLE and html:
                try:
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # Contar elementos estruturais
                    link_count = len(soup.find_all('a', href=True))
                    heading_count = len(soup.find_all(['h1', 'h2', 'h3', 'h4']))
                    
                    # Criar assinatura estrutural (tipo e ordem dos elementos principais)
                    for elem in soup.find_all(['h1', 'h2', 'h3', 'article', 'section', 'div']):
                        if elem.name in ['h1', 'h2', 'h3']:
                            structure_sig.append(f'{elem.name}:{len(elem.get_text(strip=True))}')
                        elif elem.get('class'):
                            classes = ' '.join(elem.get('class', []))
                            if any(key in classes.lower() for key in ['content', 'article', 'post', 'main']):
                                structure_sig.append(f'{elem.name}:main')
                
                except Exception as e:
                    logging.debug(f"Error in structural HTML analysis: {e}")
            
            # Extrair keywords
            normalizer = ContentNormalizer(self.config)
            top_keywords = normalizer.extract_keywords(normalized_text)
            
            return ContentFingerprint(
                word_count=word_count,
                unique_words=unique_words,
                sentence_count=sentence_count,
                paragraph_count=paragraph_count,
                link_count=link_count,
                heading_count=heading_count,
                structure_signature='-'.join(structure_sig[:20]),
                top_keywords=top_keywords
            )
        
        except Exception as e:
            logging.error(f"Error creating fingerprint: {e}")
            return ContentFingerprint(0, 0, 0, 0, 0, 0, "", [])
    
    def is_structural_change(self, old_fp: ContentFingerprint, new_fp: ContentFingerprint) -> Tuple[bool, float]:
        """Verifica se houve mudança estrutural significativa"""
        if not old_fp or not new_fp:
            return False, 0.0
        
        similarity = old_fp.similarity_to(new_fp)
        threshold = self.config.get('MIN_STRUCTURAL_SIMILARITY', 0.90)
        
        is_significant = similarity < threshold
        
        logging.debug(f"Structural similarity: {similarity:.2%} (threshold: {threshold:.2%})")
        
        return is_significant, similarity


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
        if last_time and datetime.now() - last_time < self.min_email_interval:
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
                self.last_email_time[change.url] = datetime.now()
                logging.info(f"✅ Email sent for {change.url}")
            return success
        except Exception as e:
            logging.error(f"❌ Email error for {change.url}: {e}")
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
        
        msg = MIMEMultipart('alternative')
        msg['From'] = smtp_user
        msg['To'] = ", ".join(self.config["EMAIL_RECIPIENTS"])
        msg['Subject'] = f"🔔 Mudança Real Detectada: {change.url}"
        
        html_content = self._generate_html_content(change)
        msg.attach(MIMEText(html_content, 'html', 'utf-8'))
        
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
        
        display_diff = change.diff_content
        if len(display_diff) > 3000:
            display_diff = f"{display_diff[:3000]}...\n\n<i>(Conteúdo truncado)</i>"
        
        change_type = []
        if change.structural_change:
            change_type.append("Estrutural")
        if change.semantic_change:
            change_type.append("Semântica")
        change_type_str = " + ".join(change_type) if change_type else "Geral"
        
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
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; background: #28a745; color: white; font-size: 11px; font-weight: bold; }}
        </style>
        </head>
        <body>
        <div class="container">
        <div class="header">
        <h1>🔔 Mudança Real Detectada</h1>
        </div>
        
        <div class="content">
        <div class="info-card">
        <h3>📋 Informações da Detecção</h3>
        <p><strong>🌐 Site:</strong> <a href="{change.url}" class="url-link" target="_blank">{change.url}</a></p>
        <p><strong>📅 Data/Hora:</strong> {detected_at}</p>
        <p><strong>🏷️ Tipo de Mudança:</strong> <span class="badge">{change_type_str}</span></p>
        <p><strong>🔄 Hash Anterior:</strong> <code>{change.old_hash[:16]}...</code></p>
        <p><strong>🆕 Hash Atual:</strong> <code>{change.new_hash[:16]}...</code></p>
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
        <h3>🔍 Mudanças Detectadas</h3>
        <div class="diff-container">
        <div class="diff-content">{display_diff}</div>
        </div>
        </div>
        </div>
        
        <div class="footer">
        🤖 Website Monitor - Ultra Otimizado Anti Falsos Positivos<br>
        <small>Não responda este e-mail</small>
        </div>
        </div>
        </body>
        </html>
        """


class WebsiteMonitor:
    """Monitor de websites com detecção ultra-precisa"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.setup_logging()
        
        self.content_normalizer = ContentNormalizer(config)
        self.structural_analyzer = StructuralAnalyzer(config)
        self.email_notifier = EmailNotifier(config)
        
        self.hash_file = Path(config['HASH_FILE'])
        self.content_file = Path(config.get('CONTENT_FILE', 'last_contents.json'))
        self.fingerprint_file = Path(config.get('FINGERPRINT_FILE', 'fingerprints.json'))
        self.change_history_file = Path(config.get('CHANGE_HISTORY_FILE', 'change_history.json'))
        
        for file_path in [self.hash_file, self.content_file, self.fingerprint_file, self.change_history_file]:
            file_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.last_hashes = self._load_json_file(self.hash_file)
        self.last_contents = self._load_json_file(self.content_file)
        self.last_fingerprints = self._load_fingerprints()
        self.change_history = self._load_json_file(self.change_history_file)
        
        self._stop_event = threading.Event()
        self._setup_signal_handlers()
        
        self.session = self._create_session()
        
        self.stats = {
            'sites_checked': 0,
            'changes_detected': 0,
            'false_positives_avoided': 0,
            'consecutive_changes_required': 0,
            'emails_sent': 0,
            'errors': 0,
            'start_time': datetime.now()
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
        """Cria sessão HTTP configurada"""
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
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except IOError as e:
            logging.error(f"Error saving {file_path}: {e}")
    
    def _load_fingerprints(self) -> Dict:
        """Carrega fingerprints salvos"""
        if not self.fingerprint_file.exists():
            return {}
        
        try:
            with open(self.fingerprint_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            # Reconstruir objetos ContentFingerprint
            fingerprints = {}
            for url, fp_data in data.items():
                fingerprints[url] = ContentFingerprint(**fp_data)
            
            return fingerprints
        except Exception as e:
            logging.error(f"Error loading fingerprints: {e}")
            return {}
    
    def _save_fingerprints(self):
        """Salva fingerprints"""
        try:
            # Converter para dict serializável
            data = {}
            for url, fp in self.last_fingerprints.items():
                data[url] = {
                    'word_count': fp.word_count,
                    'unique_words': fp.unique_words,
                    'sentence_count': fp.sentence_count,
                    'paragraph_count': fp.paragraph_count,
                    'link_count': fp.link_count,
                    'heading_count': fp.heading_count,
                    'structure_signature': fp.structure_signature,
                    'top_keywords': fp.top_keywords
                }
            
            with open(self.fingerprint_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logging.error(f"Error saving fingerprints: {e}")
    
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
        """Extrai conteúdo relevante"""
        if not html_content:
            return ""
        
        try:
            if "cartaometrocard.com.br" in url:
                return self._extract_linhas_info(html_content)
            
            if any(domain in url for domain in self.config.get('SPECIAL_DOMAINS', [])):
                return self._extract_gallery_content(html_content)
            
            return self._extract_standard_content(html_content)
        
        except Exception as e:
            logging.error(f"Error extracting content from {url}: {e}")
            return ""
    
    def _extract_standard_content(self, html: str) -> str:
        """Extração padrão otimizada"""
        if not BS4_AVAILABLE:
            return self._extract_content_regex(html)
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Remover elementos irrelevantes
            for element in soup([
                'script', 'style', 'meta', 'link', 'iframe', 'noscript',
                'nav', 'footer', 'header', 'aside', 'svg', 'canvas',
                'ins', 'form', 'button'
            ]):
                element.decompose()
            
            # Remover elementos dinâmicos por classe/id
            dynamic_indicators = [
                'ad', 'advertisement', 'banner', 'tracking', 'analytics',
                'cookie', 'popup', 'modal', 'notification', 'toast',
                'counter', 'timer', 'clock', 'date', 'time',
                'social', 'share', 'comment', 'disqus', 'widget',
                'sidebar', 'related', 'recommended', 'trending'
            ]
            
            for element in soup.find_all(True):
                element_class = ' '.join(element.get('class') or []).lower()
                element_id = (element.get('id') or "").lower()
                
                if any(ind in element_class or ind in element_id for ind in dynamic_indicators):
                    element.decompose()
                    continue
                
                # Remover atributos dinâmicos
                for attr in ['data-id', 'data-key', 'data-index', 'data-timestamp', 
                            'data-token', 'id', 'class', 'style', 'onclick']:
                    if attr in element.attrs:
                        del element.attrs[attr]
            
            content_parts = []
            seen_texts = set()
            
            # Priorizar elementos semânticos
            for element in soup.find_all(['h1', 'h2', 'h3', 'h4', 'p', 'li', 'td', 'th', 'article', 'section']):
                text = element.get_text(strip=True)
                
                if not text or len(text) < 10:
                    continue
                
                if text.lower() in ['menu', 'search', 'buscar', 'entrar', 'login', 'cadastro', 
                                    'register', 'sign in', 'sign up', 'home', 'início']:
                    continue
                
                text_key = text[:100].lower()
                if text_key in seen_texts:
                    continue
                
                seen_texts.add(text_key)
                content_parts.append(text)
            
            # Links importantes
            for link in soup.find_all('a', href=True):
                href = link.get('href', '')
                text = link.get_text(strip=True)
                
                if (not text or not href or len(text) < 5 or
                    href.startswith(('#', 'javascript:', 'mailto:')) or
                    any(w in text.lower() for w in ['menu', 'home', 'próximo', 'anterior', 'next', 'prev'])):
                    continue
                
                content_parts.append(f"{text} -> {href}")
            
            combined = '\n'.join(content_parts)
            return self.content_normalizer.normalize(combined)
        
        except Exception as e:
            logging.error(f"Error in standard extraction: {e}")
            return self._extract_content_regex(html)
    
    def _extract_content_regex(self, html: str) -> str:
        """Extração via regex (fallback)"""
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
                    tipo = (cells[0].get_text(strip=True) or "N/A")
                    linha = (cells[1].get_text(strip=True) or "N/A")
                    
                    link_el = row.find('a')
                    href = (link_el.get('href') if link_el and link_el.get('href') else "")
                    
                    results.append(f"{tipo}-{linha}-{href}")
            
            return self.content_normalizer.normalize('\n'.join(results))
        
        except Exception as e:
            logging.error(f"Error extracting linhas: {e}")
            return ""
    
    def _extract_gallery_content(self, html: str) -> str:
        """Extração para galerias"""
        if not BS4_AVAILABLE:
            return self._extract_content_regex(html)
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            gallery_info = []
            
            title_selectors = [
                'h1', 'h2', 'h3', '.portfolio-title', '.gallery-title',
                '.album-title', '.work-title', 'figcaption h3'
            ]
            
            seen_titles = set()
            for selector in title_selectors:
                for element in soup.select(selector):
                    text = element.get_text(strip=True)
                    if text and 5 < len(text) < 100 and text not in seen_titles:
                        seen_titles.add(text)
                        gallery_info.append(f"Título: {text}")
            
            images = soup.find_all('img')
            real_images = [img for img in images if not img.get('src', '').startswith('data:image/svg')]
            gallery_info.append(f"Total de imagens: {len(real_images)}")
            
            return self.content_normalizer.normalize('\n'.join(gallery_info))
        
        except Exception as e:
            logging.error(f"Error extracting gallery: {e}")
            return ""
    
    def calculate_content_hash(self, content: str) -> str:
        """Calcula hash do conteúdo"""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()
    
    def detect_change(self, url: str, new_content: str, new_html: str = "") -> Optional[ChangeDetection]:
        """Detecta mudanças com validação multi-camada ULTRA PRECISA"""
        if not new_content or len(new_content) < self.config['MIN_CONTENT_LENGTH']:
            logging.warning(f"⚠️ Content too short for {url}: {len(new_content)} chars")
            return None
        
        new_hash = self.calculate_content_hash(new_content)
        old_hash = self.last_hashes.get(url, "")
        old_content = self.last_contents.get(url, "")
        
        # Primeira verificação
        if not old_hash:
            self.last_hashes[url] = new_hash
            self.last_contents[url] = new_content
            
            # Criar fingerprint inicial
            if self.config.get('USE_STRUCTURAL_ANALYSIS', True):
                fingerprint = self.structural_analyzer.create_fingerprint(new_html, new_content)
                self.last_fingerprints[url] = fingerprint
            
            logging.info(f"✓ First check for {url}, storing baseline")
            return None
        
        # Hash idêntico = sem mudança
        if new_hash == old_hash:
            logging.debug(f"✓ No hash change for {url}")
            return None
        
        logging.info(f"⚠️ Hash changed for {url}, validating with multi-layer analysis...")
        
        # === CAMADA 1: Análise de Similaridade de Texto ===
        text_similarity = self._calculate_similarity(old_content, new_content)
        logging.info(f"   📊 Text similarity: {text_similarity:.2%}")
        
        similarity_threshold = self.config.get('MIN_SIMILARITY_THRESHOLD', 0.95)
        if text_similarity > similarity_threshold:
            logging.info(f"   → Text too similar ({text_similarity:.2%} > {similarity_threshold:.2%})")
            self.stats['false_positives_avoided'] += 1
            self.last_hashes[url] = new_hash
            self.last_contents[url] = new_content
            return None
        
        # === CAMADA 2: Análise Estrutural ===
        structural_change = False
        structural_similarity = 1.0
        
        if self.config.get('USE_STRUCTURAL_ANALYSIS', True):
            new_fingerprint = self.structural_analyzer.create_fingerprint(new_html, new_content)
            old_fingerprint = self.last_fingerprints.get(url)
            
            if old_fingerprint:
                structural_change, structural_similarity = self.structural_analyzer.is_structural_change(
                    old_fingerprint, new_fingerprint
                )
                logging.info(f"   🏗️ Structural similarity: {structural_similarity:.2%}")
                
                # Se estrutura é muito similar, provável falso positivo
                if not structural_change and text_similarity > 0.85:
                    logging.info(f"   → Structure unchanged and text similar, ignoring")
                    self.stats['false_positives_avoided'] += 1
                    self.last_hashes[url] = new_hash
                    self.last_contents[url] = new_content
                    self.last_fingerprints[url] = new_fingerprint
                    return None
            
            self.last_fingerprints[url] = new_fingerprint
        
        # === CAMADA 3: Análise de Tamanho e Palavras ===
        old_words = set(re.findall(r'\b\w{4,}\b', old_content.lower()))
        new_words = set(re.findall(r'\b\w{4,}\b', new_content.lower()))
        
        word_overlap = len(old_words & new_words) / len(old_words | new_words) if old_words or new_words else 0
        logging.info(f"   📝 Word overlap: {word_overlap:.2%}")
        
        # Se palavras são muito similares mas texto "diferente", é ruído
        if word_overlap > 0.90 and not structural_change:
            logging.info(f"   → High word overlap without structural change, likely noise")
            self.stats['false_positives_avoided'] += 1
            self.last_hashes[url] = new_hash
            self.last_contents[url] = new_content
            return None
        
        # Análise de tamanho
        size_diff = abs(len(new_content) - len(old_content))
        size_ratio = size_diff / len(old_content) if old_content else 1
        logging.info(f"   📏 Size change: {size_diff} chars ({size_ratio:.2%})")
        
        size_threshold = self.config.get('MIN_SIZE_CHANGE_RATIO', 0.03)
        word_threshold = self.config.get('MIN_WORD_CHANGE_RATIO', 0.05)
        
        # Mudança de tamanho e palavras muito pequena
        if size_ratio < size_threshold and (1 - word_overlap) < word_threshold:
            logging.info(f"   → Changes too small (size: {size_ratio:.2%}, words: {1-word_overlap:.2%})")
            self.stats['false_positives_avoided'] += 1
            self.last_hashes[url] = new_hash
            self.last_contents[url] = new_content
            return None
        
        # === CAMADA 4: Validação de Conteúdo ===
        # Conteúdo novo muito menor = possível erro
        if len(new_content) < len(old_content) * 0.3:
            logging.warning(f"   → New content suspiciously short, ignoring")
            return None
        
        # === CAMADA 5: Histórico de Mudanças Consecutivas ===
        if self.config.get('REQUIRE_MULTIPLE_CHANGES', True):
            min_consecutive = self.config.get('MIN_CONSECUTIVE_CHANGES', 2)
            
            if url not in self.change_history:
                self.change_history[url] = []
            
            # Adicionar mudança ao histórico
            self.change_history[url].append({
                'timestamp': datetime.now().isoformat(),
                'hash': new_hash,
                'similarity': text_similarity,
                'size_ratio': size_ratio
            })
            
            # Manter apenas últimas 10 mudanças
            self.change_history[url] = self.change_history[url][-10:]
            
            # Verificar se temos mudanças consecutivas suficientes
            recent_changes = [
                c for c in self.change_history[url]
                if datetime.fromisoformat(c['timestamp']) > datetime.now() - timedelta(seconds=self.config.get('STABLE_CHECK_INTERVAL', 300))
            ]
            
            if len(recent_changes) < min_consecutive:
                logging.info(f"   → Only {len(recent_changes)}/{min_consecutive} consecutive changes, waiting for confirmation")
                self.stats['consecutive_changes_required'] += 1
                self.last_hashes[url] = new_hash
                self.last_contents[url] = new_content
                return None
        
        # === MUDANÇA CONFIRMADA COMO REAL ===
        logging.info(f"   ✅ REAL CHANGE CONFIRMED after multi-layer validation!")
        
        diff_content = self._generate_diff(old_content, new_content)
        
        # Determinar tipo de mudança
        semantic_change = word_overlap < 0.80
        
        self.last_hashes[url] = new_hash
        self.last_contents[url] = new_content
        
        return ChangeDetection(
            url=url,
            old_hash=old_hash,
            new_hash=new_hash,
            change_ratio=1.0 - text_similarity,
            is_significant=True,
            diff_content=diff_content,
            timestamp=datetime.now(),
            structural_change=structural_change,
            semantic_change=semantic_change
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
    
    def _generate_diff(self, old_content: str, new_content: str, max_lines: int = 50) -> str:
        """Gera diff detalhado"""
        try:
            old_lines = old_content.split('\n')[:max_lines]
            new_lines = new_content.split('\n')[:max_lines]
            
            diff_lines = []
            matcher = SequenceMatcher(None, old_lines, new_lines)
            
            for tag, i1, i2, j1, j2 in matcher.get_opcodes():
                if tag == 'delete':
                    for line in old_lines[i1:i2]:
                        if line.strip():
                            diff_lines.append(f"❌ {line}")
                elif tag == 'insert':
                    for line in new_lines[j1:j2]:
                        if line.strip():
                            diff_lines.append(f"✅ {line}")
                elif tag == 'replace':
                    for line in old_lines[i1:i2]:
                        if line.strip():
                            diff_lines.append(f"❌ {line}")
                    for line in new_lines[j1:j2]:
                        if line.strip():
                            diff_lines.append(f"✅ {line}")
            
            return '\n'.join(diff_lines[:100])
        
        except Exception as e:
            logging.error(f"Error generating diff: {e}")
            return "Erro ao gerar diff"
    
    def monitor_sites(self):
        """Executa monitoramento"""
        logging.info("🚀 Starting ULTRA-PRECISE website monitoring...")
        logging.info(f"📊 Monitoring {len(self.config['URLS'])} sites")
        logging.info(f"⚙️ Text similarity threshold: {self.config.get('MIN_SIMILARITY_THRESHOLD', 0.95):.2%}")
        logging.info(f"⚙️ Structural similarity threshold: {self.config.get('MIN_STRUCTURAL_SIMILARITY', 0.90):.2%}")
        logging.info(f"⚙️ Size change threshold: {self.config.get('MIN_SIZE_CHANGE_RATIO', 0.03):.2%}")
        logging.info(f"⚙️ Require consecutive changes: {self.config.get('REQUIRE_MULTIPLE_CHANGES', True)}")
        
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
            logging.info("ℹ️ Monitoring stopped by user")
        except Exception as e:
            logging.error(f"❌ Monitoring error: {e}")
            self.stats['errors'] += 1
    
    def monitor_single_site(self, url: str) -> Optional[ChangeDetection]:
        """Monitora um site"""
        logging.info(f"🔍 Checking {url}")
        
        try:
            result = self.get_page_content(url)
            
            if not result.success:
                logging.warning(f"⚠️ Failed to fetch {url}: {result.error}")
                return None
            
            relevant_content = self.extract_relevant_content(url, result.content)
            
            if not relevant_content:
                logging.warning(f"⚠️ No relevant content from {url}")
                return None
            
            logging.debug(f"   📄 Extracted {len(relevant_content)} chars")
            
            change = self.detect_change(url, relevant_content, result.content)
            
            if change:
                logging.info(f"🔥 REAL CHANGE detected in {url}")
                return change
            else:
                logging.info(f"✅ No significant changes in {url}")
                return None
        
        except Exception as e:
            logging.error(f"❌ Error monitoring {url}: {e}")
            return None
    
    def _save_data(self):
        """Salva todos os dados"""
        try:
            self._save_json_file(self.hash_file, self.last_hashes)
            self._save_json_file(self.content_file, self.last_contents)
            self._save_json_file(self.change_history_file, self.change_history)
            self._save_fingerprints()
            logging.info("💾 Data saved successfully")
        except Exception as e:
            logging.error(f"❌ Error saving data: {e}")
    
    def _log_statistics(self):
        """Log de estatísticas"""
        duration = datetime.now() - self.stats['start_time']
        
        logging.info("")
        logging.info("=" * 70)
        logging.info("📈 Monitoring Statistics (Ultra-Precise Mode):")
        logging.info(f"   ⏱️  Duration: {duration}")
        logging.info(f"   🌐 Sites checked: {self.stats['sites_checked']}")
        logging.info(f"   🔥 REAL changes detected: {self.stats['changes_detected']}")
        logging.info(f"   🛡️  False positives avoided: {self.stats['false_positives_avoided']}")
        logging.info(f"   ⏳ Awaiting consecutive confirmation: {self.stats['consecutive_changes_required']}")
        logging.info(f"   📧 Emails sent: {self.stats['emails_sent']}")
        logging.info(f"   ❌ Errors: {self.stats['errors']}")
        
        if self.stats['changes_detected'] + self.stats['false_positives_avoided'] > 0:
            precision = self.stats['changes_detected'] / (self.stats['changes_detected'] + self.stats['false_positives_avoided'])
            logging.info(f"   🎯 Precision rate: {precision:.1%}")
        
        logging.info("=" * 70)


def main():
    """Função principal"""
    try:
        config = ConfigManager.load_config('config.json')
        
        if config.get('DELETE_HASH_ON_START', False):
            for key in ['HASH_FILE', 'CONTENT_FILE', 'FINGERPRINT_FILE', 'CHANGE_HISTORY_FILE']:
                file_path = config.get(key)
                if file_path and Path(file_path).exists():
                    Path(file_path).unlink()
                    logging.info(f"🗑️ Deleted {file_path}")
        
        monitor = WebsiteMonitor(config)
        monitor.monitor_sites()
    
    except (FileNotFoundError, ValueError, KeyError, IOError) as e:
        logging.critical(f"❌ Configuration error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logging.info("ℹ️ Monitoring stopped by user")
    except Exception as e:
        logging.critical(f"❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
