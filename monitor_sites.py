"""
Website Monitor - Versão Simplificada
Focado em cartaometrocard.com.br e SPECIAL_DOMAINS
"""

import os
import sys
import json
import logging
import hashlib
import re
import signal
import time
from datetime import datetime, timedelta
from typing import Dict, Optional
from pathlib import Path
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from zoneinfo import ZoneInfo

LOCAL_TZ = ZoneInfo("America/Sao_Paulo")

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    logging.error("Biblioteca 'requests' não disponível")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    logging.warning("BeautifulSoup não disponível")


class ConfigManager:
    """Gerenciador de configurações"""
    
    @classmethod
    def load_config(cls, path: str) -> Dict:
        """Carrega configuração"""
        config_path = Path(path)
        
        if not config_path.exists():
            raise FileNotFoundError(f"Arquivo de config não encontrado: {config_path}")
        
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        # Validações básicas
        if not config.get('URLS'):
            raise ValueError("URLS não pode estar vazio")
        if not config.get('EMAIL_RECIPIENTS'):
            raise ValueError("EMAIL_RECIPIENTS não pode estar vazio")
        
        # Valores padrão
        config.setdefault('HASH_FILE', 'last_hashes.json')
        config.setdefault('CONTENT_FILE', 'last_contents.json')
        config.setdefault('REQUEST_TIMEOUT', 30)
        config.setdefault('MIN_CONTENT_LENGTH', 100)
        config.setdefault('MIN_SIMILARITY_THRESHOLD', 0.95)
        config.setdefault('SPECIAL_DOMAINS', [])
        config.setdefault('LOG_LEVEL', 'INFO')
        
        return config


class ContentNormalizer:
    """Normalizador de conteúdo"""
    
    def __init__(self):
        # Padrões para remover conteúdo dinâmico
        self.patterns = [
            (re.compile(r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}(?:\s+\d{1,2}:\d{2}(?::\d{2})?)?\b'), ''),
            (re.compile(r'\b\d{10,13}\b'), ''),
            (re.compile(r'\b[a-fA-F0-9]{16,}\b'), ''),
            (re.compile(r'[?&](_|t|v|ts|cache|rand|session|token|csrf)=[^&\s]*', re.I), ''),
            (re.compile(r'\s+'), ' '),
        ]
    
    def normalize(self, text: str) -> str:
        """Normaliza texto removendo elementos dinâmicos"""
        if not text:
            return ""
        
        normalized = text
        for pattern, replacement in self.patterns:
            normalized = pattern.sub(replacement, normalized)
        
        # Filtrar linhas válidas
        lines = []
        for line in normalized.split('\n'):
            line = line.strip()
            if len(line) > 5:
                lines.append(line.lower())
        
        lines.sort()
        return '\n'.join(lines)


class EmailNotifier:
    """Sistema de notificação por email"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.last_email_time = {}
        self.min_email_interval = timedelta(minutes=5)
    
    def send_notification(self, url: str, old_hash: str, new_hash: str, diff: str) -> bool:
        """Envia notificação de mudança"""
        # Rate limiting
        last_time = self.last_email_time.get(url)
        if last_time and datetime.now(LOCAL_TZ) - last_time < self.min_email_interval:
            logging.info(f"Email em cooldown para {url}")
            return False
        
        smtp_user = os.getenv('GMAIL_USER', self.config.get('GMAIL_USER'))
        smtp_password = os.getenv('GMAIL_APP_PASSWORD', self.config.get('GMAIL_APP_PASSWORD'))
        
        if not smtp_user or not smtp_password:
            logging.error("Credenciais Gmail não fornecidas")
            return False
        
        try:
            msg = MIMEMultipart('alternative')
            msg['From'] = smtp_user
            msg['To'] = ", ".join(self.config["EMAIL_RECIPIENTS"])
            msg['Subject'] = f"🔔 Mudança Detectada: {url}"
            
            html = self._create_email_html(url, old_hash, new_hash, diff)
            msg.attach(MIMEText(html, 'html', 'utf-8'))
            
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login(smtp_user, smtp_password)
                server.sendmail(smtp_user, self.config["EMAIL_RECIPIENTS"], msg.as_string())
            
            self.last_email_time[url] = datetime.now(LOCAL_TZ)
            logging.info(f"✅ Email enviado para {url}")
            return True
        
        except Exception as e:
            logging.error(f"❌ Erro ao enviar email: {e}")
            return False
    
    def _create_email_html(self, url: str, old_hash: str, new_hash: str, diff: str) -> str:
        """Cria HTML do email"""
        timestamp = datetime.now(LOCAL_TZ).strftime('%d/%m/%Y %H:%M:%S')
        
        if len(diff) > 3000:
            diff = f"{diff[:3000]}...\n\n<i>(Conteúdo truncado)</i>"
        
        return f"""
        <html>
        <head>
        <meta charset="UTF-8">
        <style>
        body {{ font-family: Arial, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }}
        .container {{ max-width: 800px; margin: 0 auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 25px; text-align: center; }}
        .content {{ padding: 25px; }}
        .info {{ background: #f8f9fa; border-left: 4px solid #007bff; padding: 20px; margin: 15px 0; border-radius: 8px; }}
        .diff {{ background: #f1f3f4; border-radius: 8px; padding: 20px; margin: 20px 0; font-family: monospace; white-space: pre-wrap; font-size: 13px; }}
        .footer {{ background: #6c757d; color: white; padding: 15px; text-align: center; }}
        </style>
        </head>
        <body>
        <div class="container">
        <div class="header">
        <h1>🔔 Mudança Detectada</h1>
        </div>
        
        <div class="content">
        <div class="info">
        <p><strong>🌐 Site:</strong> <a href="{url}" target="_blank">{url}</a></p>
        <p><strong>⏰ Data/Hora:</strong> {timestamp}</p>
        <p><strong>🔑 Hash Anterior:</strong> {old_hash[:16]}...</p>
        <p><strong>🆕 Hash Atual:</strong> {new_hash[:16]}...</p>
        </div>
        
        <div class="info">
        <h3>📝 Diferenças</h3>
        <div class="diff">{diff}</div>
        </div>
        </div>
        
        <div class="footer">
        Website Monitor - Versão Simplificada
        </div>
        </div>
        </body>
        </html>
        """


class WebsiteMonitor:
    """Monitor de websites"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.setup_logging()
        
        self.normalizer = ContentNormalizer()
        self.notifier = EmailNotifier(config)
        
        self.hash_file = Path(config['HASH_FILE'])
        self.content_file = Path(config['CONTENT_FILE'])
        
        self.last_hashes = self._load_json(self.hash_file)
        self.last_contents = self._load_json(self.content_file)
        
        self.session = self._create_session()
        
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def setup_logging(self):
        """Configura logging"""
        log_level = getattr(logging, self.config.get('LOG_LEVEL', 'INFO'))
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    def _signal_handler(self, signum, frame):
        """Handler para sinais do sistema"""
        logging.info(f"Recebido sinal {signum}, encerrando...")
        self._save_data()
        sys.exit(0)
    
    def _create_session(self) -> requests.Session:
        """Cria sessão HTTP"""
        session = requests.Session()
        
        retry = Retry(total=3, backoff_factor=2, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        return session
    
    def _load_json(self, file_path: Path) -> Dict:
        """Carrega arquivo JSON"""
        if not file_path.exists():
            return {}
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {}
    
    def _save_json(self, file_path: Path, data: Dict):
        """Salva arquivo JSON"""
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def _save_data(self):
        """Salva dados"""
        logging.info("💾 Salvando dados...")
        self._save_json(self.hash_file, self.last_hashes)
        self._save_json(self.content_file, self.last_contents)
        logging.info("✅ Dados salvos")
    
    def get_page_content(self, url: str) -> Optional[str]:
        """Obtém conteúdo da página"""
        try:
            response = self.session.get(url, timeout=self.config['REQUEST_TIMEOUT'])
            response.raise_for_status()
            return response.text
        except Exception as e:
            logging.error(f"Erro ao buscar {url}: {e}")
            return None
    
    def extract_content(self, url: str, html: str) -> str:
        """Extrai conteúdo relevante"""
        if not html:
            return ""
        
        # Cartão Metrocard
        if "cartaometrocard.com.br" in url:
            return self._extract_metrocard(html)
        
        # SPECIAL_DOMAINS (galerias)
        if any(domain in url for domain in self.config.get('SPECIAL_DOMAINS', [])):
            return self._extract_gallery(html)
        
        return ""
    
    def _extract_metrocard(self, html: str) -> str:
        """Extrai informações do cartão metrocard"""
        if not BS4_AVAILABLE:
            return ""
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            rows = soup.select('table tbody tr, table tr')[:15]
            
            results = []
            for row in rows:
                cells = row.find_all(['td', 'th'])
                if len(cells) >= 2:
                    tipo = cells[0].get_text(strip=True) or "N/A"
                    linha = cells[1].get_text(strip=True) or "N/A"
                    
                    link = row.find('a')
                    href = link.get('href', '') if link else ""
                    
                    results.append(f"{tipo}-{linha}-{href}")
            
            return self.normalizer.normalize('\n'.join(results))
        
        except Exception as e:
            logging.error(f"Erro ao extrair metrocard: {e}")
            return ""
    
    def _extract_gallery(self, html: str) -> str:
        """Extrai informações de galeria"""
        if not BS4_AVAILABLE:
            return ""
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            info = []
            
            # Títulos
            for element in soup.select('h1, h2, h3, .gallery-title, .portfolio-title'):
                text = element.get_text(strip=True)
                if 5 < len(text) < 100:
                    info.append(f"Título: {text}")
            
            # Imagens
            images = [img for img in soup.find_all('img') 
                     if not img.get('src', '').startswith('data:image/svg')]
            info.append(f"Total de imagens: {len(images)}")
            
            return self.normalizer.normalize('\n'.join(info))
        
        except Exception as e:
            logging.error(f"Erro ao extrair galeria: {e}")
            return ""
    
    def monitor_site(self, url: str):
        """Monitora um site específico"""
        logging.info(f"🔍 Verificando {url}")
        
        # Buscar conteúdo
        html = self.get_page_content(url)
        if not html:
            return
        
        # Extrair conteúdo relevante
        content = self.extract_content(url, html)
        if not content or len(content) < self.config['MIN_CONTENT_LENGTH']:
            logging.warning(f"⚠️ Conteúdo insuficiente para {url}")
            return
        
        # Calcular hash
        new_hash = hashlib.sha256(content.encode()).hexdigest()
        old_hash = self.last_hashes.get(url, "")
        
        # Armazenar conteúdo
        self.last_contents[url] = content
        
        # Primeira verificação
        if not old_hash:
            self.last_hashes[url] = new_hash
            logging.info(f"📝 Primeira verificação de {url}")
            return
        
        # Sem mudança
        if new_hash == old_hash:
            logging.info(f"✓ Sem mudanças em {url}")
            return
        
        # Validar mudança significativa
        old_content = self.last_contents.get(url, "")
        if old_content:
            from difflib import SequenceMatcher
            similarity = SequenceMatcher(None, old_content, content).ratio()
            
            if similarity > self.config['MIN_SIMILARITY_THRESHOLD']:
                logging.info(f"⚠️ Mudança não significativa ({similarity:.2%})")
                self.last_hashes[url] = new_hash
                return
        
        # Mudança detectada
        logging.info(f"🔔 Mudança significativa em {url}")
        
        # Gerar diff
        diff = self._generate_diff(old_content, content)
        
        # Atualizar hash
        self.last_hashes[url] = new_hash
        
        # Enviar notificação
        self.notifier.send_notification(url, old_hash, new_hash, diff)
    
    def _generate_diff(self, old: str, new: str) -> str:
        """Gera diff entre conteúdos"""
        from difflib import SequenceMatcher
        
        old_lines = old.split('\n')[:30]
        new_lines = new.split('\n')[:30]
        
        diff = []
        matcher = SequenceMatcher(None, old_lines, new_lines)
        
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == 'delete':
                for line in old_lines[i1:i2]:
                    diff.append(f"- {line}")
            elif tag == 'insert':
                for line in new_lines[j1:j2]:
                    diff.append(f"+ {line}")
            elif tag == 'replace':
                for line in old_lines[i1:i2]:
                    diff.append(f"- {line}")
                for line in new_lines[j1:j2]:
                    diff.append(f"+ {line}")
        
        return '\n'.join(diff[:100])
    
    def run(self):
        """Executa monitoramento"""
        logging.info("🚀 Iniciando monitoramento...")
        
        try:
            for url in self.config['URLS']:
                self.monitor_site(url)
                time.sleep(1)  # Rate limiting
            
            self._save_data()
            logging.info("✅ Monitoramento concluído")
        
        except KeyboardInterrupt:
            logging.info("⏹️ Interrompido pelo usuário")
            self._save_data()
        except Exception as e:
            logging.error(f"❌ Erro: {e}")
            self._save_data()


def main():
    """Função principal"""
    try:
        config = ConfigManager.load_config('config.json')
        monitor = WebsiteMonitor(config)
        monitor.run()
    except Exception as e:
        logging.critical(f"❌ Erro crítico: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
