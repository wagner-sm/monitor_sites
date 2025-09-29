import hashlib
import logging
import re
import difflib
import json
from datetime import datetime
from typing import Optional, Dict, Any
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


class ConfigManager:
    DEFAULT_CONFIG = {
        "URLS": [],
        "EMAIL_RECIPIENTS": [],
        "EMAIL_SENDER": "monitor@example.com",
        "SMTP_SERVER": "localhost",
        "SMTP_PORT": 25,
        "SMTP_USERNAME": None,
        "SMTP_PASSWORD": None,
        "HASH_FILE": "data/hashes.json",
        "CONTENT_FILE": "data/contents.json",
        "LOG_FILE": "monitor.log",
        "MAX_WORKERS": 2,
        "REQUEST_TIMEOUT": 30,
        "MIN_CONTENT_LENGTH": 50,
        "NOTIFICATION_RATE_LIMIT_MINUTES": 60,
        "DIFF_CONTEXT_LINES": 5,
        "SIMILARITY_THRESHOLD": 0.98,
        "MIN_LINES_CHANGED": 2,
        "SITE_SELECTORS": {}
    }

    def __init__(self, config_file: str = "config.json"):
        self.config_file = config_file
        self.config = self.load_config()
        self.setup_logging()

    def load_config(self) -> Dict[str, Any]:
        try:
            with open(self.config_file, "r", encoding="utf-8") as f:
                user_config = json.load(f)
        except FileNotFoundError:
            user_config = {}

        # Merge default + user config
        cfg = {**self.DEFAULT_CONFIG, **user_config}

        # Override with GitHub Actions secrets (se existirem)
        gmail_user = os.getenv("GMAIL_USER")
        gmail_pass = os.getenv("GMAIL_APP_PASSWORD")
        if gmail_user and gmail_pass:
            cfg.update({
                "EMAIL_SENDER": gmail_user,
                "SMTP_SERVER": "smtp.gmail.com",
                "SMTP_PORT": 587,
                "SMTP_USERNAME": gmail_user,
                "SMTP_PASSWORD": gmail_pass,
            })

        return cfg

    def setup_logging(self):
        logging.basicConfig(
            filename=self.config.get("LOG_FILE"),
            level=getattr(logging, self.config.get("LOG_LEVEL", "INFO").upper()),
            format="%(asctime)s - %(levelname)s - %(message)s"
        )


class ContentNormalizer:
    def __init__(self):
        self.patterns = [
            (re.compile(r'<!--.*?-->', re.DOTALL | re.IGNORECASE), ''),
            (re.compile(r'(Última|Atualizad[oa])\s+(em|:)\s*[\w\d\:\/\.\-\,\s]+', re.IGNORECASE), ''),
            (re.compile(r'\b[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}\b'), ''),
            (re.compile(r'\b\d{10,13}\b'), ''),
            (re.compile(r'\bdata-[a-z0-9_\-]+="[^"]*"', re.IGNORECASE), ''),
            (re.compile(r"\bdata-[a-z0-9_\-]+='[^']*'", re.IGNORECASE), ''),
            (re.compile(r'(\.js|\.css|\.png|\.jpg|\.jpeg|\.svg|\.pdf)(\?[^"\s>]*)'), r'\1'),
            (re.compile(r'\s+'), ' ')
        ]

    def normalize(self, text: str) -> str:
        if not text:
            return ""
        normalized = text
        for pattern, replacement in self.patterns:
            normalized = pattern.sub(replacement, normalized)
        return normalized.strip()


class ChangeDetection:
    def __init__(self, url: str, old_hash: str, new_hash: str, change_ratio: float,
                 diff_content: str, timestamp: datetime):
        self.url = url
        self.old_hash = old_hash
        self.new_hash = new_hash
        self.change_ratio = change_ratio
        self.diff_content = diff_content
        self.timestamp = timestamp


class ContentChangeDetector:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.content_normalizer = ContentNormalizer()
        self.last_hashes = self._load_json(config["HASH_FILE"])
        self.last_contents = self._load_json(config["CONTENT_FILE"])

    def _load_json(self, path: str) -> Dict[str, str]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def save_state(self):
        os.makedirs(os.path.dirname(self.config["HASH_FILE"]), exist_ok=True)
        with open(self.config["HASH_FILE"], "w", encoding="utf-8") as f:
            json.dump(self.last_hashes, f, ensure_ascii=False, indent=2)
        with open(self.config["CONTENT_FILE"], "w", encoding="utf-8") as f:
            json.dump(self.last_contents, f, ensure_ascii=False, indent=2)

    def calculate_content_hash(self, content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def detect_change(self, url: str, new_content: str) -> Optional[ChangeDetection]:
        if not new_content or len(new_content) < self.config["MIN_CONTENT_LENGTH"]:
            return None

        new_hash = self.calculate_content_hash(new_content)
        old_hash = self.last_hashes.get(url, "")
        old_content = self.last_contents.get(url, "")

        if not old_hash:
            self.last_hashes[url] = new_hash
            self.last_contents[url] = new_content
            logging.info(f"First check for {url}, storing initial hash")
            return None

        if new_hash == old_hash:
            return None

        matcher = difflib.SequenceMatcher(None, old_content, new_content)
        similarity = matcher.ratio()

        threshold = float(self.config.get("SIMILARITY_THRESHOLD", 0.98))
        min_lines = int(self.config.get("MIN_LINES_CHANGED", 2))

        old_lines = old_content.splitlines()
        new_lines = new_content.splitlines()
        lines_diff = sum(1 for a, b in zip(old_lines, new_lines) if a != b) + abs(len(old_lines) - len(new_lines))

        is_significant = (similarity < threshold) and (lines_diff >= min_lines)
        if not is_significant:
            logging.info(f"Ignored small change for {url}: similarity={similarity:.4f}, lines_diff={lines_diff}")
            return None

        diff_content = "\n".join(
            difflib.unified_diff(
                old_content.splitlines(),
                new_content.splitlines(),
                fromfile="old",
                tofile="new",
                lineterm="",
                n=self.config.get("DIFF_CONTEXT_LINES", 5)
            )
        )

        self.last_hashes[url] = new_hash
        self.last_contents[url] = new_content

        return ChangeDetection(
            url=url,
            old_hash=old_hash,
            new_hash=new_hash,
            change_ratio=1.0 - similarity,
            diff_content=diff_content,
            timestamp=datetime.now()
        )

    def extract_relevant_content(self, url: str, html_content: str) -> str:
        if not html_content:
            return ""

        try:
            if not BS4_AVAILABLE:
                return self.content_normalizer.normalize(html_content)

            soup = BeautifulSoup(html_content, "html.parser")

            selectors_map = self.config.get("SITE_SELECTORS", {})
            selector = None
            for key, sel in selectors_map.items():
                if key in url:
                    selector = sel
                    break

            if selector:
                for sel in selector.split(","):
                    el = soup.select_one(sel.strip())
                    if el:
                        for bad in el(["script", "style", "noscript", "iframe"]):
                            bad.decompose()
                        text = el.get_text(separator="\n", strip=True)
                        return self.content_normalizer.normalize(text)

            for bad in soup(["script", "style", "noscript", "iframe"]):
                bad.decompose()
            return self.content_normalizer.normalize(soup.get_text(separator="\n", strip=True))

        except Exception as e:
            logging.error(f"Error extracting content from {url}: {e}")
            return ""


class EmailNotifier:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.last_sent: Dict[str, datetime] = {}

    def send_notification(self, change: ChangeDetection):
        url = change.url
        now = datetime.now()
        rate_limit_minutes = int(self.config.get("NOTIFICATION_RATE_LIMIT_MINUTES", 60))

        last_time = self.last_sent.get(url)
        if last_time and (now - last_time).total_seconds() < rate_limit_minutes * 60:
            logging.info(f"Skipping email for {url} due to rate limiting")
            return

        subject = f"[Monitor] Mudança detectada em {url}"
        body = f"""
Mudança detectada em: {url}
Data: {change.timestamp}

Proporção de mudança: {change.change_ratio:.2%}

Diferença:
{change.diff_content[:3000]}
"""
        msg = MIMEMultipart()
        msg["From"] = self.config.get("EMAIL_SENDER")
        msg["To"] = ", ".join(self.config.get("EMAIL_RECIPIENTS", []))
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain", "utf-8"))

        try:
            with smtplib.SMTP(self.config.get("SMTP_SERVER"), self.config.get("SMTP_PORT")) as server:
                if self.config.get("SMTP_USERNAME") and self.config.get("SMTP_PASSWORD"):
                    server.starttls()
                    server.login(self.config["SMTP_USERNAME"], self.config["SMTP_PASSWORD"])
                server.send_message(msg)
            self.last_sent[url] = now
            logging.info(f"Email sent for {url}")
        except Exception as e:
            logging.error(f"Failed to send email for {url}: {e}")


class PageMonitor:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.detector = ContentChangeDetector(config)
        self.notifier = EmailNotifier(config)
        self.session = requests.Session()

    def get_page_content(self, url: str) -> str:
        try:
            response = self.session.get(url, timeout=self.config["REQUEST_TIMEOUT"])
            response.raise_for_status()
            return response.text
        except Exception as e:
            logging.error(f"Error fetching {url}: {e}")
            return ""

    def run_once(self):
        with ThreadPoolExecutor(max_workers=self.config["MAX_WORKERS"]) as executor:
            future_to_url = {executor.submit(self.get_page_content, url): url for url in self.config["URLS"]}
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                html = future.result()
                relevant = self.detector.extract_relevant_content(url, html)
                change = self.detector.detect_change(url, relevant)
                if change:
                    self.notifier.send_notification(change)
        self.detector.save_state()


def main():
    config_manager = ConfigManager(os.getenv("MONITOR_CONFIG_PATH", "config.json"))
    monitor = PageMonitor(config_manager.config)
    monitor.run_once()


if __name__ == "__main__":
    main()