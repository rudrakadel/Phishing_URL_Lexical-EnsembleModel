from __future__ import annotations

import base64
import html
import io
import ipaddress
import json
import logging
import math
import os
import re
import socket
import ssl
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse
import importlib.util
import sys

try:
    from services.security_service import SecurityService
except ImportError:
    from .security_service import SecurityService

try:
    import dns.resolver
except Exception:  # pragma: no cover
    dns = None
else:
    dns = dns.resolver

try:
    import joblib
except Exception:  # pragma: no cover
    joblib = None

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except Exception:  # pragma: no cover
    plt = None

try:
    import numpy as np
except Exception:  # pragma: no cover
    np = None

try:
    import pandas as pd
except Exception:  # pragma: no cover
    pd = None

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

try:
    import redis
except Exception:  # pragma: no cover
    redis = None

try:
    import shap
except Exception:  # pragma: no cover
    shap = None

try:
    import tldextract
except Exception:  # pragma: no cover
    tldextract = None

try:
    import whois
except Exception:  # pragma: no cover
    whois = None

try:
    from bs4 import BeautifulSoup
except Exception:  # pragma: no cover
    BeautifulSoup = None

try:
    from playwright.sync_api import sync_playwright
except Exception:  # pragma: no cover
    sync_playwright = None

try:
    from reportlab.lib import colors as rl_colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
except Exception:  # pragma: no cover
    SimpleDocTemplate = None


log = logging.getLogger("flask-phishing-app")
if not log.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


KNOWN_BRANDS = {
    "google": "google.com",
    "microsoft": "microsoft.com",
    "paypal": "paypal.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "github": "github.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
}

SUSPICIOUS_PHRASES = [
    "verify your account",
    "confirm your identity",
    "account suspended",
    "immediate action required",
    "click here to confirm",
    "your account is at risk",
    "unusual activity detected",
    "enter your credentials",
    "verify now",
    "update your payment",
    "password",
    "otp",
]

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "cutt.ly",
    "ow.ly",
    "is.gd",
}


@dataclass
class ModelArtifacts:
    model: Any | None
    preprocessor: Any | None
    selected_features: list[str]
    errors: list[str]


class PhishingAnalyzer:
    def __init__(self, BASE_DIR: Path, model_dir: Path) -> None:
        self.base_dir = BASE_DIR
        self.model_dir = Path(os.getenv("PHISHING_MODEL_DIR", str(model_dir)))
        self.ollama_url = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434/api/generate")
        self.ollama_model = os.getenv("OLLAMA_MODEL", "deepseek:1.5b")
        self.virustotal_api_key = os.getenv("VT_API_KEY")
        self.redis_url = os.getenv("REDIS_URL", "")
        self.cache_ttl = int(os.getenv("ANALYSIS_CACHE_TTL_SECONDS", "1800"))
        self.request_timeout_seconds = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "5"))
        self.external_timeout_seconds = int(os.getenv("EXTERNAL_TIMEOUT_SECONDS", "4"))
        self.ollama_timeout_seconds = int(os.getenv("OLLAMA_TIMEOUT_SECONDS", "30"))
        self.screenshot_timeout_ms = int(os.getenv("SCREENSHOT_TIMEOUT_MS", "15000"))
        self.screenshot_dir = self.base_dir / "static" / "screenshots"
        self.runtime_dir = self.base_dir / "runtime"
        self.tld_cache_dir = self.runtime_dir / "tldextract-cache"
        self.mpl_config_dir = self.runtime_dir / "matplotlib"
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.tld_cache_dir.mkdir(parents=True, exist_ok=True)
        self.mpl_config_dir.mkdir(parents=True, exist_ok=True)
        self.screenshot_dir.mkdir(parents=True, exist_ok=True)
        os.environ.setdefault("MPLCONFIGDIR", str(self.mpl_config_dir))
        self.tld_extractor = self._build_tld_extractor()
        self.redis_client = self._build_redis_client()
        self.http = requests.Session() if requests is not None else None
        if self.http is not None:
            self.http.headers.update({"User-Agent": "Mozilla/5.0 PhishScope/1.0"})
        self.missing_dependencies = self._detect_missing_dependencies()
        self.artifacts = self._load_artifacts()
        self.model_ready = True

    @staticmethod
    def _patch_tree_model_compat(model: Any) -> None:
        """Add sklearn 1.4+ tree attributes missing from older pickles."""
        seen: set[int] = set()

        def visit(obj: Any) -> None:
            obj_id = id(obj)
            if obj_id in seen:
                return
            seen.add(obj_id)

            if obj.__class__.__name__ in {"DecisionTreeClassifier", "DecisionTreeRegressor"} and not hasattr(obj, "monotonic_cst"):
                obj.monotonic_cst = None

            for attr in ("estimators_", "estimator_", "base_estimator_", "final_estimator_"):
                child = getattr(obj, attr, None)
                if child is None:
                    continue
                if isinstance(child, (list, tuple)):
                    for item in child:
                        visit(item)
                else:
                    visit(child)

        visit(model)

    def _detect_missing_dependencies(self) -> list[str]:
        missing = []
        dependency_map = {
            "bs4": BeautifulSoup,
            "joblib": joblib,
            "pandas": pd,
            "requests": requests,
            "tldextract": tldextract,
        }
        for name, module in dependency_map.items():
            if module is None:
                missing.append(name)
        return missing

    def _load_artifacts(self) -> ModelArtifacts:
        # 1. Tier 1 Model Loading
        t1_model_path = self.model_dir / "Model" / "1" / "tier1_url_model.pkl"
        t1_prep_path = self.model_dir / "Model" / "1" / "preprocessor.pkl"
        
        if not t1_model_path.exists():
            raise FileNotFoundError(f"Missing Tier 1 Model: {t1_model_path}")
        if not t1_prep_path.exists():
            raise FileNotFoundError(f"Missing Tier 1 Preprocessor: {t1_prep_path}")
            
        try:
            self.tier1_model = joblib.load(t1_model_path)
            self.tier1_preprocessor = joblib.load(t1_prep_path)
            self._patch_tree_model_compat(self.tier1_model)
        except Exception as exc:
            raise RuntimeError(f"Failed to load Tier 1 Model or Preprocessor: {exc}")
            
        # 2. Tier 2 Model Loading
        t2_model_path = self.model_dir / "Model" / "2" / "final_ensemble.pkl"
        t2_prep_path = self.model_dir / "Model" / "2" / "preprocessor.pkl"
        t2_feat_path = self.model_dir / "Model" / "2" / "selected_features.txt"
        
        if not t2_model_path.exists():
            raise FileNotFoundError(f"Missing Tier 2 Model: {t2_model_path}")
        if not t2_prep_path.exists():
            raise FileNotFoundError(f"Missing Tier 2 Preprocessor: {t2_prep_path}")
        if not t2_feat_path.exists():
            raise FileNotFoundError(f"Missing Tier 2 Feature list: {t2_feat_path}")
            
        try:
            self.tier2_model = joblib.load(t2_model_path)
            self.tier2_preprocessor = joblib.load(t2_prep_path)
            self.tier2_selected_features = [
                line.strip() for line in t2_feat_path.read_text(encoding="utf-8").splitlines() if line.strip()
            ]
        except Exception as exc:
            raise RuntimeError(f"Failed to load Tier 2 Model or Preprocessor: {exc}")
            
        # 3. Dynamic Tier 3 (Network Intelligence) Loading
        t3_script_path = self.model_dir / "Model" / "3" / "network_intelligence.py"
        if not t3_script_path.exists():
            raise FileNotFoundError(f"Missing Tier 3 script: {t3_script_path}")
        try:
            spec = importlib.util.spec_from_file_location("network_intelligence", str(t3_script_path))
            net_intel_mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(net_intel_mod)
            self.network_analyzer = net_intel_mod.NetworkIntelligenceAnalyzer()
        except Exception as exc:
            raise RuntimeError(f"Failed to dynamically load Tier 3 Network Analyzer: {exc}")
            
        # Initialize Explicit Security Layer
        try:
            self.security_analyzer = SecurityService()
        except Exception as exc:
            raise RuntimeError(f"Failed to initialize Security Service: {exc}")
            
        # Return backward-compatible ModelArtifacts pointing to Tier 2
        return ModelArtifacts(
            model=self.tier2_model,
            preprocessor=self.tier2_preprocessor,
            selected_features=self.tier2_selected_features,
            errors=[]
        )

    def _build_tld_extractor(self):
        if tldextract is None:
            return None
        try:
            return tldextract.TLDExtract(cache_dir=str(self.tld_cache_dir))
        except Exception:
            return None

    def _extract_tier1_features(self, url: str) -> dict[str, float]:
        parsed = urlparse(url)
        hostname = parsed.netloc
        
        length_url = float(len(url))
        length_hostname = float(len(hostname))
        nb_dots = float(url.count('.'))
        nb_hyphens = float(url.count('-'))
        nb_www = float(hostname.lower().count('www'))
        ratio_digits_url = float(sum(c.isdigit() for c in url) / len(url)) if len(url) > 0 else 0.0
        
        all_words = re.findall(r'[a-zA-Z0-9]+', url)
        scheme = parsed.scheme
        if all_words and all_words[0].lower() == scheme.lower():
            all_words_no_scheme = all_words[1:]
        else:
            all_words_no_scheme = all_words
            
        ext = self.tld_extractor(hostname) if self.tld_extractor else tldextract.extract(hostname)
        tld_suffix = ext.suffix
        tld_words = re.findall(r'[a-zA-Z0-9]+', tld_suffix)
        
        host_words = re.findall(r'[a-zA-Z0-9]+', hostname)
        num_tld_words = len(tld_words)
        
        words_raw = []
        if len(all_words_no_scheme) >= len(host_words):
            words_raw = all_words_no_scheme[:len(host_words) - num_tld_words] + all_words_no_scheme[len(host_words):]
        else:
            words_raw = all_words_no_scheme
            
        length_words_raw = float(len(words_raw))
        longest_words_raw = float(max((len(w) for w in words_raw), default=0))
        
        path_full = parsed.path + ('?' + parsed.query if parsed.query else '') + ('#' + parsed.fragment if parsed.fragment else '')
        path_words = re.findall(r'[a-zA-Z0-9]+', path_full)
        longest_word_path = float(max((len(w) for w in path_words), default=0))
        
        hints = ["secure", "account", "login", "update", "bank", "verify", "signin", "password", "otp", "admin", "auth"]
        phish_hints = float(sum(1 for hint in hints if hint in url.lower()))
        
        nb_slash = float(url.count('/'))
        
        host_no_tld = '.'.join([part for part in [ext.subdomain, ext.domain] if part])
        host_no_tld_words = re.findall(r'[a-zA-Z0-9]+', host_no_tld)
        shortest_word_host = float(min((len(w) for w in host_no_tld_words), default=0))
        
        return {
            "length_url": length_url,
            "length_hostname": length_hostname,
            "nb_dots": nb_dots,
            "nb_hyphens": nb_hyphens,
            "nb_www": nb_www,
            "ratio_digits_url": ratio_digits_url,
            "length_words_raw": length_words_raw,
            "longest_words_raw": longest_words_raw,
            "longest_word_path": longest_word_path,
            "phish_hints": phish_hints,
            "nb_slash": nb_slash,
            "shortest_word_host": shortest_word_host
        }

    def _run_tier1_model(self, features: dict[str, float]) -> dict[str, Any]:
        if pd is None:
            return {"probability": 0.5, "prediction": "unknown"}
        features_list = [
            "length_url", "length_hostname", "nb_dots", "nb_hyphens", "nb_www",
            "ratio_digits_url", "length_words_raw", "longest_words_raw",
            "longest_word_path", "phish_hints", "nb_slash", "shortest_word_host"
        ]
        input_df = pd.DataFrame([features], columns=features_list)
        try:
            scaled = self.tier1_preprocessor.transform(input_df)
            prediction = int(self.tier1_model.predict(scaled)[0])
            probability = float(self.tier1_model.predict_proba(scaled)[0][1])
            return {
                "probability": probability,
                "prediction": "phishing" if prediction == 1 else "legitimate"
            }
        except Exception as e:
            log.error(f"Error running Tier 1 model: {e}")
            return {"probability": 0.5, "prediction": "unknown"}

    def optional_services_status(self) -> dict[str, Any]:
        return {
            "ollama_model": self.ollama_model,
            "virustotal_configured": bool(self.virustotal_api_key),
            "redis_configured": bool(self.redis_url),
            "redis_available": self.redis_client is not None,
            "playwright_available": sync_playwright is not None,
            "reportlab_available": SimpleDocTemplate is not None,
            "shap_available": shap is not None,
            "matplotlib_available": plt is not None,
        }

    def _build_redis_client(self):
        if not self.redis_url or redis is None:
            return None
        try:
            client = redis.Redis.from_url(self.redis_url, decode_responses=True)
            client.ping()
            return client
        except Exception:
            return None

    def _cache_key(self, normalized_url: str) -> str:
        return f"phishing-analysis:v1:{normalized_url}"

    def _request(self, method: str, url: str, timeout: int | None = None, **kwargs):
        client = self.http or requests
        if client is None:
            raise RuntimeError("requests unavailable")
        return client.request(method, url, timeout=timeout or self.request_timeout_seconds, **kwargs)

    def _get_cached_result(self, normalized_url: str) -> dict[str, Any] | None:
        if not self.redis_client:
            return None
        try:
            payload = self.redis_client.get(self._cache_key(normalized_url))
            if not payload:
                return None
            result = json.loads(payload)
            result["cache"] = {"hit": True, "backend": "redis", "ttl_seconds": self.cache_ttl}
            return result
        except Exception:
            return None

    def _set_cached_result(self, normalized_url: str, result: dict[str, Any]) -> None:
        if not self.redis_client:
            return
        try:
            cache_payload = dict(result)
            cache_payload["cache"] = {"hit": False, "backend": "redis", "ttl_seconds": self.cache_ttl}
            self.redis_client.setex(self._cache_key(normalized_url), self.cache_ttl, json.dumps(cache_payload, default=str))
        except Exception:
            pass

    def analyze_url(self, raw_url: str) -> dict[str, Any]:
        started = time.perf_counter()
        normalized = self._normalize_url(raw_url)
        cached = self._get_cached_result(normalized)
        if cached:
            cached["analysis_duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
            return cached
        validation = self._validate_url(normalized)
        if not validation["valid"]:
            return {
                "input_url": raw_url,
                "url": normalized,
                "verdict": "Invalid URL",
                "prediction": "legitimate",
                "hybrid_score": 100.0,
                "final_score": 100.0,
                "tier1_score": 100.0,
                "tier2_score": 100.0,
                "network_score": 100.0,
                "security_score": 100.0,
                "validation": validation,
                "error": validation["error"],
                "model_ready": self.model_ready,
                "model_errors": [],
            }

        # Run Tier 1 model on the URL features
        tier1_features = self._extract_tier1_features(normalized)
        tier1_result = self._run_tier1_model(tier1_features)
        tier1_score = round(tier1_result["probability"] * 100, 2)

        parsed = urlparse(normalized)
        hostname = parsed.netloc
        domain = self._registered_domain(hostname)
        url_signals = self._analyze_url_structure(normalized, hostname)

        with ThreadPoolExecutor(max_workers=6) as executor:
            crawl_future = executor.submit(self._crawl, normalized, domain)
            ssl_future = executor.submit(self._analyze_ssl, hostname)
            dns_future = executor.submit(self._analyze_dns, domain)
            reputation_future = executor.submit(self._analyze_reputation, domain)
            threat_future = executor.submit(self._check_threat_intelligence, normalized, domain)

            crawl = crawl_future.result()
            ssl_info = ssl_future.result()
            dns_info = dns_future.result()
            reputation = reputation_future.result()
            threat_intel = threat_future.result()

            nlp_future = executor.submit(self._analyze_text, normalized, crawl.get("html", ""), crawl.get("title", ""))
            sandbox_future = executor.submit(self._build_sandbox, normalized, crawl.get("html", ""))

            nlp = nlp_future.result()
            sandbox = sandbox_future.result()

            # Execute Tier 2 Model conditionally if HTML is available
            if crawl.get("html_ok"):
                ml_features = self._extract_model_features(normalized, crawl, reputation)
                ml_result = self._run_model(ml_features)
                tier2_score = round(ml_result["probability"] * 100, 2) if ml_result.get("available") else None
            else:
                ml_result = {
                    "available": False,
                    "probability": tier1_result["probability"],
                    "prediction": tier1_result["prediction"],
                    "features": {},
                    "reason": "HTML fetch failed, Tier 2 skipped."
                }
                ml_features = {}
                tier2_score = None

            # Execute Network Intelligence and Security Layer
            header_analysis = self._analyze_security_headers(crawl.get("response_headers", {}))
            security_result = self.security_analyzer.analyze(
                crawl.get("response_headers", {}),
                crawl.get("html", ""),
                crawl.get("redirect_count", 0)
            )
            security_score = round(security_result["security_score"], 2)

            ssl_score = round(self._compute_ssl_risk(ssl_info), 2)
            dns_score = round(self._compute_dns_risk(dns_info), 2)
            reputation_score = round(reputation["risk_score"], 2)
            network_score = round(0.40 * ssl_score + 0.30 * dns_score + 0.30 * reputation_score, 2)

            # Consensus Score Weighting
            if crawl.get("html_ok") and tier2_score is not None:
                final_score = round(0.55 * tier1_score + 0.25 * tier2_score + 0.10 * network_score + 0.10 * security_score, 2)
            else:
                final_score = round(0.75 * tier1_score + 0.15 * network_score + 0.10 * security_score, 2)

            verdict = self._verdict_for_score(final_score)
            if threat_intel.get("known_malicious"):
                final_score = max(final_score, 95.0)
                verdict = "Known Malicious"

            screenshot_future = executor.submit(self._capture_screenshot, normalized) if crawl.get("html_ok") else None
            ollama_future = executor.submit(
                self._analyze_with_ollama,
                normalized,
                crawl.get("html", ""),
                header_analysis,
                nlp,
                ml_result,
            ) if self._should_run_ollama(ml_result, header_analysis, nlp, crawl) else None
            shap_future = executor.submit(self._compute_shap, ml_features) if self._should_run_shap(ml_result) else None

            screenshot = screenshot_future.result() if screenshot_future else {
                "available": False,
                "path": None,
                "error": "Screenshot unavailable because the page HTML could not be fetched.",
            }
            ollama = ollama_future.result() if ollama_future else self._build_ollama_fallback(
                normalized,
                header_analysis,
                nlp,
                ml_result,
            )
            shap_result = shap_future.result() if shap_future else {
                "available": False,
                "top_features": [],
                "reason": "SHAP unavailable because Tier 2 model was skipped.",
            }

        component_scores = {
            "ML": round(ml_result["probability"] * 100, 2),
            "HTML": round(self._compute_html_risk(crawl), 2),
            "Headers": round(header_analysis["risk_score"], 2),
            "NLP": round(nlp["risk_score"], 2),
            "SSL": ssl_score,
            "DNS": dns_score,
            "Reputation": reputation_score,
            "URL": round(self._compute_url_risk(url_signals), 2),
            "Tier 1 (URL)": tier1_score,
            "Tier 2 (HTML)": tier2_score if tier2_score is not None else "Skipped",
            "Network (Tier 3)": network_score,
            "Security Layer": security_score,
        }

        charts = self._build_chart_assets(component_scores, shap_result, final_score)
        human_summary = self._generate_human_summary(verdict, final_score, nlp, shap_result, threat_intel)

        result = {
            "input_url": raw_url,
            "url": normalized,
            "domain": domain,
            "verdict": verdict,
            "prediction": "phishing" if final_score >= 50 else "legitimate",
            "hybrid_score": final_score,
            "final_score": final_score,
            "tier1_score": tier1_score,
            "tier2_score": tier2_score if tier2_score is not None else 0.0,
            "network_score": network_score,
            "security_score": security_score,
            "confidence": round(max(0.0, 100.0 - abs(tier1_score - final_score)), 2),
            "validation": validation,
            "components": component_scores,
            "ml": ml_result,
            "selected_features": self.artifacts.selected_features,
            "network": {
                "crawl": crawl,
                "ssl": ssl_info,
                "dns": dns_info,
                "reputation": reputation,
                "url_signals": url_signals,
                "security_headers": header_analysis,
                "explicit_security": security_result,
            },
            "nlp": nlp,
            "ollama": ollama,
            "threat_intelligence": threat_intel,
            "sandbox": sandbox,
            "screenshot": screenshot,
            "shap": shap_result,
            "charts": charts,
            "human_summary": human_summary,
            "model_ready": self.model_ready,
            "model_errors": [],
            "cache": {"hit": False, "backend": "redis" if self.redis_client else None, "ttl_seconds": self.cache_ttl},
            "analysis_duration_ms": round((time.perf_counter() - started) * 1000, 2),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        self._set_cached_result(normalized, result)
        return result

    def analyze_url_fast(self, raw_url: str) -> dict[str, Any]:
        started = time.perf_counter()
        normalized = self._normalize_url(raw_url)
        cached = self._get_cached_result(normalized)
        if cached:
            cached["analysis_duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
            return cached
        validation = self._validate_url(normalized)
        if not validation["valid"]:
            return {
                "input_url": raw_url,
                "url": normalized,
                "verdict": "Invalid URL",
                "prediction": "legitimate",
                "hybrid_score": 100.0,
                "final_score": 100.0,
                "tier1_score": 100.0,
                "tier2_score": 100.0,
                "network_score": 100.0,
                "security_score": 100.0,
                "validation": validation,
                "error": validation["error"],
                "model_ready": self.model_ready,
                "model_errors": [],
                "enrichment": {"status": "error"},
            }

        # Run Tier 1 model on the URL features
        tier1_features = self._extract_tier1_features(normalized)
        tier1_result = self._run_tier1_model(tier1_features)
        tier1_score = round(tier1_result["probability"] * 100, 2)

        parsed = urlparse(normalized)
        hostname = parsed.netloc
        domain = self._registered_domain(hostname)
        url_signals = self._analyze_url_structure(normalized, hostname)

        with ThreadPoolExecutor(max_workers=3) as executor:
            crawl_future = executor.submit(self._crawl, normalized, domain)
            ssl_future = executor.submit(self._analyze_ssl, hostname)
            dns_future = executor.submit(self._analyze_dns, domain)
            crawl = crawl_future.result()
            ssl_info = ssl_future.result()
            dns_info = dns_future.result()

        reputation = {"risk_score": 0, "risk_factors": [], "domain_age_days": None}
        nlp = self._analyze_text(normalized, crawl.get("html", ""), crawl.get("title", ""))
        header_analysis = self._analyze_security_headers(crawl.get("response_headers", {}))
        
        # Execute Tier 2 Model conditionally if HTML is available
        if crawl.get("html_ok"):
            ml_features = self._extract_model_features(normalized, crawl, reputation)
            ml_result = self._run_model(ml_features)
            tier2_score = round(ml_result["probability"] * 100, 2) if ml_result.get("available") else None
        else:
            ml_result = {
                "available": False,
                "probability": tier1_result["probability"],
                "prediction": tier1_result["prediction"],
                "features": {},
                "reason": "HTML fetch failed, Tier 2 skipped."
            }
            ml_features = {}
            tier2_score = None

        # Execute Network Intelligence and Security Layer
        security_result = self.security_analyzer.analyze(
            crawl.get("response_headers", {}),
            crawl.get("html", ""),
            crawl.get("redirect_count", 0)
        )
        security_score = round(security_result["security_score"], 2)

        ssl_score = round(self._compute_ssl_risk(ssl_info), 2)
        dns_score = round(self._compute_dns_risk(dns_info), 2)
        reputation_score = round(reputation["risk_score"], 2)
        network_score = round(0.40 * ssl_score + 0.30 * dns_score + 0.30 * reputation_score, 2)

        # Consensus Score Weighting
        if crawl.get("html_ok") and tier2_score is not None:
            final_score = round(0.55 * tier1_score + 0.25 * tier2_score + 0.10 * network_score + 0.10 * security_score, 2)
        else:
            final_score = round(0.75 * tier1_score + 0.15 * network_score + 0.10 * security_score, 2)

        verdict = self._verdict_for_score(final_score)
        
        component_scores = {
            "ML": round(ml_result["probability"] * 100, 2),
            "HTML": round(self._compute_html_risk(crawl), 2),
            "Headers": round(header_analysis["risk_score"], 2),
            "NLP": round(nlp["risk_score"], 2),
            "SSL": ssl_score,
            "DNS": dns_score,
            "Reputation": reputation_score,
            "URL": round(self._compute_url_risk(url_signals), 2),
            "Tier 1 (URL)": tier1_score,
            "Tier 2 (HTML)": tier2_score if tier2_score is not None else "Skipped",
            "Network (Tier 3)": network_score,
            "Security Layer": security_score,
        }
        
        charts = self._build_chart_assets(component_scores, {"available": False, "top_features": []}, final_score)

        return {
            "input_url": raw_url,
            "url": normalized,
            "domain": domain,
            "verdict": verdict,
            "prediction": "phishing" if final_score >= 50 else "legitimate",
            "hybrid_score": final_score,
            "final_score": final_score,
            "tier1_score": tier1_score,
            "tier2_score": tier2_score if tier2_score is not None else 0.0,
            "network_score": network_score,
            "security_score": security_score,
            "confidence": round(max(0.0, 100.0 - abs(tier1_score - final_score)), 2),
            "validation": validation,
            "components": component_scores,
            "ml": ml_result,
            "selected_features": self.artifacts.selected_features,
            "network": {
                "crawl": crawl,
                "ssl": ssl_info,
                "dns": dns_info,
                "reputation": reputation,
                "url_signals": url_signals,
                "security_headers": header_analysis,
                "explicit_security": security_result,
            },
            "nlp": nlp,
            "ollama": {"enabled": True, "available": False, "summary": "Deferred for background enrichment.", "findings": [], "recommendations": []},
            "threat_intelligence": {"known_malicious": False, "sources": [], "details": {}},
            "sandbox": {"html": "<div class='empty-sandbox'>Deferred for background enrichment.</div>", "removed": {}, "source_excerpt": "", "source_length": 0, "truncated": False},
            "screenshot": {"available": False, "path": None, "error": "Deferred for background enrichment."},
            "shap": {"available": False, "top_features": [], "reason": "Deferred for background enrichment."},
            "charts": charts,
            "human_summary": "Fast analysis completed. Deep enrichment is running in the background.",
            "model_ready": self.model_ready,
            "model_errors": [],
            "cache": {"hit": False, "backend": "redis" if self.redis_client else None, "ttl_seconds": self.cache_ttl},
            "analysis_duration_ms": round((time.perf_counter() - started) * 1000, 2),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "enrichment": {"status": "pending"},
        }

    def _normalize_url(self, raw_url: str) -> str:
        candidate = raw_url.strip()
        if not candidate.startswith(("http://", "https://")):
            candidate = f"http://{candidate}"
        return candidate

    def _validate_url(self, url: str) -> dict[str, Any]:
        parsed = urlparse(url)
        if not parsed.netloc:
            return {"valid": False, "error": "Missing hostname", "warnings": []}
        warnings = []
        if len(parsed.netloc) > 50:
            warnings.append("Unusually long hostname")
        if parsed.netloc.count("-") > 2:
            warnings.append("Multiple hyphens in hostname")
        if "@" in url:
            warnings.append("@ symbol present in URL")
        return {"valid": True, "warnings": warnings}

    def _registered_domain(self, host: str) -> str:
        if tldextract is None:
            return host
        try:
            extracted = self.tld_extractor(host) if self.tld_extractor else tldextract.extract(host)
        except Exception:
            return host
        return extracted.registered_domain or host

    def _crawl(self, url: str, base_domain: str) -> dict[str, Any]:
        result = {
            "status_code": None,
            "html_ok": False,
            "html": "",
            "title": "",
            "response_headers": {},
            "hyperlinks": 0,
            "ratio_external_links": 0.0,
            "ratio_null_links": 0.0,
            "login_form": False,
            "iframe": False,
            "suspicious_form_handler": False,
            "error": None,
            "redirect_count": 0,
        }
        if requests is None or BeautifulSoup is None:
            result["error"] = "requests or bs4 unavailable"
            return result

        try:
            response = self._request("GET", url, timeout=self.request_timeout_seconds, allow_redirects=True)
            result["redirect_count"] = len(response.history)
            result["status_code"] = response.status_code
            result["response_headers"] = dict(response.headers)
            if "text/html" not in response.headers.get("content-type", "").lower():
                result["error"] = "Non-HTML response"
                return result

            soup = BeautifulSoup(response.text, "html.parser")
            anchors = soup.find_all("a", href=True)
            total = len(anchors)
            external = 0
            nulls = 0
            for anchor in anchors:
                href = anchor.get("href", "").strip()
                if not href or href in {"#", "javascript:void(0)", "javascript:;"}:
                    nulls += 1
                    continue
                absolute = urljoin(url, href)
                target = self._registered_domain(urlparse(absolute).netloc)
                if target and base_domain and target != base_domain:
                    external += 1

            result.update(
                {
                    "html_ok": True,
                    "html": response.text,
                    "title": soup.title.get_text(strip=True) if soup.title else "",
                    "hyperlinks": total,
                    "ratio_external_links": round(external / total, 4) if total else 0.0,
                    "ratio_null_links": round(nulls / total, 4) if total else 0.0,
                    "login_form": bool(soup.find("input", {"type": "password"})),
                    "iframe": bool(soup.find(["iframe", "frame"])),
                    "suspicious_form_handler": any(
                        (form.get("action", "").strip().lower() in {"", "#", "about:blank"})
                        for form in soup.find_all("form")
                    ),
                }
            )
        except Exception as exc:
            result["error"] = str(exc)
        return result

    def _analyze_ssl(self, hostname: str) -> dict[str, Any]:
        info = {
            "has_ssl": False,
            "issuer": "Unknown",
            "days_until_expiry": None,
            "is_expired": None,
            "certificate_age_days": None,
            "cn_matches": None,
            "error": None,
        }
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=self.request_timeout_seconds) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            alt_names = [value.lower() for key, value in cert.get("subjectAltName", []) if key == "DNS"]
            matches = hostname.lower() in alt_names or subject.get("commonName", "").lower() == hostname.lower()
            info.update(
                {
                    "has_ssl": True,
                    "issuer": issuer.get("organizationName", issuer.get("commonName", "Unknown")),
                    "days_until_expiry": (not_after - datetime.utcnow()).days,
                    "is_expired": not_after < datetime.utcnow(),
                    "certificate_age_days": (datetime.utcnow() - not_before).days,
                    "cn_matches": matches,
                }
            )
        except Exception as exc:
            info["error"] = str(exc)
        return info

    def _analyze_dns(self, domain: str) -> dict[str, Any]:
        info = {
            "has_a_record": False,
            "has_mx_record": False,
            "has_spf": False,
            "has_dmarc": False,
            "ips": [],
            "error": None,
        }
        if dns is None:
            info["error"] = "dnspython unavailable"
            return info
        try:
            answers = dns.resolve(domain, "A", lifetime=4)
            info["has_a_record"] = True
            info["ips"] = [str(item) for item in answers]
        except Exception:
            pass
        try:
            dns.resolve(domain, "MX", lifetime=4)
            info["has_mx_record"] = True
        except Exception:
            pass
        try:
            for txt in dns.resolve(domain, "TXT", lifetime=4):
                if "v=spf1" in str(txt).lower():
                    info["has_spf"] = True
        except Exception:
            pass
        try:
            for txt in dns.resolve(f"_dmarc.{domain}", "TXT", lifetime=4):
                if "v=dmarc1" in str(txt).lower():
                    info["has_dmarc"] = True
        except Exception:
            pass
        return info

    def _analyze_reputation(self, domain: str) -> dict[str, Any]:
        factors = []
        age_days = None
        if whois is not None:
            try:
                data = whois.whois(domain)
                created = data.creation_date
                if isinstance(created, list):
                    created = created[0]
                if isinstance(created, datetime):
                    age_days = (datetime.utcnow() - created.replace(tzinfo=None)).days
            except Exception:
                pass
        if age_days is not None and age_days < 30:
            factors.append("Domain younger than 30 days")
        elif age_days is not None and age_days < 180:
            factors.append("Domain younger than 6 months")
        if len(domain) > 30:
            factors.append("Long domain")
        if domain.count("-") >= 3:
            factors.append("Hyphen-heavy domain")
        if domain.endswith((".xyz", ".top", ".click", ".work", ".pw")):
            factors.append("Suspicious TLD")
        score = 0
        for factor in factors:
            if "30 days" in factor:
                score += 40
            elif "6 months" in factor:
                score += 20
            elif "Suspicious TLD" in factor:
                score += 30
            else:
                score += 10
        return {"risk_score": min(score, 100), "risk_factors": factors, "domain_age_days": age_days}

    def _analyze_url_structure(self, url: str, hostname: str) -> dict[str, Any]:
        parsed = urlparse(url)
        if self.tld_extractor:
            try:
                ext = self.tld_extractor(hostname)
            except Exception:
                ext = None
        else:
            ext = tldextract.extract(hostname) if tldextract else None
        domain = ext.domain if ext else hostname
        try:
            ipaddress.ip_address(hostname.split(":")[0])
            uses_ip = True
        except Exception:
            uses_ip = False
        probs = []
        if domain:
            probs = [domain.count(ch) / len(domain) for ch in set(domain)]
        return {
            "uses_https": parsed.scheme == "https",
            "uses_ip_address": uses_ip,
            "url_length": len(url),
            "subdomain_count": len(ext.subdomain.split(".")) if ext and ext.subdomain else 0,
            "path_depth": len([part for part in parsed.path.split("/") if part]),
            "has_at_symbol": "@" in url,
            "has_double_slash": url.count("//") > 1,
            "shortening_service": hostname.lower() in SHORTENERS,
            "has_prefix_suffix": "-" in (ext.domain or "") if ext else "-" in hostname,
            "domain_entropy": round(-sum(p * math.log2(p) for p in probs if p > 0), 4) if probs else 0.0,
        }

    def _analyze_text(self, url: str, html_content: str, title: str) -> dict[str, Any]:
        if not html_content or BeautifulSoup is None:
            return {
                "risk_score": 0,
                "summary": "No HTML content available for text analysis.",
                "suspicious_phrases": [],
                "brand_impersonation": None,
            }
        soup = BeautifulSoup(html_content, "html.parser")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True))
        merged = f"{title} {text}".strip().lower()
        suspicious = [phrase for phrase in SUSPICIOUS_PHRASES if phrase in merged]
        impersonation = None
        actual_domain = self._registered_domain(urlparse(url).netloc).lower()
        for brand, brand_domain in KNOWN_BRANDS.items():
            if brand in merged and actual_domain != brand_domain:
                impersonation = {"brand": brand, "expected_domain": brand_domain}
                break
        risk = min(len(suspicious) * 12 + (35 if impersonation else 0), 100)
        return {
            "risk_score": risk,
            "summary": text[:240] or "No visible text extracted.",
            "suspicious_phrases": suspicious,
            "brand_impersonation": impersonation,
        }

    def _analyze_security_headers(self, headers: dict[str, Any]) -> dict[str, Any]:
        normalized = {str(key).lower(): str(value) for key, value in (headers or {}).items()}
        important = {
            "strict-transport-security": "HSTS",
            "content-security-policy": "CSP",
            "x-frame-options": "X-Frame-Options",
            "x-content-type-options": "X-Content-Type-Options",
            "referrer-policy": "Referrer-Policy",
            "permissions-policy": "Permissions-Policy",
            "cross-origin-opener-policy": "COOP",
            "cross-origin-embedder-policy": "COEP",
            "cross-origin-resource-policy": "CORP",
            "origin-agent-cluster": "Origin-Agent-Cluster",
            "x-permitted-cross-domain-policies": "X-Permitted-Cross-Domain-Policies",
        }
        present = {}
        missing = []
        for key, label in important.items():
            if normalized.get(key):
                present[label] = normalized[key]
            else:
                missing.append(label)
        issues = []
        if "content-security-policy" not in normalized:
            issues.append("Missing Content-Security-Policy")
        if "strict-transport-security" not in normalized:
            issues.append("Missing HSTS")
        if "cross-origin-opener-policy" not in normalized:
            issues.append("Missing COOP")
        if "cross-origin-resource-policy" not in normalized:
            issues.append("Missing CORP")
        if normalized.get("server"):
            issues.append(f"Server header exposed: {normalized['server']}")
        cookie_value = normalized.get("set-cookie", "")
        cookie_flags = {
            "httponly": "HttpOnly" in cookie_value,
            "secure": "Secure" in cookie_value,
            "samesite": "SameSite" in cookie_value,
        }
        if cookie_value and not cookie_flags["httponly"]:
            issues.append("Cookies missing HttpOnly")
        if cookie_value and not cookie_flags["secure"]:
            issues.append("Cookies missing Secure")
        if cookie_value and not cookie_flags["samesite"]:
            issues.append("Cookies missing SameSite")
        score = min((len(missing) * 12) + (8 if normalized.get("server") else 0), 100)
        return {
            "present": present,
            "missing": missing,
            "interesting": {
                "server": normalized.get("server"),
                "content-type": normalized.get("content-type"),
                "set-cookie": normalized.get("set-cookie"),
                "cookie_flags": cookie_flags,
                "cache-control": normalized.get("cache-control"),
                "server-timing": normalized.get("server-timing"),
            },
            "issues": issues,
            "risk_score": score,
        }

    def _analyze_with_ollama(
        self,
        url: str,
        html_content: str,
        headers: dict[str, Any],
        nlp: dict[str, Any],
        ml_result: dict[str, Any],
    ) -> dict[str, Any]:
        fallback = self._build_ollama_fallback(url, headers, nlp, ml_result)
        if requests is None:
            fallback.update({"enabled": False, "error": "requests unavailable"})
            return fallback
        if not html_content:
            fallback.update(
                {
                    "enabled": True,
                    "summary": "AI review skipped because the page HTML could not be fetched.",
                    "error": "No HTML available",
                }
            )
            return fallback
        snippet = re.sub(r"\s+", " ", html_content)[:3500]
        prompt = (
            "You are reviewing a webpage for phishing and client-side security risk.\n"
            "Return strict JSON with keys summary, risk_level, findings, suspicious_elements, recommendations, verdict_reasoning, phishing_signals, legitimate_signals, final_decision.\n"
            "Keep list items short and concrete.\n"
            f"URL: {url}\n"
            f"Final ensemble output: {json.dumps({'prediction': ml_result.get('prediction'), 'probability': ml_result.get('probability'), 'available': ml_result.get('available')})}\n"
            f"Header findings: {json.dumps(headers.get('issues', []))}\n"
            f"NLP suspicious phrases: {json.dumps(nlp.get('suspicious_phrases', []))}\n"
            f"HTML snippet: {snippet}"
        )
        try:
            response = self._request(
                "POST",
                self.ollama_url,
                json={
                    "model": self.ollama_model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                    "options": {"temperature": 0.1},
                },
                timeout=self.ollama_timeout_seconds,
            )
            response.raise_for_status()
            payload = response.json()
            parsed = json.loads((payload.get("response") or "{}").strip())
            return {
                "enabled": True,
                "available": True,
                "model": self.ollama_model,
                "summary": parsed.get("summary"),
                "risk_level": parsed.get("risk_level"),
                "findings": parsed.get("findings", []),
                "suspicious_elements": parsed.get("suspicious_elements", []),
                "recommendations": parsed.get("recommendations", []),
                "verdict_reasoning": parsed.get("verdict_reasoning", []),
                "phishing_signals": parsed.get("phishing_signals", []),
                "legitimate_signals": parsed.get("legitimate_signals", []),
                "final_decision": parsed.get("final_decision"),
                "error": None,
            }
        except Exception as exc:
            message = str(exc)
            friendly_error = "Ollama review is temporarily unavailable."
            if "Read timed out" in message or "timed out" in message.lower():
                friendly_error = "Ollama review timed out. The local model is busy or offline."
            elif "Connection refused" in message or "Failed to establish a new connection" in message:
                friendly_error = "Ollama is not reachable on the configured local endpoint."
            fallback.update(
                {
                    "enabled": True,
                    "model": self.ollama_model,
                    "summary": friendly_error,
                    "error": friendly_error,
                }
            )
            return fallback

    def _build_ollama_fallback(
        self,
        url: str,
        headers: dict[str, Any],
        nlp: dict[str, Any],
        ml_result: dict[str, Any],
    ) -> dict[str, Any]:
        findings: list[str] = []
        phishing_signals: list[str] = []
        legitimate_signals: list[str] = []
        recommendations: list[str] = []
        verdict_reasoning: list[str] = []

        header_issues = headers.get("issues", [])
        suspicious_phrases = nlp.get("suspicious_phrases", [])
        impersonation = nlp.get("brand_impersonation")
        ml_probability = float(ml_result.get("probability", 0) or 0)
        prediction = ml_result.get("prediction", "unknown")

        if ml_result.get("available"):
            verdict_reasoning.append(f"Classifier prediction: {prediction} ({round(ml_probability * 100, 2)}%).")
            if ml_probability >= 0.65:
                phishing_signals.append("The classifier confidence is elevated for phishing behavior.")
            elif ml_probability <= 0.25:
                legitimate_signals.append("The classifier confidence is low for phishing behavior.")
        else:
            verdict_reasoning.append("Classifier output was unavailable, so this panel is using heuristic signals.")

        if suspicious_phrases:
            findings.append(f"Suspicious wording detected: {', '.join(suspicious_phrases[:4])}.")
            phishing_signals.append("The page language contains credential or urgency cues.")
        else:
            legitimate_signals.append("No suspicious credential-harvesting phrases were detected in visible text.")

        if impersonation:
            findings.append(f"Possible brand impersonation of {impersonation.get('brand')}.")
            phishing_signals.append(f"The content references {impersonation.get('brand')} while using a different domain.")

        if header_issues:
            findings.append(f"Security header issues: {', '.join(header_issues[:3])}.")
            recommendations.append("Verify the page manually because security headers are weaker than expected.")
        else:
            legitimate_signals.append("No major security-header gaps were flagged in the response.")

        if not recommendations:
            recommendations.append("Use the network, sandbox, and screenshot sections to confirm whether the page matches the expected brand.")
        if not findings:
            findings.append(f"Heuristic review completed for {url}, but no strong phishing-specific indicators were found.")

        return {
            "enabled": True,
            "available": False,
            "model": self.ollama_model,
            "summary": "AI review is unavailable, so this section is showing a heuristic analyst summary instead.",
            "risk_level": "Heuristic Review",
            "findings": findings,
            "suspicious_elements": phishing_signals,
            "recommendations": recommendations,
            "verdict_reasoning": verdict_reasoning,
            "phishing_signals": phishing_signals,
            "legitimate_signals": legitimate_signals,
            "final_decision": "Heuristic Review",
            "error": None,
        }

    def _check_threat_intelligence(self, url: str, domain: str) -> dict[str, Any]:
        results = {"known_malicious": False, "sources": [], "details": {}}
        if requests is None:
            return results
        try:
            response = self._request("POST", "https://urlhaus-api.abuse.ch/v1/host/", data={"host": domain}, timeout=self.external_timeout_seconds)
            if response.ok:
                data = response.json()
                if data.get("query_status") == "ok" and int(data.get("urls", 0) or 0) > 0:
                    results["known_malicious"] = True
                    results["sources"].append("URLhaus")
                    results["details"]["urlhaus"] = {"urls": data.get("urls"), "firstseen": data.get("firstseen")}
        except Exception as exc:
            results["details"]["urlhaus_error"] = str(exc)
        if self.virustotal_api_key:
            try:
                vt_url = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")
                response = self._request(
                    "GET",
                    f"https://www.virustotal.com/api/v3/urls/{vt_url}",
                    headers={"x-apikey": self.virustotal_api_key},
                    timeout=self.external_timeout_seconds,
                )
                if response.ok:
                    stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    if int(stats.get("malicious", 0)) or int(stats.get("suspicious", 0)):
                        results["known_malicious"] = True
                        results["sources"].append("VirusTotal")
                    results["details"]["virustotal"] = stats
            except Exception as exc:
                results["details"]["virustotal_error"] = str(exc)
        return results

    def _build_sandbox(self, url: str, raw_html: str) -> dict[str, Any]:
        if not raw_html or BeautifulSoup is None:
            return {
                "html": "<div class='empty-sandbox'>Preview unavailable because page HTML could not be fetched.</div>",
                "removed": {},
                "source_excerpt": "",
                "source_length": 0,
                "truncated": False,
            }
        soup = BeautifulSoup(raw_html, "html.parser")
        removed = {"dangerous_tags": 0, "event_handlers": 0, "javascript_urls": 0, "meta_refresh": 0}
        for tag in soup(["script", "noscript", "iframe", "object", "embed", "base"]):
            removed["dangerous_tags"] += 1
            tag.decompose()
        for meta in soup.find_all("meta"):
            if meta.get("http-equiv", "").lower() == "refresh":
                removed["meta_refresh"] += 1
                meta.decompose()
        for tag in soup.find_all(True):
            for attr in list(tag.attrs):
                if attr.lower().startswith("on"):
                    removed["event_handlers"] += 1
                    del tag[attr]
            for attr in ("href", "src", "action"):
                value = tag.attrs.get(attr)
                if isinstance(value, str) and value.lower().startswith("javascript:"):
                    removed["javascript_urls"] += 1
                    del tag[attr]
        for form in soup.find_all("form"):
            form["data-disabled"] = "true"
            form["action"] = "#"
            if form.find("input", {"type": "password"}):
                badge = soup.new_tag("div")
                badge.string = "Password form detected in sandbox preview"
                badge["class"] = "sandbox-warning"
                form.insert(0, badge)
        style = soup.new_tag("style")
        style.string = (
            "body{font-family:Arial,sans-serif;padding:16px;}"
            "a,button,input,textarea,select,form{pointer-events:none!important;}"
            ".sandbox-warning{background:#fee2e2;color:#991b1b;padding:8px;margin-bottom:8px;font-size:12px;border:1px solid #fca5a5;}"
        )
        if soup.head:
            soup.head.insert(0, style)
        else:
            head = soup.new_tag("head")
            head.insert(0, style)
            soup.insert(0, head)
        sanitized_html = str(soup)
        limit = 2200
        return {
            "html": sanitized_html,
            "removed": removed,
            "source_url": url,
            "source_excerpt": html.escape(sanitized_html[:limit]),
            "source_length": len(sanitized_html),
            "truncated": len(sanitized_html) > limit,
        }

    def _extract_model_features(self, url: str, crawl: dict[str, Any], reputation: dict[str, Any]) -> dict[str, float]:
        parsed = urlparse(url)
        path_tokens = re.split(r"[-/._?=&]", parsed.path)
        features = {
            "nb_www": float(parsed.netloc.lower().count("www")),
            "longest_word_path": float(max((len(token) for token in path_tokens if token), default=0)),
            "phish_hints": float(
                sum(1 for hint in ("secure", "account", "login", "update", "bank", "verify", "signin", "password", "otp") if hint in url.lower())
            ),
            "nb_hyperlinks": float(crawl.get("hyperlinks", 0)),
            "ratio_extHyperlinks": float(crawl.get("ratio_external_links", 0.0)),
            "domain_age": float(reputation.get("domain_age_days") or 0.0),
            "web_traffic": float(min(crawl.get("hyperlinks", 0) * 800, 500000)) if crawl.get("html_ok") else 0.0,
            "google_index": 1.0 if parsed.scheme == "https" and crawl.get("hyperlinks", 0) > 5 else 0.0,
            "page_rank": 0.0,
            # Neutralize the poisoned transport-status feature so HTTP status alone
            # cannot dominate the saved stacking model.
            "status_encoded": 0.5,
        }
        features["page_rank"] = float(
            min(
                10,
                (2 if parsed.scheme == "https" else 0)
                + (2 if features["nb_hyperlinks"] > 20 else 0)
                + (2 if features["domain_age"] > 365 else 0)
                + (1 if features["domain_age"] > 1825 else 0)
                + (2 if features["google_index"] else 0)
                + (1 if features["ratio_extHyperlinks"] < 0.3 else 0),
            )
        )
        return features

    def _status_to_encoded(self, status_code: int | None, html_ok: bool = False) -> float:
        if status_code is None:
            return 1.0
        if 200 <= status_code < 300:
            return 0.0 if html_ok else 0.5
        if 300 <= status_code < 400:
            return 0.5
        if 400 <= status_code < 500:
            return 1.0
        return 1.0

    def _run_model(self, features: dict[str, float]) -> dict[str, Any]:
        if not self.model_ready:
            return {
                "available": False,
                "probability": 0.5,
                "prediction": "unknown",
                "features": features,
                "reason": "Model artifacts or dependencies are unavailable",
            }
        if pd is None:
            return {
                "available": False,
                "probability": 0.5,
                "prediction": "unknown",
                "features": features,
                "reason": "pandas is not installed",
            }
        ml_columns = list(self.artifacts.selected_features)
        ml_input = {feature: float(features.get(feature, 0.0)) for feature in ml_columns}
        try:
            frame = pd.DataFrame([ml_input], columns=ml_columns)
            transformed = self.artifacts.preprocessor.transform(frame)
            model_columns = getattr(self.artifacts.model, "feature_names_in_", None)
            if model_columns is not None:
                transformed = pd.DataFrame(transformed, columns=list(model_columns))
            prediction = int(self.artifacts.model.predict(transformed)[0])
            probability = float(self.artifacts.model.predict_proba(transformed)[0][1])
            return {
                "available": True,
                "probability": probability,
                "prediction": "phishing" if prediction == 1 else "legitimate",
                "features": ml_input,
            }
        except Exception as exc:
            return {
                "available": False,
                "probability": 0.5,
                "prediction": "unknown",
                "features": ml_input,
                "reason": str(exc),
            }

    def _compute_shap(self, features: dict[str, float]) -> dict[str, Any]:
        if not self.model_ready or pd is None:
            return {"available": False, "top_features": [], "reason": "Model explanation dependencies unavailable"}
        ml_columns = list(self.artifacts.selected_features)
        frame = pd.DataFrame([[float(features.get(column, 0.0)) for column in ml_columns]], columns=ml_columns)
        try:
            transformed_frame = self.artifacts.preprocessor.transform(frame)
            model_columns = getattr(self.artifacts.model, "feature_names_in_", None)
            if model_columns is not None:
                transformed_frame = pd.DataFrame(transformed_frame, columns=list(model_columns))
            current_probability = float(self.artifacts.model.predict_proba(transformed_frame)[0][1])
            means = getattr(self.artifacts.preprocessor, "mean_", None)
            if means is None or len(means) != len(ml_columns):
                means = [0.0] * len(ml_columns)
            items = []
            for idx, feature_name in enumerate(ml_columns):
                reference_frame = frame.copy()
                reference_value = float(means[idx])
                reference_frame.iloc[0, idx] = reference_value
                transformed_reference = self.artifacts.preprocessor.transform(reference_frame)
                if model_columns is not None:
                    transformed_reference = pd.DataFrame(transformed_reference, columns=list(model_columns))
                reference_probability = float(
                    self.artifacts.model.predict_proba(transformed_reference)[0][1]
                )
                impact = current_probability - reference_probability
                items.append(
                    {
                        "feature": feature_name,
                        "impact": float(impact),
                        "abs_impact": float(abs(impact)),
                        "value": float(frame.iloc[0, idx]),
                        "reference_value": reference_value,
                    }
                )
            items.sort(key=lambda item: item["abs_impact"], reverse=True)
            return {
                "available": True,
                "estimator": "stacking-ensemble",
                "method": "mean-reference local contribution",
                "top_features": items[:8],
            }
        except Exception as exc:
            return {"available": False, "top_features": [], "reason": str(exc)}

    def _chart_to_base64(self, fig: Any) -> str | None:
        if fig is None or plt is None:
            return None
        buffer = io.BytesIO()
        fig.savefig(buffer, format="png", bbox_inches="tight", dpi=110)
        plt.close(fig)
        buffer.seek(0)
        return base64.b64encode(buffer.read()).decode("utf-8")

    def _build_chart_assets(self, scores: dict[str, float], shap_result: dict[str, Any], hybrid_score: float) -> dict[str, Any]:
        return {
            "gauge": self._chart_gauge(hybrid_score),
            "components": self._chart_components(scores),
            "shap": self._chart_shap(shap_result),
        }

    def _chart_gauge(self, score: float) -> str | None:
        if plt is None or np is None:
            return None
        fig, ax = plt.subplots(figsize=(4.2, 2.8))
        ax.set_xlim(-1.2, 1.2)
        ax.set_ylim(-0.2, 1.2)
        ax.set_aspect("equal")
        ax.axis("off")
        colors = ["#1d9a6c", "#d97706", "#dc2626"]
        spans = [(math.pi, math.pi * 0.67), (math.pi * 0.67, math.pi * 0.33), (math.pi * 0.33, 0)]
        for (start, end), color in zip(spans, colors):
            theta = np.linspace(start, end, 80)
            ax.plot(np.cos(theta), np.sin(theta), color=color, lw=10, alpha=0.18)
        theta = np.linspace(math.pi, math.pi - (score / 100) * math.pi, 120)
        ax.plot(np.cos(theta), np.sin(theta), color="#0f766e" if score < 35 else "#d97706" if score < 65 else "#dc2626", lw=12)
        ax.text(0, 0.35, f"{score:.0f}", ha="center", va="center", fontsize=28, fontweight="bold")
        ax.text(0, 0.08, "Risk score", ha="center", va="center", fontsize=10, color="#475569")
        return self._chart_to_base64(fig)

    def _chart_components(self, scores: dict[str, float]) -> str | None:
        if plt is None or not scores:
            return None
        # Filter out non-numeric values (like "Skipped") to avoid matplotlib errors
        numeric_scores = {k: v for k, v in scores.items() if isinstance(v, (int, float))}
        if not numeric_scores:
            return None
        labels = list(numeric_scores.keys())
        values = list(numeric_scores.values())
        fig, ax = plt.subplots(figsize=(7, 3))
        bars = ax.bar(labels, values, color=["#dc2626" if value >= 65 else "#d97706" if value >= 40 else "#1d9a6c" for value in values])
        ax.set_ylim(0, 100)
        ax.set_ylabel("Risk")
        ax.tick_params(axis="x", rotation=25)
        for bar, value in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, value + 2, f"{value:.0f}", ha="center", fontsize=8)
        fig.tight_layout()
        return self._chart_to_base64(fig)

    def _chart_shap(self, shap_result: dict[str, Any]) -> str | None:
        if plt is None or not shap_result.get("available"):
            return None
        items = shap_result.get("top_features", [])
        if not items:
            return None
        fig, ax = plt.subplots(figsize=(7, 3.2))
        features = [item["feature"] for item in items]
        impacts = [item["impact"] for item in items]
        bars = ax.barh(features, impacts, color=["#dc2626" if value > 0 else "#1d9a6c" for value in impacts])
        ax.axvline(0, color="#94a3b8", linewidth=1)
        for bar, value in zip(bars, impacts):
            ax.text(value, bar.get_y() + bar.get_height() / 2, f"{value:+.3f}", va="center", ha="left" if value >= 0 else "right", fontsize=8)
        ax.invert_yaxis()
        fig.tight_layout()
        return self._chart_to_base64(fig)

    def _capture_screenshot(self, url: str) -> dict[str, Any]:
        if sync_playwright is None:
            return {"available": False, "path": None, "error": "playwright not installed"}
        filename = f"screenshot-{datetime.now().strftime('%Y%m%d%H%M%S')}.png"
        output_path = self.screenshot_dir / filename
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--no-zygote",
                    ],
                )
                page = browser.new_page(viewport={"width": 1366, "height": 900})
                page.goto(url, wait_until="domcontentloaded", timeout=self.screenshot_timeout_ms)
                page.screenshot(path=str(output_path), full_page=True)
                browser.close()
            return {"available": True, "path": f"/static/screenshots/{filename}", "error": None}
        except Exception as exc:
            return {"available": False, "path": None, "error": str(exc)}

    def _should_run_ollama(self, ml_result: dict[str, Any], header_analysis: dict[str, Any], nlp: dict[str, Any], crawl: dict[str, Any]) -> bool:
        if not crawl.get("html_ok"):
            return False
        probability = float(ml_result.get("probability", 0))
        return probability >= 0.55 or header_analysis.get("risk_score", 0) >= 40 or nlp.get("risk_score", 0) >= 20

    def _should_run_shap(self, ml_result: dict[str, Any]) -> bool:
        return bool(ml_result.get("available"))

    def generate_pdf_report(self, result: dict[str, Any]) -> str | None:
        if SimpleDocTemplate is None:
            return None
        fd, output_path = tempfile.mkstemp(suffix=".pdf", prefix="phishing-report-")
        os.close(fd)
        try:
            doc = SimpleDocTemplate(output_path, pagesize=A4, leftMargin=0.6 * inch, rightMargin=0.6 * inch)
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle("Title", parent=styles["Heading1"], textColor=rl_colors.HexColor("#0f766e"))
            body_style = styles["BodyText"]
            table_style = TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), rl_colors.HexColor("#1f2937")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), rl_colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, rl_colors.HexColor("#d1d5db")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [rl_colors.white, rl_colors.HexColor("#f8fafc")]),
                ]
            )
            story = [
                Paragraph("Phishing URL Detection Report", title_style),
                Spacer(1, 10),
                Paragraph(result.get("human_summary", "No analyst summary available."), body_style),
                Spacer(1, 10),
            ]
            summary_rows = [
                ["Field", "Value"],
                ["URL", result.get("url", "")],
                ["Verdict", result.get("verdict", "")],
                ["Hybrid Score", str(result.get("hybrid_score", ""))],
                ["Confidence", str(result.get("confidence", ""))],
                ["Generated", result.get("generated_at", "")],
            ]
            table = Table(summary_rows, colWidths=[1.7 * inch, 5.2 * inch])
            table.setStyle(table_style)
            story.append(table)
            if result.get("shap", {}).get("top_features"):
                story.append(Spacer(1, 12))
                story.append(Paragraph("Top SHAP Features", styles["Heading2"]))
                shap_rows = [["Feature", "Impact", "Value"]]
                for item in result["shap"]["top_features"][:5]:
                    shap_rows.append([item["feature"], f"{item['impact']:+.4f}", str(item["value"])])
                shap_table = Table(shap_rows, colWidths=[2.5 * inch, 1.4 * inch, 3.0 * inch])
                shap_table.setStyle(table_style)
                story.append(shap_table)
            doc.build(story)
            return output_path
        except Exception:
            return None

    def _generate_human_summary(
        self,
        verdict: str,
        hybrid: float,
        nlp: dict[str, Any],
        shap_result: dict[str, Any],
        threat_intel: dict[str, Any],
    ) -> str:
        parts = [f"Classification: {verdict} ({hybrid:.1f}/100)."]
        if threat_intel.get("known_malicious"):
            parts.append(f"Threat feeds flagged this target via {', '.join(threat_intel.get('sources', []))}.")
        if nlp.get("brand_impersonation"):
            parts.append(f"Brand impersonation signs reference {nlp['brand_impersonation']['brand']}.")
        if nlp.get("suspicious_phrases"):
            parts.append("Urgency or credential-harvesting language is present in page text.")
        if shap_result.get("top_features"):
            parts.append(
                "Most influential model features: "
                + ", ".join(item["feature"] for item in shap_result["top_features"][:3])
                + "."
            )
        return " ".join(parts)

    def _compute_html_risk(self, crawl: dict[str, Any]) -> float:
        score = 0.0
        if crawl.get("login_form"):
            score += 20
        if crawl.get("iframe"):
            score += 15
        if crawl.get("suspicious_form_handler"):
            score += 15
        ext = crawl.get("ratio_external_links", 0)
        if ext > 0.6:
            score += 20
        elif ext > 0.3:
            score += 10
        if crawl.get("ratio_null_links", 0) > 0.5:
            score += 10
        if not crawl.get("html_ok"):
            score += 6
        return min(score, 100.0)

    def _compute_ssl_risk(self, info: dict[str, Any]) -> float:
        if not info.get("has_ssl"):
            return 85.0
        score = 0.0
        if info.get("is_expired"):
            score += 40
        if info.get("cn_matches") is False:
            score += 25
        if (info.get("days_until_expiry") or 0) < 7:
            score += 20
        if (info.get("certificate_age_days") or 999) < 30:
            score += 15
        return min(score, 100.0)

    def _compute_dns_risk(self, info: dict[str, Any]) -> float:
        score = 0.0
        if not info.get("has_a_record"):
            score += 50
        if not info.get("has_mx_record"):
            score += 10
        if not info.get("has_spf"):
            score += 20
        if not info.get("has_dmarc"):
            score += 20
        return min(score, 100.0)

    def _compute_url_risk(self, signals: dict[str, Any]) -> float:
        score = 0.0
        if not signals.get("uses_https"):
            score += 20
        if signals.get("uses_ip_address"):
            score += 30
        if signals.get("has_at_symbol"):
            score += 20
        if signals.get("has_double_slash"):
            score += 15
        if signals.get("shortening_service"):
            score += 20
        if signals.get("has_prefix_suffix"):
            score += 10
        subdomain_count = signals.get("subdomain_count", 0)
        score += 15 if subdomain_count >= 3 else 5 if subdomain_count == 2 else 0
        if signals.get("domain_entropy", 0) > 3.5:
            score += 10
        url_length = signals.get("url_length", 0)
        score += 10 if url_length > 100 else 5 if url_length > 75 else 0
        return min(score, 100.0)

    def _score_components(
        self,
        ml_result: dict[str, Any],
        crawl: dict[str, Any],
        header_analysis: dict[str, Any],
        nlp: dict[str, Any],
        ssl_info: dict[str, Any],
        dns_info: dict[str, Any],
        reputation: dict[str, Any],
        url_signals: dict[str, Any],
    ) -> dict[str, float]:
        return {
            "ML": round(ml_result["probability"] * 100, 2),
            "HTML": round(self._compute_html_risk(crawl), 2),
            "Headers": round(header_analysis["risk_score"], 2),
            "NLP": round(nlp["risk_score"], 2),
            "SSL": round(self._compute_ssl_risk(ssl_info), 2),
            "DNS": round(self._compute_dns_risk(dns_info), 2),
            "Reputation": round(reputation["risk_score"], 2),
            "URL": round(self._compute_url_risk(url_signals), 2),
        }

    def _combine_risk_signals(
        self,
        component_scores: dict[str, float],
        crawl: dict[str, Any],
        ml_result: dict[str, Any],
        threat_intel: dict[str, Any],
    ) -> float:
        weights = {
            "ML": 0.30,
            "URL": 0.22,
            "NLP": 0.16,
            "HTML": 0.12,
            "Headers": 0.08,
            "Reputation": 0.05,
            "SSL": 0.04,
            "DNS": 0.03,
        }
        active_weights = dict(weights)
        if not crawl.get("html_ok"):
            active_weights["HTML"] = 0.04
            active_weights["NLP"] = 0.02
            active_weights["Headers"] = 0.03
        if not ml_result.get("available"):
            active_weights["ML"] = 0.12
        total_weight = sum(active_weights.values()) or 1.0
        weighted_score = sum(component_scores.get(name, 0.0) * weight for name, weight in active_weights.items()) / total_weight
        if not crawl.get("html_ok"):
            weighted_score = min(weighted_score, 72.0)
        if threat_intel.get("known_malicious"):
            weighted_score = max(weighted_score, 95.0)
        return round(weighted_score, 2)

    def _verdict_for_score(self, score: float) -> str:
        if score >= 65:
            return "High Risk"
        if score >= 40:
            return "Medium Risk"
        return "Low Risk"
