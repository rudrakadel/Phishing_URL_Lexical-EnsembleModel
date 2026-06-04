from __future__ import annotations

import argparse
import re
import sys
import warnings
from pathlib import Path
from typing import Iterable


warnings.filterwarnings("ignore", message=".*X does not have valid feature names.*")
warnings.filterwarnings("ignore", message=".*If you are loading a serialized model.*")

ROOT_DIR = Path(__file__).resolve().parents[1]
APP_DIR = ROOT_DIR / "flask_phishing_app"
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

from services.analysis import PhishingAnalyzer
from services.storage import HistoryStore


URL_PATTERN = re.compile(
    r"((?:(?:https?|ftp)://|www\.)?[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}"
    r"(?::\d{2,5})?(?:/[^\s<>\")]*)?)",
    re.IGNORECASE,
)


def normalize_candidate(value: object) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    text = re.sub(r"\bhxxps://", "https://", text, flags=re.IGNORECASE)
    text = re.sub(r"\bhxxp://", "http://", text, flags=re.IGNORECASE)
    match = URL_PATTERN.search(text)
    if not match:
        return None
    url = match.group(1).strip("()[]{}<>,.?!\"'`")
    if url.lower().startswith("www."):
        return f"http://{url}"
    if url.startswith(("http://", "https://", "ftp://")):
        return url
    return f"http://{url}"


def values_from_text(path: Path) -> Iterable[object]:
    yield from path.read_text(encoding="utf-8", errors="ignore").splitlines()


def values_from_table(path: Path, column: str | None) -> Iterable[object]:
    try:
        import pandas as pd
    except Exception as exc:
        raise RuntimeError("pandas is required to read CSV/XLSX files") from exc

    if path.suffix.lower() in {".xlsx", ".xls"}:
        frame = pd.read_excel(path)
    elif path.suffix.lower() == ".tsv":
        frame = pd.read_csv(path, sep="\t")
    else:
        frame = pd.read_csv(path)

    if frame.empty:
        return []

    if column:
        if column not in frame.columns:
            available = ", ".join(str(item) for item in frame.columns)
            raise ValueError(f"Column '{column}' was not found. Available columns: {available}")
        return frame[column].tolist()

    preferred = ["url", "urls", "link", "links", "website", "domain", "target"]
    lower_map = {str(name).strip().lower(): name for name in frame.columns}
    for name in preferred:
        if name in lower_map:
            return frame[lower_map[name]].tolist()

    return frame.astype(str).agg(" ".join, axis=1).tolist()


def load_urls(path: Path, column: str | None) -> list[str]:
    suffix = path.suffix.lower()
    if suffix in {".txt", ".list"}:
        values = values_from_text(path)
    elif suffix in {".csv", ".tsv", ".xlsx", ".xls"}:
        values = values_from_table(path, column)
    else:
        raise ValueError("Input must be .txt, .csv, .tsv, .xlsx, or .xls")

    urls: list[str] = []
    seen: set[str] = set()
    for value in values:
        url = normalize_candidate(value)
        if url and url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze URLs from a file and save them into PhishScope history.")
    parser.add_argument("input", help="Path to a .txt, .csv, .tsv, .xlsx, or .xls file containing URLs")
    parser.add_argument("--column", help="Column name to read from CSV/XLSX files")
    parser.add_argument("--username", default="admin", help="History username to save under, default: admin")
    parser.add_argument("--auth-provider", default="cli", help="History auth provider label, default: cli")
    parser.add_argument("--limit", type=int, default=0, help="Maximum URLs to import, default: all")
    parser.add_argument("--full", action="store_true", help="Run full analysis instead of fast history pre-load")
    parser.add_argument(
        "--database-url",
        default=f"sqlite:///{(APP_DIR / 'data' / 'analysis_history.db').as_posix()}",
        help="Database URL, default: flask_phishing_app/data/analysis_history.db",
    )
    args = parser.parse_args()

    path = Path(args.input).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(path)

    urls = load_urls(path, args.column)
    if args.limit > 0:
        urls = urls[: args.limit]
    if not urls:
        print("No URLs found.")
        return 1

    store = HistoryStore(args.database_url)
    store.init_db()
    analyzer = PhishingAnalyzer(BASE_DIR=APP_DIR, model_dir=ROOT_DIR)

    print(f"Importing {len(urls)} URL(s) into history as '{args.username}'...")
    saved = 0
    failed = 0
    for index, url in enumerate(urls, start=1):
        try:
            result = analyzer.analyze_url(url) if args.full else analyzer.analyze_url_fast(url)
            result["input_url"] = url
            analysis_id = store.save(result, username=args.username, auth_provider=args.auth_provider)
            saved += 1
            print(f"[{index}/{len(urls)}] saved #{analysis_id}: {url} -> {result.get('verdict')}")
        except Exception as exc:
            failed += 1
            print(f"[{index}/{len(urls)}] failed: {url} ({exc})")

    print(f"Done. Saved: {saved}. Failed: {failed}.")
    return 0 if saved else 1


if __name__ == "__main__":
    raise SystemExit(main())
