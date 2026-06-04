import os
import tempfile
import unittest
from pathlib import Path


APP_DIR = Path(__file__).resolve().parents[1] / "flask_phishing_app"
import sys
sys.path.insert(0, str(APP_DIR))

from config import AppConfig
from rate_limit import RateLimiter
from services.storage import HistoryStore


class ConfigTests(unittest.TestCase):
    def test_requires_secret_in_production(self):
        old_env = dict(os.environ)
        try:
            os.environ["APP_ENV"] = "production"
            os.environ.pop("FLASK_SECRET_KEY", None)
            config = AppConfig.from_env(APP_DIR, APP_DIR.parent)
            with self.assertRaises(RuntimeError):
                config.validate()
        finally:
            os.environ.clear()
            os.environ.update(old_env)


class RateLimiterTests(unittest.TestCase):
    def test_fixed_window_limit(self):
        limiter = RateLimiter(window_seconds=60)
        self.assertTrue(limiter.check("bucket", 2).allowed)
        self.assertTrue(limiter.check("bucket", 2).allowed)
        self.assertFalse(limiter.check("bucket", 2).allowed)


class HistoryStoreTests(unittest.TestCase):
    def test_sqlite_store_and_jobs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "history.db"
            store = HistoryStore(f"sqlite:///{db_path}")
            store.init_db()
            user_id = store.create_user("analyst", "Alice", "Smith", "5551234567", "hash-value")
            self.assertGreater(user_id, 0)
            user = store.get_user_by_username("analyst")
            self.assertEqual(user["first_name"], "Alice")
            self.assertEqual(user["mobile"], "5551234567")
            self.assertEqual(store.count_users(), 1)
            analysis_id = store.save(
                {
                    "input_url": "https://example.com",
                    "url": "https://example.com",
                    "verdict": "Low Risk",
                    "hybrid_score": 12.5,
                    "ml": {"probability": 0.1},
                    "cache": {"hit": False},
                }
            )
            self.assertGreater(analysis_id, 0)
            job_id = store.enqueue_job("enrich-analysis", {"analysis_id": analysis_id, "url": "https://example.com"})
            self.assertGreater(job_id, 0)
            claimed = store.claim_job("worker-test", stale_after_seconds=30)
            self.assertIsNotNone(claimed)
            self.assertEqual(claimed["id"], job_id)
            store.complete_job(job_id)
            self.assertEqual(store.count_pending_jobs(), 0)
            feedback_id = store.save_feedback(
                analysis_id=analysis_id,
                normalized_url="https://example.com",
                username="analyst",
                helpful=False,
                corrected_label="Legitimate",
                note="False positive on test domain",
            )
            self.assertGreater(feedback_id, 0)
            summary = store.feedback_summary_for_url("https://example.com")
            self.assertTrue(summary["available"])
            self.assertEqual(summary["not_helpful_count"], 1)


if __name__ == "__main__":
    unittest.main()
