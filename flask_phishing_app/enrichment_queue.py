from __future__ import annotations

import logging
import threading
import time
import uuid


log = logging.getLogger("flask-phishing-app")


class EnrichmentQueue:
    def __init__(self, history, analyzer, metrics, poll_interval_seconds: int, max_retries: int, stale_after_seconds: int) -> None:
        self.history = history
        self.analyzer = analyzer
        self.metrics = metrics
        self.poll_interval_seconds = poll_interval_seconds
        self.max_retries = max_retries
        self.stale_after_seconds = stale_after_seconds
        self.worker_id = f"worker-{uuid.uuid4().hex[:12]}"
        self._thread = None
        self._stop = threading.Event()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, name="enrichment-worker", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def enqueue(self, url: str, analysis_id: int) -> int:
        job_id = self.history.enqueue_job(
            "enrich-analysis",
            {"url": url, "analysis_id": analysis_id},
        )
        self.metrics.increment("phishscope_jobs_enqueued_total")
        self.metrics.gauge("phishscope_jobs_pending", float(self.history.count_pending_jobs()))
        return job_id

    def _run(self) -> None:
        while not self._stop.is_set():
            job = self.history.claim_job(
                worker_id=self.worker_id,
                stale_after_seconds=self.stale_after_seconds,
            )
            if not job:
                time.sleep(self.poll_interval_seconds)
                continue

            started = time.perf_counter()
            self.metrics.increment("phishscope_jobs_started_total")
            try:
                self._process_job(job)
                self.history.complete_job(job["id"])
                self.metrics.increment("phishscope_jobs_completed_total")
            except Exception as exc:
                retryable = job["attempts"] < self.max_retries
                self.history.fail_job(job["id"], str(exc), retryable=retryable)
                self.metrics.increment("phishscope_jobs_failed_total")
                log.exception("Enrichment job failed", extra={"job_id": job["id"]})
            finally:
                self.metrics.observe("phishscope_job_duration", time.perf_counter() - started)
                self.metrics.gauge("phishscope_jobs_pending", float(self.history.count_pending_jobs()))

    def _process_job(self, job: dict) -> None:
        payload = job["payload"]
        analysis_id = int(payload["analysis_id"])
        url = str(payload["url"])
        current = self.history.get_analysis(analysis_id)
        if not current:
            raise RuntimeError(f"analysis {analysis_id} not found")
        enriched = self.analyzer.analyze_url(url)
        enriched["analysis_id"] = analysis_id
        enriched["notes"] = self.history.fetch_notes(analysis_id)
        enriched["enrichment"] = {"status": "complete"}
        self.history.update_analysis(analysis_id, enriched)
