"""Model retraining pipeline: builds a training set from admin-labeled and
high-confidence auto-labeled URLs, augments it adversarially, fine-tunes
both stage models, and hot-swaps them into ModelRegistry on success.
"""

import asyncio
import logging
import os
import traceback
from datetime import datetime
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

from db.database import RetrainQueue, SessionLocal, URLQueue
from services import html_classifier, html_parser, url_transformer
from services.adversarial_augmentor import AdversarialAugmentor
from services.model_registry import VERSION_DIR, model_registry

logger = logging.getLogger(__name__)

LABEL_MAP = {"clean": 0, "phishing": 1}


def _compute_f1(labels, predictions) -> float:
    from sklearn.metrics import f1_score

    return float(f1_score(labels, predictions, average="binary", pos_label=1))


class ModelTrainer:
    URL_EPOCHS = 20
    URL_LR = 2e-5
    URL_BATCH_SIZE = 32

    HTML_EPOCHS = 15
    HTML_LR = 3e-5
    HTML_BATCH_SIZE = 16

    HIGH_CONFIDENCE_THRESHOLD = 0.85
    VAL_SPLIT = 0.2

    async def run_retraining(self, retrain_queue_id: int) -> None:
        self._update_job(retrain_queue_id, status="running", started_at=datetime.utcnow())

        try:
            df = await asyncio.to_thread(self._build_training_dataframe)
            augmented_df = await asyncio.to_thread(
                AdversarialAugmentor().augment_dataset, df
            )
            attack_type_counts = augmented_df.attrs.get("attack_type_counts", {})

            version = self._next_version()

            url_metrics = await asyncio.to_thread(
                self._train_url_model, augmented_df, version
            )
            html_metrics = await asyncio.to_thread(
                self._train_html_model, augmented_df, version
            )

            metadata = {
                "version": version,
                "trained_at": datetime.utcnow().isoformat(),
                "dataset_size": len(df),
                "val_f1_url": url_metrics["val_f1"],
                "val_f1_html": html_metrics["val_f1"],
                "augmented_samples": len(augmented_df) - len(df),
                "attack_type_counts": attack_type_counts,
            }
            self._write_metadata(version, metadata)

            model_registry.deploy(version)

            self._update_job(
                retrain_queue_id, status="complete", completed_at=datetime.utcnow()
            )
        except Exception:
            logger.error(
                "Retraining job %s failed:\n%s",
                retrain_queue_id,
                traceback.format_exc(),
            )
            self._update_job(retrain_queue_id, status="failed")

    # -- job bookkeeping -----------------------------------------------

    def _update_job(self, retrain_queue_id: int, **fields) -> None:
        db = SessionLocal()
        try:
            job = (
                db.query(RetrainQueue)
                .filter(RetrainQueue.id == retrain_queue_id)
                .first()
            )
            if job is None:
                logger.error("Retrain job %s not found", retrain_queue_id)
                return
            for key, value in fields.items():
                setattr(job, key, value)
            db.commit()
        finally:
            db.close()

    # -- dataset construction -------------------------------------------

    def _build_training_dataframe(self) -> pd.DataFrame:
        db = SessionLocal()
        try:
            labeled_rows = (
                db.query(URLQueue).filter(URLQueue.true_label.isnot(None)).all()
            )
            high_confidence_rows = (
                db.query(URLQueue)
                .filter(URLQueue.true_label.is_(None))
                .filter(URLQueue.confidence >= self.HIGH_CONFIDENCE_THRESHOLD)
                .all()
            )
            records = [
                {
                    "url": row.url,
                    "html_features": self._fetch_html(row.url),
                    "label": row.true_label,
                }
                for row in labeled_rows
            ] + [
                {
                    "url": row.url,
                    "html_features": self._fetch_html(row.url),
                    "label": row.label,
                }
                for row in high_confidence_rows
            ]
        finally:
            db.close()

        return pd.DataFrame(records, columns=["url", "html_features", "label"])

    def _fetch_html(self, url: str) -> str:
        try:
            return asyncio.run(html_parser.fetch_html(url))
        except Exception as exc:
            logger.warning("Could not fetch HTML for %s during training: %s", url, exc)
            return ""

    # -- fine-tuning ------------------------------------------------------

    def _train_url_model(self, df: pd.DataFrame, version: int) -> dict:
        from datasets import Dataset
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
            Trainer,
            TrainingArguments,
        )

        working_df = df.dropna(subset=["url", "label"])
        working_df = working_df[working_df["label"].isin(LABEL_MAP)]

        train_df, val_df = train_test_split(
            working_df,
            test_size=self.VAL_SPLIT,
            random_state=42,
            stratify=working_df["label"] if len(working_df) > 1 else None,
        )

        tokenizer = AutoTokenizer.from_pretrained(url_transformer.MODEL_NAME)
        model = AutoModelForSequenceClassification.from_pretrained(
            url_transformer.MODEL_NAME, num_labels=2
        )

        def tokenize(batch):
            return tokenizer(
                batch["url"],
                truncation=True,
                padding="max_length",
                max_length=url_transformer.MAX_LENGTH,
            )

        train_dataset = Dataset.from_pandas(
            train_df.assign(label=train_df["label"].map(LABEL_MAP)),
            preserve_index=False,
        ).map(tokenize, batched=True)
        val_dataset = Dataset.from_pandas(
            val_df.assign(label=val_df["label"].map(LABEL_MAP)),
            preserve_index=False,
        ).map(tokenize, batched=True)

        output_dir = str(Path(VERSION_DIR) / f"v{version}" / "url_model")

        def compute_metrics(eval_pred):
            logits, labels = eval_pred
            predictions = logits.argmax(axis=-1)
            return {"f1": _compute_f1(labels, predictions)}

        training_args = TrainingArguments(
            output_dir=output_dir,
            num_train_epochs=self.URL_EPOCHS,
            learning_rate=self.URL_LR,
            per_device_train_batch_size=self.URL_BATCH_SIZE,
            per_device_eval_batch_size=self.URL_BATCH_SIZE,
            eval_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
            metric_for_best_model="f1",
            report_to=[],
        )

        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=val_dataset,
            compute_metrics=compute_metrics,
        )

        trainer.train()
        eval_result = trainer.evaluate()

        os.makedirs(output_dir, exist_ok=True)
        trainer.save_model(output_dir)
        tokenizer.save_pretrained(output_dir)

        return {"val_f1": eval_result.get("eval_f1", 0.0)}

    def _train_html_model(self, df: pd.DataFrame, version: int) -> dict:
        from datasets import Dataset
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
            Trainer,
            TrainingArguments,
        )

        working_df = df.dropna(subset=["html_features", "label"]).copy()
        working_df = working_df[working_df["label"].isin(LABEL_MAP)]
        working_df["text"] = working_df.apply(
            lambda row: html_classifier._serialize_features(
                html_parser.parse_html(row["url"], row["html_features"] or "")
            ),
            axis=1,
        )

        train_df, val_df = train_test_split(
            working_df,
            test_size=self.VAL_SPLIT,
            random_state=42,
            stratify=working_df["label"] if len(working_df) > 1 else None,
        )

        tokenizer = AutoTokenizer.from_pretrained(html_classifier.MODEL_NAME)
        model = AutoModelForSequenceClassification.from_pretrained(
            html_classifier.MODEL_NAME, num_labels=2
        )

        def tokenize(batch):
            return tokenizer(
                batch["text"],
                truncation=True,
                padding="max_length",
                max_length=html_classifier.MAX_LENGTH,
            )

        train_dataset = Dataset.from_pandas(
            train_df.assign(label=train_df["label"].map(LABEL_MAP)),
            preserve_index=False,
        ).map(tokenize, batched=True)
        val_dataset = Dataset.from_pandas(
            val_df.assign(label=val_df["label"].map(LABEL_MAP)),
            preserve_index=False,
        ).map(tokenize, batched=True)

        output_dir = str(Path(VERSION_DIR) / f"v{version}" / "html_model")

        def compute_metrics(eval_pred):
            logits, labels = eval_pred
            predictions = logits.argmax(axis=-1)
            return {"f1": _compute_f1(labels, predictions)}

        training_args = TrainingArguments(
            output_dir=output_dir,
            num_train_epochs=self.HTML_EPOCHS,
            learning_rate=self.HTML_LR,
            per_device_train_batch_size=self.HTML_BATCH_SIZE,
            per_device_eval_batch_size=self.HTML_BATCH_SIZE,
            eval_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
            metric_for_best_model="f1",
            report_to=[],
        )

        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=val_dataset,
            compute_metrics=compute_metrics,
        )

        trainer.train()
        eval_result = trainer.evaluate()

        os.makedirs(output_dir, exist_ok=True)
        trainer.save_model(output_dir)
        tokenizer.save_pretrained(output_dir)

        return {"val_f1": eval_result.get("eval_f1", 0.0)}

    # -- versioning -------------------------------------------------------

    def _next_version(self) -> int:
        os.makedirs(VERSION_DIR, exist_ok=True)
        existing = [
            int(name[1:])
            for name in os.listdir(VERSION_DIR)
            if name.startswith("v") and name[1:].isdigit()
        ]
        return max(existing, default=0) + 1

    def _write_metadata(self, version: int, metadata: dict) -> None:
        path = Path(VERSION_DIR) / f"v{version}" / "metadata.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        import json

        with open(path, "w") as f:
            json.dump(metadata, f, indent=2)
