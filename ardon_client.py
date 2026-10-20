"""
client/ardon_client.py — Тонкий клиент MF Ardon (поставляется клиенту).

Принцип безопасности:
1. На клиенте НЕТ весов, формулы Курно, матриц многообразия и правил удаления.
2. SKU, названия товаров и названия категорий 1С остаются ТОЛЬКО на клиенте.
3. На сервер уходят псевдонимы (`id`, `group`) и числа, а также непрозрачный
   зашифрованный `state_blob` (AES-256-GCM), который клиент не может расшифровать или подделать.
4. Опционально поддерживает гомоморфное ослепление масштаба цен (`price_scale_blinding`):
   клиент умножает `price` и `unit_cost` на секретный локальный множитель `alpha`,
   а полученный от сервера `expected_profit_delta` и `freed_capital` делит обратно на `alpha`.
"""

from __future__ import annotations
import hashlib
import hmac
import json
import os
import time
import urllib.request
import uuid
from typing import Any, Callable, Dict, List, Optional


class ArdonClient:
    """SKU и названия остаются только здесь. На сервер уходят псевдонимы (UUID/HMAC) и числа."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        state_path: str = "ardon_state.bin",
        client_secret_salt: str = "",
        price_scale_blinding: float = 1.0,
        transport_fn: Optional[Callable[[str, dict, dict], dict]] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.state_path = state_path
        self.client_secret_salt = client_secret_salt
        self.price_scale_blinding = float(price_scale_blinding) if price_scale_blinding > 0 else 1.0
        self.transport_fn = transport_fn
        self.last_expires_at: int = 0
        self.last_epoch: int = 0

    def _load_state(self) -> str | None:
        if not self.state_path or not os.path.exists(self.state_path):
            return None
        with open(self.state_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            return content if content else None

    def _save_state(self, blob: str) -> None:
        if not self.state_path:
            return
        with open(self.state_path, "w", encoding="utf-8") as f:
            f.write(blob)

    def _make_pseudonym(self, raw_value: str, prefix: str = "") -> str:
        """
        Создаёт псевдоним для SKU или категории.
        Если задан `client_secret_salt`, генерирует стабильный HMAC-псевдоним (чтобы сервер
        мог отслеживать динамическую эластичность по истории цен между батчами, не зная SKU!).
        Если `client_secret_salt` пуст — генерирует случайный `uuid4().hex`.
        """
        if self.client_secret_salt:
            digest = hmac.new(
                self.client_secret_salt.encode("utf-8"),
                f"{prefix}:{raw_value}".encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()[:16]
            return digest
        return uuid.uuid4().hex

    def is_result_expired(self, current_unix_time: Optional[int] = None) -> bool:
        now = current_unix_time if current_unix_time is not None else int(time.time())
        return now >= self.last_expires_at

    def recommend(
        self,
        rows: list[dict],
        goal: str = "grow_profit_shrink_sku",
        constraints: Optional[dict] = None,
    ) -> list[dict]:
        mapping: dict[str, str] = {}
        group_mapping: dict[str, str] = {}
        items = []
        scale = self.price_scale_blinding

        for r in rows:
            sku = str(r["sku"])
            pid = self._make_pseudonym(sku, prefix="SKU")
            mapping[pid] = sku

            raw_cat = str(r.get("category", r.get("group", "default")))
            if raw_cat not in group_mapping:
                group_mapping[raw_cat] = self._make_pseudonym(raw_cat, prefix="GRP")[:12]
            gid = group_mapping[raw_cat]

            items.append({
                "id": pid,
                "group": gid,
                "price": float(r["price"]) * scale,
                "unit_cost": float(r["unit_cost"]) * scale,
                "velocity": float(r["velocity"]),
                "stock": float(r["stock"]),
                "days_idle": float(r.get("days_idle", 0.0)),
                "dte": float(r.get("dte", 180.0)),
            })

        body: Dict[str, Any] = {
            "goal": goal,
            "items": items,
            "state_blob": self._load_state(),
        }
        if constraints:
            body["constraints"] = constraints

        headers = {"Content-Type": "application/json", "X-Api-Key": self.api_key}

        if self.transport_fn is not None:
            data = self.transport_fn(f"{self.base_url}/v1/recommend", body, headers)
        else:
            req = urllib.request.Request(
                f"{self.base_url}/v1/recommend",
                data=json.dumps(body).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))

        self._save_state(data["state_blob"])
        self.last_expires_at = int(data.get("expires_at", 0))
        self.last_epoch = int(data.get("epoch", 1))

        out = []
        for res_row in data["results"]:
            # Деанонимизируем рёбра графа обратно в локальные SKU клиента
            mapped_edges = []
            for edge in res_row.get("edges", []):
                mapped_edges.append({
                    **edge,
                    "target_sku": mapping.get(edge["target"], edge["target"]),
                })
            out.append({
                **res_row,
                "sku": mapping[res_row["id"]],
                "expected_profit_delta": round(float(res_row["expected_profit_delta"]) / scale, 2),
                "freed_capital": round(float(res_row.get("freed_capital", 0.0)) / scale, 2),
                "edges": mapped_edges,
                "expires_at": self.last_expires_at,
                "epoch": self.last_epoch,
            })
        return out