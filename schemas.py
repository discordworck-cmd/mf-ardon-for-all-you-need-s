"""
contract/schemas.py — Общая схема запросов и ответов платформы MF Ardon (поставляется клиенту).

Клиент отправляет только числовые признаки под псевдонимами (`id`, `group`).
Названия товаров, артикулы 1С и имена категорий остаются исключительно на стороне клиента.
Все расчёты, калибровка многообразия (X*, Y*), граф зависимостей и оператор Курно
выполняются строго на сервере, а состояние передаётся в непрозрачном AES-256-GCM блоке `state_blob`.
"""

from __future__ import annotations
from typing import List, Optional
import pydantic
from pydantic import BaseModel, Field
_PYDANTIC_V2 = int(pydantic.__version__.split(".")[0]) >= 2
_LIST_BOUNDS = {"min_length": 1, "max_length": 5000} if _PYDANTIC_V2 else {"min_items": 1, "max_items": 5000}


class Item(BaseModel):
    id: str = Field(..., min_length=8, max_length=64, description="Псевдоним позиции (UUID/хэш), создаёт клиент")
    group: str = Field("default", max_length=64, description="Псевдоним категории/группы для поиска субститутов")
    price: float = Field(..., gt=0, description="Текущая цена (может быть масштабирована клиентским множителем)")
    unit_cost: float = Field(..., ge=0, description="Себестоимость единицы")
    velocity: float = Field(..., ge=0, description="Скорость продаж (шт./мес или поток)")
    stock: float = Field(..., ge=0, description="Остаток на складе (шт.)")
    days_idle: float = Field(0.0, ge=0, description="Дней без движения")
    dte: float = Field(180.0, ge=0, description="Дней до истечения срока годности")
    extra_signals: Optional[List[float]] = Field(default=None, description="Дополнительные безразмерные сигналы потока")


class CustomConstraints(BaseModel):
    """Опциональные параметры коридора цен и стоимости капитала для продвинутых разработчиков."""
    min_margin_pct: float = Field(3.0, ge=-50.0, le=95.0)
    max_down_pct: float = Field(-18.0, ge=-80.0, le=0.0)
    max_up_pct: float = Field(15.0, ge=0.0, le=100.0)
    capital_cost_monthly: float = Field(0.02, ge=0.0, le=0.5)


class RecommendRequest(BaseModel):
    goal: str = Field("grow_profit_shrink_sku", description="Целевая функция ядра")
    items: List[Item] = Field(..., **_LIST_BOUNDS)
    state_blob: Optional[str] = Field(default=None, description="Непрозрачный зашифрованный AES-256-GCM блок от прошлого вызова")
    constraints: Optional[CustomConstraints] = Field(default=None, description="Кастомные ограничения коридора цен")


class EdgeOut(BaseModel):
    """Выявленная сервером связь между псевдонимами позиций."""
    target: str
    type: str                  # "SUBSTITUTE" (каннибализация/заменитель) или "COMPLEMENT" (товар-локомотив)
    strength: float
    transfer: float


class Result(BaseModel):
    id: str
    verdict: str
    price_delta_pct: float
    expected_profit_delta: float
    freed_capital: float = 0.0
    projected_velocity: float = 0.0
    turnover_days: float = 0.0
    local_elasticity: float = -0.018
    reason_code: str = ""
    edges: List[EdgeOut] = Field(default_factory=list)


class RecommendResponse(BaseModel):
    request_id: str
    expires_at: int            # unix time (now + 3600s), после которого результат устаревает и требует пересчёта на сервере
    epoch: int = 1             # монотонный номер эпохи калибровки (защита от отката state_blob)
    results: List[Result]
    state_blob: str            # зашифровано сервером (AES-256-GCM), клиент не может прочитать или подделать