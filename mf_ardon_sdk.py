"""
mf_ardon_sdk.py — Клиентский SDK платформы MF Ardon v4.0 (поставляется клиенту).

ВАЖНОЕ АРХИТЕКТУРНОЕ РАЗДЕЛЕНИЕ (БЕЗОПАСНОСТЬ):
-----------------------------------------------
1. В этом клиентском SDK НЕТ математического ядра, НЕТ весов `(w_x, w_y)`, НЕТ формулы Курно
   и НЕТ серверных правил калибровки — их невозможно украсть или пропатчить в клиентском коде/бинарнике.
2. Что делает клиентский SDK локально:
   - Принимает любые сырые выгрузки из 1С:Предприятие (CSV, CommerceML XML, JSON, словари или
     «слепые» неразмеченные матрицы `np.ndarray`).
   - Псевдонимизирует коммерческую тайну (`SKU -> UUID/HMAC`, `Категория -> GroupHash`).
   - Опционально применяет гомоморфное ослепление масштаба цен (`price_scale_blinding`), чтобы
     сервер не видел даже реального порядка цен в рублях.
   - Вызывает защищённый сервер `/v1/recommend` через `ArdonClient` (`ardon/client/ardon_client.py`),
     передавая и сохраняя непрозрачный зашифрованный `AES-256-GCM` блок состояния `state_blob`.
   - Локально деанонимизирует полученные от сервера `UUID` обратно в реальные артикулы и названия 1С,
     формирует подробные текстовые обоснования для бухгалтерии (XAI) и выводит результат в любом
     удобном формате (`accountant_table`, `1c_xml_patch`, `json`, `csv`, `custom_fields`).
"""

from __future__ import annotations
import sys, pathlib
_HERE = pathlib.Path(__file__).resolve().parent
for _p in (str(_HERE), str(_HERE / "ardon")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import csv
import io
import json
import math
import os
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import numpy as np

from client.ardon_client import ArdonClient
from mf_ardon_server import LocalServerBridge


# =====================================================================
# 1. Цели ядра и виды вердиктов
# =====================================================================

class GoalType(str, Enum):
    GROW_PROFIT_SHRINK_SKU = "grow_profit_shrink_sku"     # Главная цель для 1С: рост прибыли при сокращении числа SKU
    MAX_PROFIT = "max_profit"                             # Максимальная чистая прибыль портфеля
    ACCELERATE_CASHFLOW = "accelerate_cashflow"           # Ускорение оборачиваемости и разморозка оборотного капитала
    LIQUIDATE_DEAD_STOCK = "liquidate_dead_stock"         # Расчистка неликвидов и залежалого склада
    EXPAND_MARKET_SHARE = "expand_market_share"           # Захват доли рынка при сохранении минимального порога маржи
    PROTECT_MARGIN_INFLATION = "protect_margin_inflation" # Защита наценки при скачках закупочных цен поставщиков


class ActionVerdict(str, Enum):
    DELETE_IMMEDIATELY = "DELETE_IMMEDIATELY"
    LIQUIDATE_AND_DELETE = "LIQUIDATE_AND_DELETE"
    RAISE_PRICE = "RAISE_PRICE"
    LOWER_PRICE_BOOST_VOL = "LOWER_PRICE_BOOST_VOL"
    KEEP_TRAFFIC_ANCHOR = "KEEP_TRAFFIC_ANCHOR"
    KEEP_OPTIMAL = "KEEP_OPTIMAL"


VERDICT_LABELS_RU = {
    "DELETE_IMMEDIATELY": "УДАЛИТЬ ИЗ МАТРИЦЫ",
    "LIQUIDATE_AND_DELETE": "РАСПРОДАТЬ И УДАЛИТЬ",
    "RAISE_PRICE": "ПОВЫСИТЬ ЦЕНУ",
    "LOWER_PRICE_BOOST_VOL": "СНИЗИТЬ ЦЕНУ (ОБОРОТ)",
    "KEEP_TRAFFIC_ANCHOR": "СОХРАНИТЬ (ЛОКОМОТИВ)",
    "KEEP_OPTIMAL": "УДЕРЖИВАТЬ ОПТИМУМ",
}


# =====================================================================
# 2. Локальный парсер сырых выгрузок 1С / CSV / XML / JSON / Матриц
# =====================================================================

@dataclass
class LocalEntityMeta:
    """Локальные метаданные позиции (остаются строго на клиенте, на сервер не уходят!)."""
    sku: str
    name: str
    category: str
    price: float
    unit_cost: float
    velocity: float
    stock: float
    days_idle: float
    dte: float

    @property
    def unit_margin_rub(self) -> float:
        return self.price - self.unit_cost

    @property
    def margin_pct(self) -> float:
        return ((self.price - self.unit_cost) / max(1e-4, self.price)) * 100.0

    @property
    def current_monthly_profit(self) -> float:
        return (self.price - self.unit_cost) * self.velocity

    @property
    def frozen_capital_rub(self) -> float:
        return max(0.0, self.stock * self.unit_cost)

    @property
    def turnover_days(self) -> float:
        return min(999.0, self.stock / (self.velocity / 30.0)) if self.velocity > 1e-4 else 999.0


class Universal1CStreamIntake:
    """Локальный парсер клиентских потоков данных (CSV, XML 1С, JSON, слепые матрицы)."""

    SYNONYMS = {
        "id": ("sku", "id", "код", "артикул", "код_номенклатуры", "code", "item_id"),
        "name": ("name", "наименование", "номенклатура", "товар", "название", "title"),
        "category": ("category", "group", "категория", "группа", "вид_номенклатуры", "раздел", "бренд"),
        "price": ("price", "current_price", "цена", "цена_розн", "ценарозн", "розничная_цена", "прайс"),
        "cost": ("unit_cost", "production_cost", "cost", "себестоимость", "закупочная_цена", "закуп"),
        "velocity": ("velocity", "monthly_sales", "sales", "продажи", "продажи_шт", "продажишт", "обороты", "спрос"),
        "stock": ("stock", "остаток", "остаток_на_складе", "остатокнаскладе", "склад", "inventory"),
        "days_idle": ("days_idle", "дней_без_движения", "днейбездвижения", "возраст_запаса", "idle_days"),
        "dte": ("dte", "срок_годности_дней", "срокгодностидней", "дней_до_просрочки"),
    }

    def _match_key(self, raw_keys: List[str], role: str) -> Optional[str]:
        candidates = self.SYNONYMS.get(role, ())
        norm_map = {k.strip().lower().replace(" ", "_"): k for k in raw_keys}
        for cand in candidates:
            if cand in norm_map:
                return norm_map[cand]
        for norm_k, orig_k in norm_map.items():
            for cand in candidates:
                if len(cand) >= 4 and cand in norm_k:
                    return orig_k
        return None

    def _parse_float(self, val: Any, default: float = 0.0) -> float:
        if val is None:
            return default
        if isinstance(val, (int, float, np.number)) and not isinstance(val, bool):
            return float(val)
        s = str(val).strip().replace("\u00a0", "").replace(" ", "").replace(",", ".")
        s = "".join(ch for ch in s if ch in "0123456789.-eE")
        try:
            return float(s) if s else default
        except ValueError:
            return default

    def parse(self, raw_data: Any) -> List[LocalEntityMeta]:
        if isinstance(raw_data, str):
            text = raw_data
            if os.path.exists(raw_data) and os.path.isfile(raw_data):
                with open(raw_data, "r", encoding="utf-8") as f:
                    text = f.read()
            stripped = text.strip()
            if stripped.startswith("<"):
                root = ET.fromstring(stripped)
                rows = []
                for elem in root.iter():
                    tag_clean = elem.tag.split("}")[-1]
                    if tag_clean in {"Товар", "Предложение", "Строка", "Номенклатура", "Item", "Row"} and (len(elem) > 0 or elem.attrib):
                        row = dict(elem.attrib)
                        for child in elem:
                            if child.text and child.text.strip():
                                row[child.tag.split("}")[-1]] = child.text.strip()
                        if row:
                            rows.append(row)
                raw_data = rows
            elif stripped.startswith("{") or stripped.startswith("["):
                raw_data = json.loads(stripped)
            else:
                lines = [ln for ln in stripped.splitlines() if ln.strip()]
                delim = ";" if lines and lines[0].count(";") >= lines[0].count(",") else ","
                raw_data = [dict(r) for r in csv.DictReader(io.StringIO("\n".join(lines)), delimiter=delim)]

        # Слепая матрица чисел без названий колонок
        if isinstance(raw_data, np.ndarray) or (
            isinstance(raw_data, list) and raw_data and isinstance(raw_data[0], (list, tuple, np.ndarray))
        ):
            mat = np.array(raw_data, dtype=float)
            if mat.ndim == 1:
                mat = mat.reshape(1, -1)
            out = []
            for idx in range(mat.shape[0]):
                r = mat[idx]
                p = float(r[0])
                c = float(r[1]) if len(r) > 1 else p * 0.65
                v = float(r[2]) if len(r) > 2 else 10.0
                s = float(r[3]) if len(r) > 3 else v * 2.0
                out.append(LocalEntityMeta(
                    sku=f"VEC-{idx+1:04d}",
                    name=f"Позиция потока #{idx+1}",
                    category="STREAM_GROUP",
                    price=max(0.01, p),
                    unit_cost=max(0.0, c),
                    velocity=max(0.0, v),
                    stock=max(0.0, s),
                    days_idle=0.0 if v > 10.0 else 65.0,
                    dte=90.0,
                ))
            return out

        if isinstance(raw_data, dict):
            items_list = raw_data.get("items", [dict(v, sku=k) for k, v in raw_data.items()])
        elif isinstance(raw_data, list):
            items_list = list(raw_data)
        else:
            raise ValueError(f"Неподдерживаемый формат потока: {type(raw_data)}")

        if not items_list:
            return []

        keys = list(items_list[0].keys())
        k_id = self._match_key(keys, "id")
        k_name = self._match_key(keys, "name")
        k_cat = self._match_key(keys, "category")
        k_price = self._match_key(keys, "price")
        k_cost = self._match_key(keys, "cost")
        k_vel = self._match_key(keys, "velocity")
        k_stock = self._match_key(keys, "stock")
        k_idle = self._match_key(keys, "days_idle")
        k_dte = self._match_key(keys, "dte")

        records: List[LocalEntityMeta] = []
        for idx, row in enumerate(items_list):
            sku = str(row.get(k_id, f"SKU-{idx+1:04d}")).strip() if k_id else f"SKU-{idx+1:04d}"
            name = str(row.get(k_name, sku)).strip() if k_name else sku
            cat = str(row.get(k_cat, "DEFAULT")).strip() if k_cat else "DEFAULT"
            price = self._parse_float(row.get(k_price), 100.0) if k_price else 100.0
            cost = self._parse_float(row.get(k_cost), price * 0.65) if k_cost else price * 0.65
            vel = self._parse_float(row.get(k_vel), 10.0) if k_vel else 10.0
            stock = self._parse_float(row.get(k_stock), vel * 2.0) if k_stock else vel * 2.0
            idle = self._parse_float(row.get(k_idle), 0.0) if k_idle else 0.0
            dte = self._parse_float(row.get(k_dte), 180.0) if k_dte else 180.0
            records.append(LocalEntityMeta(
                sku=sku, name=name, category=cat,
                price=max(0.01, price), unit_cost=max(0.0, cost),
                velocity=max(0.0, vel), stock=max(0.0, stock),
                days_idle=max(0.0, idle), dte=max(1.0, dte),
            ))
        return records


# =====================================================================
# 3. Локальная сборка объяснимости (XAI) после деанонимизации ответа сервера
# =====================================================================

@dataclass
class DependencyEdge:
    source_id: str
    target_id: str
    target_name: str
    relation_type: str
    strength: float
    demand_transfer_ratio: float
    explanation: str


@dataclass
class SKURecommendation:
    sku: str
    name: str
    category: str
    verdict: str
    verdict_label_ru: str
    old_price: float
    new_price: float
    price_delta_pct: float
    unit_cost: float
    old_margin_pct: float
    new_margin_pct: float
    current_velocity: float
    projected_velocity: float
    stock_units: float
    turnover_days: float
    frozen_capital_rub: float
    holding_cost_monthly_rub: float
    current_monthly_profit_rub: float
    projected_monthly_profit_rub: float
    expected_profit_delta_rub: float
    freed_working_capital_rub: float
    local_elasticity: float
    reason_code: str
    dependencies: List[DependencyEdge]
    why_explanation: str
    math_justification: str

    def to_dict(self, selected_fields: Optional[List[str]] = None) -> Dict[str, Any]:
        d = asdict(self)
        if selected_fields:
            return {k: d[k] for k in selected_fields if k in d}
        return d


@dataclass
class OutputConfig:
    format: str = "accountant_table"   # "accountant_table", "json", "1c_xml_patch", "csv", "custom_fields"
    fields: Optional[List[str]] = None
    only_verdicts: Optional[List[str]] = None
    sort_by: str = "expected_profit_delta_rub"
    include_explanations: bool = True
    include_dependency_map: bool = True
    include_security_footer: bool = True


class ArdonOutputFormatter:
    @staticmethod
    def render(result: "ArdonExecutionResult", config: Optional[OutputConfig] = None) -> str:
        cfg = config or OutputConfig()
        recs = list(result.recommendations)

        if cfg.only_verdicts:
            allowed = set(cfg.only_verdicts)
            recs = [r for r in recs if r.verdict in allowed]

        if cfg.sort_by and recs and hasattr(recs[0], cfg.sort_by):
            recs.sort(key=lambda r: getattr(r, cfg.sort_by), reverse=True)

        fmt = cfg.format.lower()
        if fmt == "json":
            return json.dumps({
                "goal": result.goal,
                "command": result.command_executed,
                "portfolio_summary": result.portfolio_summary,
                "security_metadata": result.security_metadata,
                "recommendations": [r.to_dict(cfg.fields) for r in recs],
            }, ensure_ascii=False, indent=2)

        elif fmt == "custom_fields":
            fields = cfg.fields or ["sku", "name", "verdict_label_ru", "old_price", "new_price", "expected_profit_delta_rub", "why_explanation"]
            return json.dumps([r.to_dict(fields) for r in recs], ensure_ascii=False, indent=2)

        elif fmt == "csv":
            buf = io.StringIO()
            fields = cfg.fields or [
                "sku", "name", "category", "verdict", "old_price", "new_price",
                "price_delta_pct", "expected_profit_delta_rub", "freed_working_capital_rub", "why_explanation"
            ]
            writer = csv.DictWriter(buf, fieldnames=fields, delimiter=";")
            writer.writeheader()
            for r in recs:
                writer.writerow(r.to_dict(fields))
            return buf.getvalue()

        elif fmt == "1c_xml_patch":
            root = ET.Element("КоммерческаяИнформация", ВерсияСхемы="2.10", Платформа="MF_Ardon_v4.0_ServerCore", Цель=result.goal)
            doc = ET.SubElement(root, "ДокументПереоценкиИОптимизацииМатрицы")
            ET.SubElement(doc, "ОжидаемыйПриростПрибылиРубМес").text = f"{result.portfolio_summary['total_monthly_profit_gain_rub']:.2f}"
            ET.SubElement(doc, "ВысвобождаемыйОборотныйКапиталРуб").text = f"{result.portfolio_summary['freed_working_capital_rub']:.2f}"
            ET.SubElement(doc, "СокращениеМатрицыШт").text = str(result.portfolio_summary["skus_to_remove_count"])
            items_el = ET.SubElement(doc, "Товары")
            for r in recs:
                it = ET.SubElement(items_el, "СтрокаТабличнойЧасти", Код=r.sku, Наименование=r.name)
                ET.SubElement(it, "Действие1С").text = r.verdict
                ET.SubElement(it, "ДействиеОписание").text = r.verdict_label_ru
                ET.SubElement(it, "СтараяЦена").text = f"{r.old_price:.2f}"
                ET.SubElement(it, "НоваяЦена").text = f"{r.new_price:.2f}"
                ET.SubElement(it, "ИзменениеЦеныПроц").text = f"{r.price_delta_pct:+.2f}"
                ET.SubElement(it, "БлокироватьЗакупку").text = "Да" if "DELETE" in r.verdict else "Нет"
                ET.SubElement(it, "ЭффектПрибылиРубМес").text = f"{r.expected_profit_delta_rub:+.2f}"
                ET.SubElement(it, "ВысвобождениеКапиталаРуб").text = f"{r.freed_working_capital_rub:.2f}"
                if cfg.include_explanations:
                    ET.SubElement(it, "ОбоснованиеДляБухгалтерии").text = r.why_explanation
            return ET.tostring(root, encoding="unicode")

        s = result.portfolio_summary
        lines = [
            "=" * 112,
            f" ОТЧЁТ MF ARDON (SERVER-SIDE CORE v4.0) | ЦЕЛЬ: {result.goal.upper()} | КОМАНДА: {result.command_executed}",
            "=" * 112,
            f" Всего позиций в потоке 1С:    {s['total_skus']} шт.  -->  После оптимизации матрицы: {s['retained_skus_count']} шт. "
            f"(к выводу/делистингу: {s['skus_to_remove_count']} шт., -{s['assortment_reduction_pct']:.1f}%)",
            f" Текущая прибыль портфеля:     {s['current_monthly_profit_rub']:>12,.0f} ₽/мес",
            f" Прогноз прибыли после мер:    {s['projected_monthly_profit_rub']:>12,.0f} ₽/мес "
            f"({s['total_monthly_profit_gain_rub']:+,.0f} ₽/мес | {s['profit_growth_pct']:+.1f}%)",
            f" Разморозка оборотных средств: {s['freed_working_capital_rub']:>12,.0f} ₽ (высвобождение живых денег из неликвидов и дублей)",
            "-" * 112,
            f"{'SKU':<10} | {'Наименование':<26} | {'Вердикт сервера':<24} | {'Старая ₽':>9} | {'Новая ₽':>9} | {'Сдвиг %':>8} | {'ΔПрибыль/мес':>13} | {'Разморозка ₽':>12}",
            "-" * 112,
        ]
        for r in recs:
            short_name = (r.name[:24] + "..") if len(r.name) > 26 else r.name
            lines.append(
                f"{r.sku:<10} | {short_name:<26} | {r.verdict_label_ru:<24} | "
                f"{r.old_price:>9,.1f} | {r.new_price:>9,.1f} | {r.price_delta_pct:>+7.1f}% | "
                f"{r.expected_profit_delta_rub:>+12,.0f} ₽ | {r.freed_working_capital_rub:>11,.0f} ₽"
            )
        lines.append("-" * 112)

        if cfg.include_explanations:
            lines.append("\nПОДРОБНОЕ ОБОСНОВАНИЕ РЕШЕНИЙ (ДЕАНОНИМИЗИРОВАНО ЛОКАЛЬНО НА КЛИЕНТЕ):")
            for r in recs:
                lines.append(f" • [{r.sku}] «{r.name}» -> {r.verdict_label_ru} (Цена: {r.old_price:,.0f} -> {r.new_price:,.0f} ₽, {r.price_delta_pct:+.1f}%):")
                lines.append(f"   Почему: {r.why_explanation}")
                lines.append(f"   Метрики: {r.math_justification}")

        if cfg.include_dependency_map and result.dependency_edges:
            lines.append("\nВЫЯВЛЕННАЯ КАРТА ЗАВИСИМОСТЕЙ И ПЕРЕТОКА СПРОСА МЕЖДУ ТОВАРАМИ:")
            for edge in result.dependency_edges[:10]:
                lines.append(
                    f"   [{edge.source_id}] ===({edge.relation_type}, сила={edge.strength:.2f}, переток={edge.demand_transfer_ratio*100:.0f}%)===> "
                    f"[{edge.target_id} «{edge.target_name}»]: {edge.explanation}"
                )

        if cfg.include_security_footer and result.security_metadata:
            sm = result.security_metadata
            lines.append("\n" + "-" * 112)
            lines.append(
                f" [Server-Side Security] Эпоха: {sm.get('epoch')} | StateBlob: AES-256-GCM (непрозрачен для клиента) | "
                f"Псевдонимизация: UUID/HMAC (масштаб цен x{sm.get('price_scale_blinding')}) | "
                f"Результат действителен до: +{sm.get('ttl_remaining_sec')} сек"
            )
            lines.append("=" * 112)

        return "\n".join(lines)


@dataclass
class ArdonExecutionResult:
    goal: str
    command_executed: str
    recommendations: List[SKURecommendation]
    dependency_edges: List[DependencyEdge]
    portfolio_summary: Dict[str, Any]
    security_metadata: Dict[str, Any]

    def format(self, config: Optional[OutputConfig] = None) -> str:
        return ArdonOutputFormatter.render(self, config)


# =====================================================================
# 4. Главный класс клиентского SDK: ArdonSDK (тонкий клиент над ArdonClient)
# =====================================================================

class ArdonSDK:
    """
    Клиентский SDK для интеграции с 1С и ERP.
    Вся математика выполняется на сервере (`ardon/server/engine.py`), а клиент отвечает за:
    1) Универсальное чтение сырых данных 1С (CSV/XML/JSON/матрицы).
    2) Псевдонимизацию `SKU -> UUID` и гомоморфное ослепление масштаба цен.
    3) Хранение непрозрачного `state_blob` (`AES-256-GCM`).
    4) Локальное форматирование таблиц, объяснений и XML-патчей для 1С.
    """

    AVAILABLE_COMMANDS = {
        "grow_profit_shrink_sku": "Главная функция для 1С: рост чистой прибыли портфеля при сокращении числа товаров (калибровка цен + делистинг + переток спроса)",
        "calibrate_prices": "Полная калибровка цен по всем позициям на основе оптимума Курно и перекрёстной эластичности",
        "analyze_dependencies": "Глубокий анализ связей между товарами (выявление каннибализации, заменителей и товаров-локомотивов)",
        "audit_working_capital": "Бухгалтерский аудит замороженного оборотного капитала, стоимости хранения и неликвидов 1С",
        "liquidate_dead_stock": "Расчёт точечных скидок для быстрой распродажи залежалых остатков и разморозки денег",
        "detect_margin_leaks": "Поиск скрытых утечек маржи (позиции, чья валовая прибыль ниже стоимости удержания запаса)",
        "export_1c_revaluation": "Генерация готового XML/JSON-пакета переоценки и блокировки закупок для загрузки в 1С:Предприятие",
    }

    def __init__(
        self,
        goal: Union[GoalType, str] = GoalType.GROW_PROFIT_SHRINK_SKU,
        base_url: str = "http://127.0.0.1:8000",
        api_key: str = "test-key",
        state_path: Optional[str] = None,
        client_secret_salt: str = "1c-local-salt",
        price_scale_blinding: float = 1.0,
        capital_cost_rate_monthly: float = 0.02,
        constraints: Optional[Dict[str, float]] = None,
        transport_fn: Optional[Callable[[str, dict, dict], dict]] = None,
    ):
        self.goal = GoalType(goal) if isinstance(goal, str) and goal in [g.value for g in GoalType] else (
            goal if isinstance(goal, GoalType) else GoalType.GROW_PROFIT_SHRINK_SKU
        )
        self.capital_cost_rate_monthly = capital_cost_rate_monthly
        self.constraints = constraints or {
            "min_margin_pct": 3.0,
            "max_down_pct": -18.0,
            "max_up_pct": 15.0,
            "capital_cost_monthly": capital_cost_rate_monthly,
        }
        self.intake = Universal1CStreamIntake()

        if state_path is None:
            fd, tmp_path = tempfile.mkstemp(prefix="ardon_state_", suffix=".bin")
            os.close(fd)
            os.unlink(tmp_path)
            state_path = tmp_path

        # Если внешний HTTP-сервер не передан, используем встроенный мост к серверному FastAPI-приложению
        if transport_fn is None and base_url.startswith("http://127.0.0.1:8000"):
            bridge = LocalServerBridge()
            transport_fn = bridge.post_recommend

        self.client = ArdonClient(
            base_url=base_url,
            api_key=api_key,
            state_path=state_path,
            client_secret_salt=client_secret_salt,
            price_scale_blinding=price_scale_blinding,
            transport_fn=transport_fn,
        )

    @classmethod
    def list_available_commands(cls) -> Dict[str, str]:
        return dict(cls.AVAILABLE_COMMANDS)

    def set_constraints(self, min_margin_pct: float = 3.0, max_down_pct: float = -18.0, max_up_pct: float = 15.0, capital_cost_monthly: float = 0.02):
        self.capital_cost_rate_monthly = capital_cost_monthly
        self.constraints = {
            "min_margin_pct": min_margin_pct,
            "max_down_pct": max_down_pct,
            "max_up_pct": max_up_pct,
            "capital_cost_monthly": capital_cost_monthly,
        }
        return self

    def _build_local_explanation(
        self,
        meta: LocalEntityMeta,
        srv_row: dict,
        edges: List[DependencyEdge],
    ) -> Tuple[str, str]:
        verdict = srv_row["verdict"]
        delta = float(srv_row["price_delta_pct"])
        new_price = round(meta.price * (1.0 + delta / 100.0), 2)
        profit_delta = float(srv_row["expected_profit_delta"])
        freed_cap = float(srv_row.get("freed_capital", 0.0))
        proj_vel = float(srv_row.get("projected_velocity", 0.0))
        loc_eps = float(srv_row.get("local_elasticity", -0.018))
        holding = meta.frozen_capital_rub * self.capital_cost_rate_monthly
        rc = srv_row.get("reason_code", "")

        sub_edges = [e for e in edges if e.relation_type == "SUBSTITUTE"]
        comp_edges = [e for e in edges if e.relation_type == "COMPLEMENT"]

        if verdict == "KEEP_TRAFFIC_ANCHOR":
            linked_str = ", ".join(f"{e.target_id} «{e.target_name}»" for e in comp_edges[:2]) or "высокомаржинальных позиций"
            why = (
                f"Товар-локомотив трафика: собственная наценка невысока ({meta.margin_pct:.1f}%), "
                f"но позиция генерирует сопутствующие продажи [{linked_str}] на сумму "
                f"{profit_delta:,.0f} ₽/мес чистой прибыли. Удаление запрещено — это обрушит связанный чек."
            )
            math_just = f"Reason={rc}; SynergyProfit={profit_delta:,.0f} ₽/мес; q_0={meta.velocity:.0f} шт./мес."
        elif verdict in ("LIQUIDATE_AND_DELETE", "DELETE_IMMEDIATELY"):
            sub_str = f" (переток спроса на {sub_edges[0].target_id} «{sub_edges[0].target_name}»)" if sub_edges else ""
            if rc == "CAPITAL_DRAIN_LIQUIDATE" or meta.current_monthly_profit < holding:
                why = (
                    f"Хронический вымыватель капитала: валовая прибыль ({meta.current_monthly_profit:,.0f} ₽/мес) "
                    f"меньше стоимости удержания запаса на складе ({holding:,.0f} ₽/мес при заморозке "
                    f"{meta.frozen_capital_rub:,.0f} ₽ и оборачиваемости {meta.turnover_days:.0f} дн.){sub_str}. "
                    f"Рекомендована ликвидационная скидка {delta:.1f}% для возврата {freed_cap:,.0f} ₽ в оборот с блокировкой закупок в 1С."
                )
            else:
                why = (
                    f"Каннибализация и заморозка оборотных средств ({meta.turnover_days:.0f} дн. оборачиваемости, "
                    f"заморожено {meta.frozen_capital_rub:,.0f} ₽){sub_str}: вывод позиции и перераспределение спроса "
                    f"увеличат чистую прибыль портфеля на {profit_delta:+,.0f} ₽/мес и высвободят {freed_cap:,.0f} ₽."
                )
            math_just = (
                f"Reason={rc}; HoldingCost={holding:,.0f} ₽/мес; "
                f"ΔProfit={profit_delta:+,.0f} ₽/мес; FreedCap={freed_cap:,.0f} ₽."
            )
        elif verdict == "RAISE_PRICE":
            why = (
                f"Спрос на позицию низкоэластичен (ε={loc_eps:.3f}), текущая наценка ({meta.margin_pct:.1f}%) "
                f"ниже точки равновесия Курно при высокой оборачиваемости ({meta.turnover_days:.0f} дн.). "
                f"Повышение цены на {delta:+.1f}% (до {new_price:,.0f} ₽) увеличит маржу с единицы "
                f"до {new_price - meta.unit_cost:,.0f} ₽ при минимальной потере объёма ({meta.velocity:.0f} -> {proj_vel:.1f} шт.), "
                f"давая +{profit_delta:,.0f} ₽/мес дополнительной чистой прибыли."
            )
            math_just = f"Reason={rc}; ε_local={loc_eps:.4f}; Δa={delta:+.2f}%; q_0={meta.velocity:.1f} -> q_1={proj_vel:.1f} шт."
        elif verdict == "LOWER_PRICE_BOOST_VOL":
            why = (
                f"Позиция переоценена относительно чувствительности спроса (ε={loc_eps:.3f}) и "
                f"замедляет оборот склада ({meta.turnover_days:.0f} дн., заморожено {meta.frozen_capital_rub:,.0f} ₽). "
                f"Калибровка цены на {delta:+.1f}% (до {new_price:,.0f} ₽) разгонит продажи "
                f"с {meta.velocity:.0f} до {proj_vel:.1f} шт./мес, высвободит {freed_cap:,.0f} ₽ из запасов "
                f"и принесёт +{profit_delta:,.0f} ₽/мес за счёт роста оборота."
            )
            math_just = f"Reason={rc}; ε_local={loc_eps:.4f}; Δa={delta:+.2f}%; q_0={meta.velocity:.1f} -> q_1={proj_vel:.1f} шт."
        else:
            why = f"Позиция находится в окрестности оптимума Курно (маржа {meta.margin_pct:.1f}%)."
            math_just = f"Reason={rc}; ε_local={loc_eps:.4f}; Δa={delta:+.2f}%."

        return why, math_just

    def execute(
        self,
        raw_stream: Any,
        command: str = "grow_profit_shrink_sku",
        goal: Optional[Union[GoalType, str]] = None,
        output_config: Optional[OutputConfig] = None,
    ) -> ArdonExecutionResult:
        if goal is not None:
            effective_goal = goal.value if isinstance(goal, GoalType) else str(goal)
        elif command == "calibrate_prices":
            effective_goal = "calibrate_prices"
        elif command == "audit_working_capital":
            effective_goal = GoalType.ACCELERATE_CASHFLOW.value
        elif command == "liquidate_dead_stock":
            effective_goal = GoalType.LIQUIDATE_DEAD_STOCK.value
        else:
            effective_goal = self.goal.value

        records = self.intake.parse(raw_stream)
        if not records:
            raise ValueError("Входной поток данных пуст.")

        by_sku = {r.sku: r for r in records}
        rows_for_client = [
            {
                "sku": r.sku,
                "category": r.category,
                "price": r.price,
                "unit_cost": r.unit_cost,
                "velocity": r.velocity,
                "stock": r.stock,
                "days_idle": r.days_idle,
                "dte": r.dte,
            }
            for r in records
        ]

        # Отправляем обезличенный пакет на сервер и получаем решения + зашифрованный state_blob
        srv_results = self.client.recommend(
            rows_for_client,
            goal=effective_goal,
            constraints=self.constraints,
        )

        recommendations: List[SKURecommendation] = []
        all_edges: List[DependencyEdge] = []
        total_curr_profit = 0.0
        total_proj_profit = 0.0
        total_freed_cap = 0.0
        skus_removed = 0

        for srv_row in srv_results:
            sku = srv_row["sku"]
            meta = by_sku[sku]
            verdict = srv_row["verdict"]
            delta = float(srv_row["price_delta_pct"])
            new_price = round(meta.price * (1.0 + delta / 100.0), 2)
            new_margin_pct = ((new_price - meta.unit_cost) / max(1e-4, new_price)) * 100.0
            profit_delta = float(srv_row["expected_profit_delta"])
            freed_cap = float(srv_row.get("freed_capital", 0.0))
            proj_vel = float(srv_row.get("projected_velocity", 0.0))
            loc_eps = float(srv_row.get("local_elasticity", -0.018))
            holding = meta.frozen_capital_rub * self.capital_cost_rate_monthly

            # Деанонимизируем рёбра графа
            sku_edges: List[DependencyEdge] = []
            for e in srv_row.get("edges", []):
                t_sku = e["target_sku"]
                t_meta = by_sku.get(t_sku)
                t_name = t_meta.name if t_meta else t_sku
                if e["type"] == "SUBSTITUTE":
                    expl = (
                        f"Внутрикатегорийный заменитель в группе «{meta.category}»: при выводе или повышении цены на {sku} "
                        f"до {e['transfer']*100:.0f}% спроса переходит на более маржинальный {t_sku} «{t_name}»."
                    )
                else:
                    expl = (
                        f"Синергия чека (товар-локомотив): интенсивный поток продаж {sku} ({meta.velocity:.0f} шт./мес) "
                        f"формирует {e['transfer']*100:.0f}% сопутствующего спроса на высокомаржинальный {t_sku} «{t_name}»."
                    )
                edge_obj = DependencyEdge(
                    source_id=sku,
                    target_id=t_sku,
                    target_name=t_name,
                    relation_type=e["type"],
                    strength=float(e["strength"]),
                    demand_transfer_ratio=float(e["transfer"]),
                    explanation=expl,
                )
                sku_edges.append(edge_obj)
                all_edges.append(edge_obj)

            why_text, math_text = self._build_local_explanation(meta, srv_row, sku_edges)

            curr_p = meta.current_monthly_profit
            total_curr_profit += curr_p
            if verdict in ("DELETE_IMMEDIATELY", "LIQUIDATE_AND_DELETE"):
                skus_removed += 1
                effective_gain = profit_delta
            elif verdict == "KEEP_TRAFFIC_ANCHOR":
                effective_gain = 0.0
            else:
                effective_gain = profit_delta

            total_proj_profit += curr_p + effective_gain
            total_freed_cap += freed_cap

            recommendations.append(SKURecommendation(
                sku=sku,
                name=meta.name,
                category=meta.category,
                verdict=verdict,
                verdict_label_ru=VERDICT_LABELS_RU.get(verdict, verdict),
                old_price=round(meta.price, 2),
                new_price=new_price,
                price_delta_pct=round(delta, 2),
                unit_cost=round(meta.unit_cost, 2),
                old_margin_pct=round(meta.margin_pct, 1),
                new_margin_pct=round(new_margin_pct, 1),
                current_velocity=round(meta.velocity, 1),
                projected_velocity=round(proj_vel, 1),
                stock_units=round(meta.stock, 1),
                turnover_days=round(meta.turnover_days, 1),
                frozen_capital_rub=round(meta.frozen_capital_rub, 0),
                holding_cost_monthly_rub=round(holding, 0),
                current_monthly_profit_rub=round(curr_p, 0),
                projected_monthly_profit_rub=round(curr_p + effective_gain, 0),
                expected_profit_delta_rub=round(effective_gain, 0),
                freed_working_capital_rub=round(freed_cap, 0),
                local_elasticity=round(loc_eps, 4),
                reason_code=srv_row.get("reason_code", ""),
                dependencies=sku_edges,
                why_explanation=why_text,
                math_justification=math_text,
            ))

        all_edges.sort(key=lambda x: x.strength, reverse=True)
        total_gain = total_proj_profit - total_curr_profit
        total_skus = len(records)

        summary = {
            "total_skus": total_skus,
            "retained_skus_count": total_skus - skus_removed,
            "skus_to_remove_count": skus_removed,
            "assortment_reduction_pct": round((skus_removed / max(1, total_skus)) * 100.0, 1),
            "current_monthly_profit_rub": round(total_curr_profit, 0),
            "projected_monthly_profit_rub": round(total_proj_profit, 0),
            "total_monthly_profit_gain_rub": round(total_gain, 0),
            "profit_growth_pct": round((total_gain / max(1.0, abs(total_curr_profit))) * 100.0, 1),
            "freed_working_capital_rub": round(total_freed_cap, 0),
        }

        sec_meta = {
            "epoch": self.client.last_epoch,
            "expires_at": self.client.last_expires_at,
            "ttl_remaining_sec": max(0, self.client.last_expires_at - int(time.time())),
            "price_scale_blinding": self.client.price_scale_blinding,
            "state_path": self.client.state_path,
        }

        return ArdonExecutionResult(
            goal=effective_goal,
            command_executed=command,
            recommendations=recommendations,
            dependency_edges=all_edges,
            portfolio_summary=summary,
            security_metadata=sec_meta,
        )

    def grow_profit_shrink_sku(self, raw_stream: Any, output_config: Optional[OutputConfig] = None) -> ArdonExecutionResult:
        return self.execute(raw_stream, command="grow_profit_shrink_sku", goal=GoalType.GROW_PROFIT_SHRINK_SKU, output_config=output_config)

    def calibrate_prices(self, raw_stream: Any, output_config: Optional[OutputConfig] = None) -> ArdonExecutionResult:
        return self.execute(raw_stream, command="calibrate_prices", goal="calibrate_prices", output_config=output_config)

    def audit_working_capital(self, raw_stream: Any, output_config: Optional[OutputConfig] = None) -> ArdonExecutionResult:
        return self.execute(raw_stream, command="audit_working_capital", goal=GoalType.ACCELERATE_CASHFLOW, output_config=output_config)

    def liquidate_dead_stock(self, raw_stream: Any, output_config: Optional[OutputConfig] = None) -> ArdonExecutionResult:
        return self.execute(raw_stream, command="liquidate_dead_stock", goal=GoalType.LIQUIDATE_DEAD_STOCK, output_config=output_config)


__all__ = [
    "GoalType",
    "ActionVerdict",
    "LocalEntityMeta",
    "Universal1CStreamIntake",
    "DependencyEdge",
    "SKURecommendation",
    "OutputConfig",
    "ArdonOutputFormatter",
    "ArdonExecutionResult",
    "ArdonClient",
    "ArdonSDK",
]