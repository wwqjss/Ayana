"""运维知识库：Markdown 为知识正文事实来源。

一个知识点 / 系统链路 / 典型故障 = knowledge/*.md
YAML front matter 供检索；正文自由 Markdown。
SQLite 仅作可重建索引（本模块以 MD 为准）。
知识只提供调查/建议，不授予执行权，不写入实时状态。
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# status: active 可用于调查 | draft 草稿不进自动上下文 | deprecated 废弃 | historical 仅历史
#         invalid 非法 status，隔离，绝不默认 active
# type: system | issue | procedure
VALID_STATUS = {"active", "draft", "deprecated", "historical", "invalid"}
VALID_TYPE = {"system", "issue", "procedure", "note"}
# 仅 active 进入 Investigation 当前依据
USABLE_STATUS = {"active"}


@dataclass
class KnowledgeDoc:
    id: str
    title: str
    status: str = "active"
    type: str = "system"
    objects: list[str] = field(default_factory=list)  # asset:name 或 name
    tags: list[str] = field(default_factory=list)
    body: str = ""
    path: str = ""
    hash: str = ""
    depends_on: list[str] = field(default_factory=list)

    def to_public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "status": self.status,
            "type": self.type,
            "objects": list(self.objects),
            "tags": list(self.tags),
            "body": self.body,
            "path": self.path,
            "hash": self.hash,
            "depends_on": list(self.depends_on),
        }

    def ref(self) -> dict[str, Any]:
        """Investigation 固定记录用：doc_id + hash + status。"""
        return {"id": self.id, "hash": self.hash, "status": self.status, "title": self.title}

    def asset_ids(self) -> list[str]:
        out = []
        for o in self.objects:
            a = o.split(":", 1)[0] if ":" in o else ""
            if a and a not in out:
                out.append(a)
        return out

    def object_names(self) -> list[str]:
        return [o.split(":", 1)[-1] for o in self.objects]


# ---- front matter ----

def _parse_scalar(raw: str) -> str:
    v = raw.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        return v[1:-1]
    return v


def parse_front_matter(text: str) -> tuple[dict[str, Any], str]:
    """解析 YAML front matter（仅覆盖 id/title/status/type/objects/tags 列表）。"""
    if not text.startswith("---"):
        return {}, text
    lines = text.splitlines()
    if lines[0].strip() != "---":
        return {}, text
    meta: dict[str, Any] = {}
    current_list: str | None = None
    i = 1
    for i in range(1, len(lines)):
        line = lines[i]
        if line.strip() == "---":
            break
        if not line.strip() or line.strip().startswith("#"):
            continue
        # list item under current key
        m_item = re.match(r"^\s+-\s+(.*)$", line)
        if m_item and current_list:
            meta.setdefault(current_list, [])
            if not isinstance(meta[current_list], list):
                meta[current_list] = []
            meta[current_list].append(_parse_scalar(m_item.group(1)))
            continue
        m = re.match(r"^([A-Za-z_][\w-]*)\s*:\s*(.*)$", line)
        if not m:
            current_list = None
            continue
        key, val = m.group(1), m.group(2)
        if val == "":
            meta[key] = []
            current_list = key
        elif val.strip() == "[]":
            meta[key] = []
            current_list = None
        else:
            meta[key] = _parse_scalar(val)
            current_list = None
    body = "\n".join(lines[i + 1 :]) if i + 1 <= len(lines) else ""
    return meta, body.lstrip("\n")


def parse_doc(path: Path, text: str | None = None) -> KnowledgeDoc:
    raw = text if text is not None else path.read_text(encoding="utf-8")
    meta, body = parse_front_matter(raw)
    doc_id = str(meta.get("id") or path.stem)
    title = str(meta.get("title") or doc_id)
    status = str(meta.get("status") or "active").lower()
    # 未知/非法 status 不得默认 active
    if status not in VALID_STATUS:
        status = "invalid"
    typ = str(meta.get("type") or "system").lower()
    if typ not in VALID_TYPE:
        typ = "system"
    objects = meta.get("objects") or []
    if isinstance(objects, str):
        objects = [objects]
    tags = meta.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    depends = meta.get("depends_on") or meta.get("depends") or []
    if isinstance(depends, str):
        depends = [depends]
    return KnowledgeDoc(
        id=doc_id,
        title=title,
        status=status,
        type=typ,
        objects=[str(o) for o in objects],
        tags=[str(t) for t in tags],
        body=body,
        path=str(path),
        hash=hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16],
        depends_on=[str(x) for x in depends],
    )


# ---- 对象引用 ----

def _match_object(doc_objects: list[str], asset_id: str, object_name: str) -> bool:
    """asset:object | asset:* | *:object | object | asset:probe:object"""
    name = object_name.split(":")[-1] if object_name else ""
    refs = {o.strip() for o in doc_objects}
    candidates = set()
    if asset_id and name:
        candidates.add(f"{asset_id}:{name}")
    if name:
        candidates.add(name)
    if asset_id:
        candidates.add(f"{asset_id}:*")
    candidates.add(f"*:{name}" if name else "*")
    for r in refs:
        if not r:
            continue
        if r in candidates:
            return True
        # asset:probe:object → asset:object / object
        parts = r.split(":")
        if len(parts) >= 2:
            a, n = parts[0], parts[-1]
            if a == asset_id and n == name:
                return True
            if n == name and not object_name:
                return True
        if r == "*":
            return True
    return False


class KnowledgeBase:
    """扫描 knowledge/*.md，建立对象/标签索引。"""

    def __init__(self, db: Any = None, root: str | Path | None = None):
        self.db = db  # 保留兼容；正文不入库
        self.root = Path(root) if root else self._default_root()
        self._docs: list[KnowledgeDoc] = []
        self.reload()

    @staticmethod
    def _default_root() -> Path:
        # ayana/knowledge.py → 仓库根/knowledge
        return Path(__file__).resolve().parents[1] / "knowledge"

    def reload(self) -> int:
        self._docs = []
        if not self.root.is_dir():
            return 0
        for p in sorted(self.root.glob("*.md")):
            try:
                self._docs.append(parse_doc(p))
            except Exception:
                continue
        return len(self._docs)

    @property
    def revision(self) -> str:
        """当前知识集 revision（原子 reload 后可复算）。"""
        blob = "|".join(f"{d.id}:{d.hash}:{d.status}" for d in sorted(self._docs, key=lambda x: x.id))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:12]

    # ---- 查询 ----

    def list_docs(self, *, status: str = "", typ: str = "", q: str = "") -> list[KnowledgeDoc]:
        out = []
        ql = (q or "").lower()
        for d in self._docs:
            if status and d.status != status:
                continue
            if typ and d.type != typ:
                continue
            if ql:
                blob = " ".join(
                    [d.id, d.title, d.body, " ".join(d.tags), " ".join(d.objects)]
                ).lower()
                if ql not in blob:
                    continue
            out.append(d)
        return out

    def get(self, doc_id: str) -> KnowledgeDoc | None:
        for d in self._docs:
            if d.id == doc_id:
                return d
        return None

    def docs_for_object(
        self, asset_id: str, object_name: str, *, include_inactive: bool = False
    ) -> list[KnowledgeDoc]:
        hits = [
            d
            for d in self._docs
            if _match_object(d.objects, asset_id, object_name)
        ]
        if include_inactive:
            return hits
        # 仅 active 进入当前调查依据；draft/deprecated/historical/invalid 一律排除
        return [d for d in hits if d.status in USABLE_STATUS]

    def docs_for_objects(
        self, pairs: list[tuple[str, str]], *, include_inactive: bool = False
    ) -> dict[str, Any]:
        """多对象命中同一主题 → 共同知识/共同依赖。"""
        per: dict[str, list[str]] = {}
        for asset_id, obj in pairs:
            for d in self.docs_for_object(asset_id, obj, include_inactive=include_inactive):
                per.setdefault(d.id, [])
                label = f"{asset_id}:{obj.split(':')[-1]}"
                if label not in per[d.id]:
                    per[d.id].append(label)
        shared = [i for i, objs in per.items() if len(objs) >= 2]
        return {
            "per_doc": per,
            "shared_ids": shared,
            "shared_docs": [self.get(i) for i in shared if self.get(i)],
        }

    # ---- Agent / Investigation 上下文 ----

    def investigation_context(
        self,
        asset_id: str,
        object_id: str = "",
        extra_failures: list[str] | None = None,
    ) -> dict[str, Any]:
        """只用 active 知识生成调查上下文；draft/deprecated/historical/invalid 不作为当前依据。"""
        name = object_id.split(":")[-1] if object_id else ""
        pairs: list[tuple[str, str]] = []
        if asset_id and name:
            pairs.append((asset_id, name))
        for n in extra_failures or []:
            nn = n.split(":")[-1]
            if nn and (asset_id, nn) not in pairs:
                pairs.append((asset_id, nn))

        active_docs: list[KnowledgeDoc] = []
        seen = set()
        for a, o in pairs:
            for d in self.docs_for_object(a, o, include_inactive=False):
                if d.id not in seen:
                    seen.add(d.id)
                    active_docs.append(d)

        # 共同命中 / shared dependency
        shared_info = self.docs_for_objects(pairs, include_inactive=False) if len(pairs) >= 2 else {
            "shared_docs": [],
            "per_doc": {},
        }
        shared_docs = shared_info.get("shared_docs") or []

        parts: list[str] = []
        for d in active_docs:
            parts.append(f"### [{d.id}] {d.title} ({d.type}/{d.status})\n{d.body.strip()}")

        common_text = ""
        if shared_docs:
            titles = "、".join(d.title for d in shared_docs)
            common_text = (
                f"多个异常对象共同命中知识：{titles}。"
                "优先按这些知识中的共同依赖/链路调查，不要先假定各探测目标本身同时故障。"
                "共同发生≠已证明共同根因，只能形成 hypothesis。"
            )
            parts.append(f"### 多对象异常解读\n{common_text}")

        # 仅作历史/草稿参考的（不作为当前操作依据）
        inactive = []
        for a, o in pairs:
            for d in self.docs_for_object(a, o, include_inactive=True):
                if d.status not in USABLE_STATUS and d.id not in seen:
                    inactive.append(d)

        # depends_on 邻接提示（不授予执行权）
        dep_hints: list[str] = []
        for d in active_docs:
            for dep in d.depends_on:
                dep_hints.append(f"{d.id} depends_on {dep}")

        return {
            "docs": [d.to_public() for d in active_docs],
            "shared_docs": [d.to_public() for d in shared_docs],
            "historical_docs": [d.to_public() for d in inactive],
            "knowledge_refs": [d.ref() for d in active_docs],
            "revision": self.revision,
            "common": {
                "shared_ids": [d.id for d in shared_docs],
                "shared_failure_meaning": common_text,
                "hint": "优先调查共同依赖" if shared_docs else "",
                "depends_on": dep_hints,
                "note": "共同发生只能形成 hypothesis，不能直接认定共同根因",
            },
            "context_text": "\n\n".join(parts),
            "primary": active_docs[0].to_public() if active_docs else None,
        }

    # ---- 兼容旧调用（object_knowledge 不再是正文源）----

    def find(self, asset_id: str, object_id: str) -> dict[str, Any] | None:
        docs = self.docs_for_object(asset_id, object_id)
        return docs[0].to_public() if docs else None

    def list_all(self) -> list[dict[str, Any]]:
        return [d.to_public() for d in self._docs]

    def list_for_asset(self, asset_id: str) -> list[dict[str, Any]]:
        return [
            d.to_public()
            for d in self._docs
            if asset_id in d.asset_ids() or any(
                o.startswith(asset_id + ":") or o == asset_id for o in d.objects
            )
        ]
