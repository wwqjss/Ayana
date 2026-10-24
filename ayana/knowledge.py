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
# verified: result=恢复已验证 | speculation=纯推测（不进自动上下文）| none=未标注
VALID_VERIFIED = {"result", "speculation", "none"}
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
    verified: str = "none"  # result | speculation | none
    root_cause: str = ""  # 可 unknown；空=未记录
    source_incident: str = ""
    verified_at: str = ""
    revision: int = 1

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
            "verified": self.verified,
            "root_cause": self.root_cause,
            "source_incident": self.source_incident,
            "verified_at": self.verified_at,
            "revision": self.revision,
        }

    def usable_for_context(self) -> bool:
        """active 且非纯推测，才可作为自动调查依据。"""
        return self.status in USABLE_STATUS and self.verified != "speculation"

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


def _parse_inline_list(val: str) -> list[str] | None:
    """解析 [a, b] / [kanata:mysql] 行内列表；不是列表则返回 None。"""
    v = val.strip()
    if not (v.startswith("[") and v.endswith("]")):
        return None
    inner = v[1:-1].strip()
    if not inner:
        return []
    return [_parse_scalar(p) for p in inner.split(",") if p.strip()]


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
            inline = _parse_inline_list(val)
            meta[key] = inline if inline is not None else _parse_scalar(val)
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
    verified = str(meta.get("verified") or "none").lower()
    if verified not in VALID_VERIFIED:
        verified = "none"
    root_cause = str(meta.get("root_cause") or "")
    source_incident = str(meta.get("source_incident") or "")
    verified_at = str(meta.get("verified_at") or "")
    try:
        revision = int(meta.get("revision") or 1)
    except (TypeError, ValueError):
        revision = 1
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
        verified=verified,
        root_cause=root_cause,
        source_incident=source_incident,
        verified_at=verified_at,
        revision=max(1, revision),
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
        # 仅 active 且非纯推测进入当前调查依据
        return [d for d in hits if d.usable_for_context()]

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

    # ---- 写入 / 相似合并（SpeedSupreme P1）----

    def _similarity(self, a: KnowledgeDoc, b: KnowledgeDoc) -> float:
        """词面相似度：type + objects 交集 + tags 重叠 + 标题/首段词。0–1。"""
        if a.type != b.type:
            return 0.0
        objs_a = {o.strip().lower() for o in a.objects if o.strip()}
        objs_b = {o.strip().lower() for o in b.objects if o.strip()}
        tags_a = {t.strip().lower() for t in a.tags if t.strip()}
        tags_b = {t.strip().lower() for t in b.tags if t.strip()}
        if not objs_a or not objs_b or not (objs_a & objs_b):
            return 0.0
        score = 0.35  # 同 type 且 objects 有交集
        if tags_a & tags_b:
            score += 0.25
        words_a = _content_words(a.title + " " + a.body[:200])
        words_b = _content_words(b.title + " " + b.body[:200])
        if words_a and words_b:
            overlap = len(words_a & words_b) / max(1, len(words_a | words_b))
            score += 0.4 * overlap
        return min(1.0, score)

    def find_similar(
        self, *, type: str, objects: list[str], tags: list[str], title: str, body: str = "",
        threshold: float = 0.45,
    ) -> KnowledgeDoc | None:
        """找相似知识；无命中返回 None。阈值见 _similarity。"""
        probe = KnowledgeDoc(
            id="_probe_",
            title=title,
            type=type if type in VALID_TYPE else "issue",
            objects=list(objects),
            tags=list(tags),
            body=body or title,
        )
        best: KnowledgeDoc | None = None
        best_score = threshold
        for d in self._docs:
            if d.status in ("invalid",):
                continue
            s = self._similarity(probe, d)
            if s >= best_score:
                best_score = s
                best = d
        return best

    def upsert(
        self,
        *,
        title: str,
        type: str = "issue",
        objects: list[str] | None = None,
        tags: list[str] | None = None,
        body: str = "",
        verified: str = "result",
        root_cause: str = "",
        source_incident: str = "",
        verified_at: str = "",
        status: str = "active",
        doc_id: str = "",
        change_note: str = "",
        actor: str = "mcp_agent",
    ) -> dict[str, Any]:
        """自动积累：相似则更新 revision，否则新建。

        verified=result 且 status=active 才是「已验证事实」；
        verified=speculation 允许入库但不进自动上下文。
        """
        if not title or not title.strip():
            raise ValueError("title required")
        if verified not in VALID_VERIFIED:
            raise ValueError("bad verified")
        if status not in VALID_STATUS:
            raise ValueError("bad status")
        # 纯推测不得伪装成已验证
        if verified == "speculation" and status == "active":
            status = "draft"
        objects = [str(o).strip() for o in (objects or []) if str(o).strip()]
        tags = [str(t).strip() for t in (tags or []) if str(t).strip()]
        body = (body or "").strip()
        if verified == "result" and not root_cause:
            root_cause = "unknown"

        existing = self.get(doc_id) if doc_id else self.find_similar(
            type=type, objects=objects, tags=tags, title=title, body=body
        )
        if existing:
            new_tags = list(existing.tags)
            for t in tags:
                if t not in new_tags:
                    new_tags.append(t)
            new_objects = list(existing.objects)
            for o in objects:
                if o not in new_objects:
                    new_objects.append(o)
            new_body = body if body else existing.body
            if change_note and body:
                new_body = body.rstrip() + f"\n\n## 变更说明\n- {change_note}\n"
            elif change_note:
                new_body = existing.body.rstrip() + f"\n\n## 变更说明\n- {change_note}\n"
            revision = existing.revision + 1
            doc = KnowledgeDoc(
                id=existing.id,
                title=title.strip() or existing.title,
                status=status,
                type=existing.type,
                objects=new_objects,
                tags=new_tags,
                body=new_body,
                path=existing.path,
                depends_on=list(existing.depends_on),
                verified=verified,
                root_cause=root_cause or existing.root_cause,
                source_incident=source_incident or existing.source_incident,
                verified_at=verified_at or existing.verified_at,
                revision=revision,
            )
            action = "updated"
        else:
            slug = doc_id.strip() if doc_id.strip() else _slugify(type, objects, title)
            doc = KnowledgeDoc(
                id=slug,
                title=title.strip(),
                status=status,
                type=type if type in VALID_TYPE else "issue",
                objects=objects,
                tags=tags,
                body=body or f"## 现象 / 影响\n{title}\n",
                path=str(self.root / f"{slug}.md"),
                verified=verified,
                root_cause=root_cause,
                source_incident=source_incident,
                verified_at=verified_at,
                revision=1,
            )
            action = "created"

        self._write_doc(doc, actor=actor)
        self.reload()
        return {
            "ok": True,
            "action": action,
            "doc_id": doc.id,
            "revision": doc.revision,
            "path": doc.path,
            "status": doc.status,
            "verified": doc.verified,
        }

    def deprecate(self, doc_id: str, *, reason: str = "", actor: str = "mcp_agent") -> dict[str, Any]:
        """错误/过时经验标记 deprecated，不再注入自动上下文。"""
        doc = self.get(doc_id)
        if not doc:
            return {"ok": False, "error": "not_found", "doc_id": doc_id}
        doc.status = "deprecated"
        if reason:
            doc.body = doc.body.rstrip() + f"\n\n## 变更说明\n- deprecated: {reason}\n"
        self._write_doc(doc, actor=actor)
        self.reload()
        return {"ok": True, "action": "deprecated", "doc_id": doc.id, "revision": doc.revision}

    def _write_doc(self, doc: KnowledgeDoc, *, actor: str = "") -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.root / f"{doc.id}.md"
        path.write_text(format_doc(doc), encoding="utf-8")
        doc.path = str(path)


def _content_words(text: str) -> set[str]:
    return {w for w in re.findall(r"[\w一-鿿]+", (text or "").lower()) if len(w) >= 2}


def _slugify(typ: str, objects: list[str], title: str) -> str:
    asset_obj = (objects[0] if objects else "general").replace(":", "-").replace("/", "-")
    words = re.findall(r"[\w一-鿿]+", title.lower())[:4]
    tail = "-".join(words) if words else "note"
    slug = f"{typ}-{asset_obj}-{tail}"
    slug = re.sub(r"[^a-z0-9一-鿿\-]+", "", slug).strip("-") or "knowledge"
    return slug[:80]


def format_doc(doc: KnowledgeDoc) -> str:
    """按 HANDOFF 模板序列化 Markdown + front matter。"""
    def _list(items: list[str]) -> str:
        return "[" + ", ".join(items) + "]" if items else "[]"

    fm = [
        "---",
        f"id: {doc.id}",
        f"title: {doc.title}",
        f"status: {doc.status}",
        f"type: {doc.type}",
        f"objects: {_list(doc.objects)}",
        f"tags: {_list(doc.tags)}",
        f"verified: {doc.verified}",
        f"root_cause: {doc.root_cause or 'unknown'}",
        f"source_incident: {doc.source_incident}",
        f"verified_at: {doc.verified_at}",
        f"revision: {doc.revision}",
        "---",
        "",
    ]
    return "\n".join(fm) + doc.body.strip() + "\n"
