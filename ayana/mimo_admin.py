"""MiMoCode 管理面：状态、连接验证与用户授权的密钥配置。

MiMoCode 与 Ayana 独立运行；本模块只做进程/健康/只读观测与会话入口。
密钥仅保存在服务账号的 MiMoCode 配置文件；公开摘要、错误和审计均不得回显。
"""

from __future__ import annotations

import asyncio
import json
import hashlib
import tempfile
import threading
from urllib.parse import urlsplit, urlunsplit
import os
import re
import shutil
from pathlib import Path
from typing import Any

log = __import__("logging").getLogger("ayana.mimo_admin")


def _jsonc_object(raw: str) -> dict[str, Any]:
    """Parse JSONC without treating URL/string contents as comments."""
    out=[]; i=0; quoted=False; escaped=False
    while i<len(raw):
        ch=raw[i]
        if quoted:
            out.append(ch)
            if escaped: escaped=False
            elif ch=="\\": escaped=True
            elif ch=='"': quoted=False
            i+=1; continue
        if ch=='"': quoted=True; out.append(ch); i+=1; continue
        if raw[i:i+2]=='//':
            while i<len(raw) and raw[i] not in '\r\n': i+=1
            out.append(' '); continue
        if raw[i:i+2]=='/*':
            end=raw.find('*/',i+2)
            if end<0: raise ValueError('invalid_provider_config')
            out.append(' '); i=end+2; continue
        out.append(ch); i+=1
    text=''.join(out); out=[]; quoted=False; escaped=False
    for i,ch in enumerate(text):
        if quoted:
            out.append(ch)
            if escaped: escaped=False
            elif ch=="\\": escaped=True
            elif ch=='"': quoted=False
            continue
        if ch=='"': quoted=True
        if ch==',':
            j=i+1
            while j<len(text) and text[j].isspace(): j+=1
            if j<len(text) and text[j] in '}]': continue
        out.append(ch)
    def unique(pairs):
        data={}
        for k,v in pairs:
            if k in data: raise ValueError('invalid_provider_config')
            data[k]=v
        return data
    try:
        data=json.loads(''.join(out),object_pairs_hook=unique,
                        parse_constant=lambda value: (_ for _ in ()).throw(ValueError('invalid_provider_config')))
    except (ValueError,TypeError):
        raise ValueError('invalid_provider_config') from None
    if not isinstance(data,dict): raise ValueError('invalid_provider_config')
    return data


def _public_url(value: Any) -> str:
    try:
        part=urlsplit(str(value or ''))
        if part.scheme not in ('https','http') or not part.hostname: return ''
        # Do not reflect credentials, query strings or fragments from legacy files.
        host=part.hostname
        if ':' in host: host='['+host+']'
        return urlunsplit((part.scheme,host+(':'+str(part.port) if part.port else ''),part.path,'',''))
    except ValueError: return ''


_CONFIG_LOCK=threading.RLock()


class MimoAdmin:
    def __init__(
        self,
        *,
        mimo_bin: str = "mimo",
        workdir: str = "",
        serve_url: str = "",
        unit_name: str = "",
        config_dir: str = "",
    ):
        self.mimo_bin = mimo_bin or "mimo"
        self.workdir = workdir or ""
        self.serve_url = serve_url or ""
        self.unit_name = unit_name or ""
        self.config_dir = config_dir or ""

    def _bin(self) -> str:
        return shutil.which(self.mimo_bin) or self.mimo_bin

    async def _run(self, args: list[str], timeout: float = 15.0) -> dict[str, Any]:
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.workdir or None,
            )
            out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return {
                "ok": proc.returncode == 0,
                "returncode": proc.returncode,
                "stdout": self._redact((out_b or b"").decode("utf-8", "replace"))[:8000],
                "stderr": self._redact((err_b or b"").decode("utf-8", "replace"))[:2000],
            }
        except FileNotFoundError:
            return {"ok": False, "error": "mimo_not_found", "stdout": "", "stderr": ""}
        except asyncio.TimeoutError:
            if proc is not None and proc.returncode is None:
                try: proc.kill()
                except ProcessLookupError: pass
                await proc.wait()
            return {"ok": False, "error": "timeout", "stdout": "", "stderr": ""}
        except OSError:
            return {"ok": False, "error": "process_error", "stdout": "", "stderr": ""}

    def _redact(self, text: str) -> str:
        try:
            for conf in self._providers(self._read_config()).values():
                key=(conf.get('options') or {}).get('apiKey')
                if isinstance(key,str) and key: text=text.replace(key,'[redacted]')
        except ValueError: pass
        text=re.sub(r'(?i)(Bearer\s+)[^\s"\']+',r'\1[redacted]',text)
        return text

    async def status(self) -> dict[str, Any]:
        """健康与版本：mimo 是否存在、systemd（若配置）、serve URL。"""
        bin_path = self._bin()
        exists = bool(shutil.which(self.mimo_bin)) or Path(bin_path).exists()
        version = ""
        if exists:
            v = await self._run([bin_path, "--version"], timeout=8.0)
            version = (v.get("stdout") or v.get("stderr") or "").strip().splitlines()[:1]
            version = version[0] if version else ""
        unit = {"configured": bool(self.unit_name), "active": None, "detail": ""}
        if self.unit_name:
            u = await self._run(["systemctl", "is-active", self.unit_name], timeout=6.0)
            unit["active"] = (u.get("stdout") or "").strip() == "active"
            unit["detail"] = (u.get("stdout") or u.get("stderr") or "").strip()
        return {
            "ok": exists,
            "binary": bin_path,
            "exists": exists,
            "version": version,
            "workdir": self.workdir,
            "serve_url": self.serve_url,
            "unit": unit,
        }

    async def start(self) -> dict[str, Any]:
        if not self.unit_name:
            return {"ok": False, "error": "unit_not_configured"}
        return await self._run(["systemctl", "start", self.unit_name], timeout=20.0)

    async def stop(self) -> dict[str, Any]:
        if not self.unit_name:
            return {"ok": False, "error": "unit_not_configured"}
        return await self._run(["systemctl", "stop", self.unit_name], timeout=20.0)

    async def restart(self) -> dict[str, Any]:
        if not self.unit_name:
            return {"ok": False, "error": "unit_not_configured"}
        return await self._run(["systemctl", "restart", self.unit_name], timeout=30.0)

    async def logs(self, lines: int = 80) -> dict[str, Any]:
        lines = max(10, min(500, int(lines or 80)))
        if self.unit_name:
            return await self._run(
                ["journalctl", "-u", self.unit_name, "-n", str(lines), "--no-pager"],
                timeout=12.0,
            )
        return await self._run([self._bin(), "debug", "--help"], timeout=8.0)

    async def stats(self) -> dict[str, Any]:
        """用量统计：mimo stats（只读）。不含 API Key。"""
        return await self._run([self._bin(), "stats"], timeout=15.0)

    async def models(self) -> dict[str, Any]:
        return await self._run([self._bin(), "models"], timeout=15.0)

    def config_path(self, config_dir: str = "") -> Path:
        """One explicit managed file, also supplied to the runtime CLI."""
        directory=config_dir or self.config_dir
        if directory:
            base=Path(directory).expanduser()
            names=('mimocode.jsonc','mimocode.json','config.jsonc','config.json')
        else:
            base=Path(os.environ.get('XDG_CONFIG_HOME') or Path.home()/'.config')/'mimocode'
            names=('mimocode.jsonc','mimocode.json')
            if not any((base/n).exists() for n in names):
                legacy=Path.home()/'.mimocode'
                for name in ('mimocode.jsonc','mimocode.json','config.jsonc','config.json'):
                    if (legacy/name).exists(): return legacy/name
        for name in names:
            if (base/name).exists() or (base/name).is_symlink(): return base/name
        return base/'mimocode.jsonc'

    def provider_summary(self, config_dir: str = "") -> dict[str, Any]:
        path=self.config_path(config_dir)
        out={'ok':True,'config_dir':str(path.parent),'path':str(path),'providers':[],'model':''}
        if not path.exists():
            out.update(ok=False,error='config_not_found');return out
        try:
            data=self._read_config(path)
            providers=self._providers(data)
        except ValueError:
            out.update(ok=False,error='invalid_provider_config');return out
        out['model']=str(data.get('model') or '')[:256]
        out['provider_id']=out['model'].partition('/')[0] if '/' in out['model'] else ''
        for name,conf in providers.items():
            opts=conf.get('options') or {}
            models=conf.get('models') or {}
            out['providers'].append({'name':name,'models':list(models) if isinstance(models,dict) else [],
                'baseURL':_public_url(opts.get('baseURL')),'key_set':bool(opts.get('apiKey'))})
        return out


    def _read_config(self, path: Path | None = None) -> dict[str, Any]:
        path=path or self.config_path()
        if path.is_symlink(): raise ValueError('unsafe_config_path')
        if not path.exists(): return {}
        try: return _jsonc_object(path.read_text(encoding='utf-8-sig'))
        except (OSError,UnicodeError): raise ValueError('invalid_provider_config') from None

    @staticmethod
    def _providers(data: dict) -> dict:
        providers=data.get('provider',data.get('providers',{}))
        if not isinstance(providers,dict): raise ValueError('invalid_provider_config')
        for name,conf in providers.items():
            if not isinstance(name,str) or not isinstance(conf,dict): raise ValueError('invalid_provider_config')
            if not isinstance(conf.get('options',{}),dict): raise ValueError('invalid_provider_config')
        return providers

    def _write_config(self, path: Path, data: dict) -> None:
        temporary=None
        try:
            if path.is_symlink(): raise ValueError('unsafe_config_path')
            path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',dir=path.parent,
                    prefix='.mimocode-',suffix='.tmp',delete=False) as stream:
                temporary=Path(stream.name)
                os.chmod(temporary,0o600)
                json.dump(data,stream,ensure_ascii=False,indent=2)
                stream.write('\n');stream.flush();os.fsync(stream.fileno())
            os.replace(temporary,path)
            temporary=None
        except ValueError: raise
        except OSError: raise ValueError('provider_save_failed') from None
        finally:
            if temporary is not None:
                try: temporary.unlink()
                except OSError: pass

    def resolve_provider(self, *, provider_id: str = '', base_url: str = '', api_key: str = '',
                         model: str = '', config_dir: str = '') -> dict[str,str]:
        data=self._read_config(self.config_path(config_dir));providers=self._providers(data)
        selected=str(data.get('model') or '')
        active=selected.partition('/')[0] if '/' in selected else ''
        provider_id=(provider_id or active or (next(iter(providers)) if len(providers)==1 else 'xiaomi')).strip()
        if not re.fullmatch(r'[a-z][a-z0-9_-]{0,32}',provider_id): raise ValueError('bad_provider_id')
        conf=providers.get(provider_id) or {};opts=conf.get('options') or {}
        saved_base=str(opts.get('baseURL') or '').strip().rstrip('/')
        base_url=(base_url or saved_base).strip().rstrip('/')
        provided_key=bool(api_key and api_key.strip())
        if not provided_key and (base_url!=saved_base or (active and provider_id!=active)):
            raise ValueError('key_required_for_endpoint_change')
        key=(api_key if provided_key else opts.get('apiKey') or '')
        if not isinstance(key,str) or not key.strip(): raise ValueError('api_key_required')
        key=key.strip()
        if len(key)>8192 or any(ord(ch)<33 or ord(ch)==127 for ch in key): raise ValueError('bad_api_key')
        from .llm import LLMClient
        try: allowed=LLMClient(key,base_url,'validation',secure_network=True)._endpoint_allowed()
        except ValueError: allowed=False
        if not allowed: raise ValueError('invalid_base_url')
        if not model and active==provider_id: model=selected.partition('/')[2]
        model=(model or '').strip()
        if model.startswith(provider_id+'/'): model=model[len(provider_id)+1:]
        if not model: raise ValueError('model_required')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}',model): raise ValueError('invalid_model')
        return {'provider_id':provider_id,'base_url':base_url,'api_key':key,'model':model}

    def _fingerprint(self, credentials: dict, config_dir: str = '') -> str:
        bound={**credentials,'path':str(self.config_path(config_dir).absolute())}
        return hashlib.sha256(json.dumps(bound,sort_keys=True,separators=(',',':')).encode()).hexdigest()

    def record_verification(self, db: Any, credentials: dict, result: dict) -> dict:
        # Draft tests cannot certify or invalidate a different saved configuration.
        with _CONFIG_LOCK:
            try: current=self.resolve_provider()
            except ValueError: return self.verification_state(db)
            if self._fingerprint(current)!=self._fingerprint(credentials): return self.verification_state(db)
            from .db import now
            state={'verified':bool(result.get('ok')),'fingerprint':self._fingerprint(current),
                'last_test_at':now(),'last_result':str(result.get('result') or 'test_failed'),
                'last_message':str(result.get('message') or '')[:200],
                'provider_id':current['provider_id'],'model':current['model'],'base_url':current['base_url']}
            self.save_verification_state(db,state)
            return self.verification_state(db)

    def runtime_configuration(self, db: Any) -> dict[str,Any]:
        with _CONFIG_LOCK:
            # Bind the exact credentials returned to the child, not a previous
            # read that an external atomic config replacement could invalidate.
            try: credentials=self.resolve_provider()
            except ValueError: raise ValueError('provider_not_verified') from None
            row=db.query_one("SELECT value FROM meta WHERE key='mimo_provider_state'") if db is not None else None
            try: state=json.loads(row['value'] or '{}') if row else {}
            except (ValueError,TypeError): state={}
            if (not isinstance(state,dict) or state.get('verified') is not True
                    or state.get('fingerprint')!=self._fingerprint(credentials)):
                raise ValueError('provider_not_verified')
            provider=credentials['provider_id'];model=credentials['model']
            config={'provider':{provider:{'npm':'@ai-sdk/openai-compatible','name':provider,
                'options':{'apiKey':credentials['api_key'],'baseURL':credentials['base_url']},
                'models':{model:{'name':model}}}},'model':provider+'/'+model}
            return {'mimo_bin':self.mimo_bin,'cwd':self.workdir or None,'model':config['model'],
                'config_path':str(self.config_path().absolute()),'config':config}

    def verification_state(self, db: Any = None) -> dict[str, Any]:
        st={}
        if db is not None:
            row=db.query_one("SELECT value FROM meta WHERE key='mimo_provider_state'")
            if row:
                try: st=json.loads(row['value'] or '{}')
                except (ValueError,TypeError): st={}
        if not isinstance(st,dict): st={}
        matches=False;current={}
        try:
            current=self.resolve_provider()
            matches=bool(st.get('fingerprint')==self._fingerprint(current))
        except ValueError: pass
        verified=st.get('verified') is True and matches
        result=str(st.get('last_result') or '')
        message=str(st.get('last_message') or '')[:200]
        if st.get('verified') and not matches:
            result='configuration_changed';message='当前配置尚未验证，请重新测试连接'
        return {'verified':verified,'last_test_at':st.get('last_test_at') or 0,'last_result':result,
            'last_message':message,'provider_id':current.get('provider_id') or '',
            'model':current.get('model') or '', 'base_url':current.get('base_url') or ''}

    def save_verification_state(self, db: Any, state: dict[str, Any]) -> None:
        if db is None: raise ValueError('provider_state_save_failed')
        try:
            db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('mimo_provider_state',?)",
                       (json.dumps(state,ensure_ascii=False),))
        except Exception: raise ValueError('provider_state_save_failed') from None

    @staticmethod
    def classify_api_response(status: int, body: str, timed_out: bool = False) -> dict[str,Any]:
        if timed_out: return {'ok':False,'result':'timeout','message':'请求超时'}
        text=(body or '')[:65536];low=text.lower()
        if status in (200,201):
            try:
                data=json.loads(text);choices=data.get('choices') if isinstance(data,dict) else None
                first=choices[0] if isinstance(choices,list) and choices else None
                message=first.get('message') if isinstance(first,dict) else None
                content=message.get('content') if isinstance(message,dict) else None
                if not isinstance(content,str) or not content.strip() or data.get('error'):
                    raise ValueError()
            except (ValueError,TypeError,KeyError):
                return {'ok':False,'result':'invalid_response','message':'接口未返回有效的模型回复'}
            return {'ok':True,'result':'success','message':'连接成功，已收到模型回复'}
        if status in (401,403): return {'ok':False,'result':'auth_failed','message':'认证失败：API Key 无效或无权限'}
        if status==402 or (status==429 and any(x in low for x in ('quota','exhaust','insufficient','余额','额度'))):
            return {'ok':False,'result':'quota_exhausted','message':'额度不足或已用尽'}
        if status==429: return {'ok':False,'result':'rate_limited','message':'触发限流，请稍后再试'}
        if status==404: return {'ok':False,'result':'model_or_endpoint_not_found','message':'模型或接口不存在，请检查模型 ID 和 Base URL'}
        if 300<=status<400: return {'ok':False,'result':'redirect_rejected','message':'接口重定向已拒绝，请使用模型服务的直接地址'}
        if status>=500: return {'ok':False,'result':'server_error','message':f'服务端错误 HTTP {status}'}
        return {'ok':False,'result':'http_error','message':f'接口错误 HTTP {status}'}

    def test_connection(self, *, base_url: str, api_key: str, model: str, timeout: float = 30.0) -> dict[str,Any]:
        """One bounded real request, executed off the Web event loop by callers."""
        return asyncio.run(self._test_connection_async(base_url=base_url,api_key=api_key,model=model,timeout=timeout))

    async def _test_connection_async(self, *, base_url: str, api_key: str, model: str, timeout: float) -> dict[str,Any]:
        import aiohttp
        from .llm import LLMClient
        base=(base_url or '').strip().rstrip('/');key=(api_key or '').strip();model=(model or '').strip()
        if not base or not key or not model:
            return {'ok':False,'result':'bad_request','message':'Base URL、API Key 和模型 ID 均必填'}
        if len(key)>8192 or any(ord(ch)<33 or ord(ch)==127 for ch in key):
            return {'ok':False,'result':'bad_request','message':'API Key 格式不正确'}
        client=LLMClient(key,base,model,timeout=min(60,max(1,float(timeout))),secure_network=True)
        try: allowed=client._endpoint_allowed()
        except ValueError: allowed=False
        if not allowed:
            return {'ok':False,'result':'bad_request','message':'请使用公开 HTTPS 模型接口，不接受带凭据或查询参数的地址'}
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=client.timeout),connector=client._connector()) as session:
                async with session.post(base+'/chat/completions',json={'model':model,
                        'messages':[{'role':'user','content':'Reply with exactly: PONG'}],
                        'max_tokens':32,'temperature':0},headers={'Authorization':'Bearer '+key},allow_redirects=False) as response:
                    try:
                        raw=await response.content.readexactly(65537)
                    except asyncio.IncompleteReadError as error:
                        raw=error.partial
                    if len(raw)>65536: return {'ok':False,'result':'invalid_response','message':'接口返回内容过大'}
                    result=self.classify_api_response(response.status,raw.decode('utf-8','replace'))
                    return {**result,'http_status':response.status}
        except asyncio.TimeoutError:
            return {'ok':False,'result':'timeout','message':'请求超时'}
        except (aiohttp.ClientError,OSError):
            return {'ok':False,'result':'connection_error','message':'网络或 TLS 连接失败，请检查服务地址'}
        except Exception:
            # Header validation and provider exceptions can contain the submitted key.
            return {'ok':False,'result':'connection_error','message':'连接测试失败，请检查模型服务配置'}

    def apply_provider(self, *, provider_id: str = '', api_key: str = '', base_url: str = '',
                       model: str = '', config_dir: str = '', verified: bool = False) -> dict[str,Any]:
        with _CONFIG_LOCK:
            credentials=self.resolve_provider(provider_id=provider_id,api_key=api_key,base_url=base_url,
                                              model=model,config_dir=config_dir)
            path=self.config_path(config_dir);data=self._read_config(path)
            providers=self._providers(data).copy();provider=credentials['provider_id'];model=credentials['model']
            conf=dict(providers.get(provider) or {})
            conf.setdefault('name',provider);conf.setdefault('npm','@ai-sdk/openai-compatible')
            conf['options']={**(conf.get('options') or {}),'apiKey':credentials['api_key'],'baseURL':credentials['base_url']}
            models=conf.get('models') or {}
            if not isinstance(models,dict): raise ValueError('invalid_provider_config')
            conf['models']={**models,model:{**(models.get(model) if isinstance(models.get(model),dict) else {}),'name':model}}
            providers[provider]=conf;data['provider']=providers;data['model']=provider+'/'+model
            self._write_config(path,data)
            return {'ok':True,'path':str(path),'provider':provider,'model':model,
                    'verified':bool(verified),'key_len':len(credentials['api_key'])}

    def clear_provider(self, provider_id: str = '', config_dir: str = '') -> dict[str,Any]:
        with _CONFIG_LOCK:
            path=self.config_path(config_dir)
            if not path.exists(): return {'ok':True,'cleared':False}
            data=self._read_config(path);providers=self._providers(data).copy()
            if not provider_id:
                selected=str(data.get('model') or '')
                provider_id=selected.partition('/')[0] if '/' in selected else (next(iter(providers)) if len(providers)==1 else '')
            if not re.fullmatch(r'[a-z][a-z0-9_-]{0,32}',provider_id or ''): raise ValueError('bad_provider_id')
            conf=dict(providers.get(provider_id) or {});opts=dict(conf.get('options') or {})
            if 'apiKey' not in opts: return {'ok':True,'cleared':False,'path':str(path)}
            opts.pop('apiKey');conf['options']=opts;providers[provider_id]=conf;data['provider']=providers
            self._write_config(path,data)
            return {'ok':True,'cleared':True,'path':str(path)}
