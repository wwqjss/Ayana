"""Durable native admission/recovery without replaying prompts or inventing receipts."""
from __future__ import annotations
import json
import time
import uuid

from .duty_session import DutySessionManager


class NativeAdmissionError(RuntimeError):
    def __init__(self, code, message=""):
        self.code=code
        super().__init__(message or code)


def _assistant_finished(info):
    """A finished tool-call step is not proof that the whole turn finished."""
    return bool((info.get("time") or {}).get("completed") and
                (info.get("error") or info.get("finish") in
                 ("stop", "end_turn", "length", "content_filter", "content-filter")))


class NativeTurns:
    def __init__(self, db):
        self.db=db;self.duty=DutySessionManager(db)

    def begin(self,sid,rid,kind,payload,*,controller=None):
        with self.db.tx() as conn:
            if not conn.in_transaction:conn.execute("BEGIN IMMEDIATE")
            session=self.duty.get(sid)
            if not session or session["status"]!="open" or session.get("deleted_at") or session.get("delete_requested_at"):
                raise NativeAdmissionError("session_unavailable")
            if session.get("remote_session_id") != rid:raise NativeAdmissionError("runtime_binding_changed")
            if controller is not None:
                binding=conn.execute("SELECT controller,controller_connection_id,control_expires_at FROM agent_runtime_bindings WHERE session_id=?",(sid,)).fetchone()
                if not binding or (binding["controller"],binding["controller_connection_id"])!=controller or binding["control_expires_at"]<=time.time():
                    raise NativeAdmissionError("control_changed")
            if kind=="prompt" and session.get("paused_at"):raise NativeAdmissionError("session_paused","会话已暂停，请先恢复任务或解除暂停。")
            if conn.execute("SELECT 1 FROM agent_native_submissions WHERE session_id=? AND state IN ('submitting','unknown')",(sid,)).fetchone():
                raise NativeAdmissionError("submission_unconfirmed","上次提交结果待确认，未重复发送。")
            if kind=="recovery" and conn.execute("SELECT 1 FROM agent_native_submissions WHERE session_id=? AND kind='recovery' AND state='recovering'",(sid,)).fetchone():
                raise NativeAdmissionError("recovery_running")
            if conn.execute("SELECT 1 FROM agent_runtime_receipts WHERE session_id=? AND status='unknown'",(sid,)).fetchone():
                raise NativeAdmissionError("native_turn_unknown")
            if kind=="prompt":
                external=conn.execute("SELECT 1 FROM session_write_ops WHERE session_id=? AND status IN ('claimed','unknown')",(sid,)).fetchone()
                external=external or conn.execute("SELECT 1 FROM actions WHERE json_valid(params_json) AND json_extract(params_json,'$._ayana_session_id')=? AND state IN ('dispatched','unknown','verifying')",(sid,)).fetchone()
                owned=self.duty._owned_job_ids(sid)
                if not payload.get("queued") and owned:
                    marks=','.join('?' for _ in owned)
                    external=external or conn.execute("SELECT 1 FROM investigation_jobs WHERE incident_id IN ("+marks+") AND status='running' AND phase IN ('decision','execution','verification','verifying')",tuple(owned)).fetchone()
                if external:
                    raise NativeAdmissionError("external_work_busy","本轮处置或验证仍在执行，请等待结果确认后发送指导；当前消息未发送。")
            submission="sub_"+uuid.uuid4().hex;t=time.time()
            payload["human_revision"]=int(session.get("human_message_revision") or 0)+1
            payload["pause_before"]={"paused_at":session.get("paused_at") or 0,"pause_reason":session.get("pause_reason") or ""}
            conn.execute("INSERT INTO agent_native_submissions(session_id,submission_id,kind,state,created_at,updated_at,remote_session_id,payload_json) VALUES(?,?,?,'submitting',?,?,?,?)",(sid,submission,kind,t,t,rid,json.dumps(payload)))
            conn.execute("UPDATE duty_sessions SET human_message_revision=human_message_revision+1,archive_due_at=0 WHERE id=?",(sid,))
            if kind=="recovery":conn.execute("UPDATE duty_sessions SET paused_at=0,pause_reason='' WHERE id=?",(sid,))
        return submission

    def finish(self,sid,submission,state,*,receipt_id="",payload=None):
        with self.db.tx() as conn:
            sql="UPDATE agent_native_submissions SET state=?,updated_at=?,receipt_id=?";args=[state,time.time(),receipt_id]
            if payload is not None:sql+=",payload_json=?";args.append(json.dumps(payload))
            conn.execute(sql+" WHERE session_id=? AND submission_id=?",(*args,sid,submission))

    def ack(self,sid,*,state,message,receipt_id="",queued=False,error=""):
        self.duty.record_event(sid,type="input_ack",title=message,payload={"state":state,"message":message,"receipt_id":receipt_id,"queued":queued,"error":error})

    async def prompt(self,manager,sid,rid,path,body,*,origin="tui"):
        controller=manager.require_live_controller(sid)
        client=manager.serve_client_factory();client._admit()
        status=await client.session_status(rid)
        queued=status.get("type") in ("busy","retry")
        binding=manager._binding(sid) or {}
        if binding.get("state")=="unknown" or binding.get("receipt_status")=="unknown":raise NativeAdmissionError("native_turn_unknown")
        message_id=body.get("messageID")
        if message_id:
            old=self.db.query_one("SELECT state,receipt_id FROM agent_native_submissions WHERE session_id=? AND kind='prompt' AND json_extract(payload_json,'$.messageID')=? ORDER BY created_at DESC LIMIT 1",(sid,message_id))
            if old:
                if old["state"]=="accepted" and old["receipt_id"]:return 202,{"receiptId":old["receipt_id"]}
                raise NativeAdmissionError("submission_unconfirmed")
        manager.require_live_controller(sid,controller)
        submission=self.begin(sid,rid,"prompt",{"messageID":message_id or "","queued":queued,"engine":manager.engine_signature()},controller=controller)
        try:
            response=await client._request("POST",path,body=body,include_status=True)
            status,payload=response["status"],response["data"]
            receipt=payload.get("receiptId") if isinstance(payload,dict) else None
            if status==204:
                # MiMo's prompt_async contract explicitly says 204 means no
                # user turn was admitted; it is not an ambiguous transport loss.
                raise NativeAdmissionError("turn_not_admitted","原生任务未接收本次消息，请稍后重试。")
            if status!=202 or not isinstance(receipt,str) or not receipt:
                raise NativeAdmissionError("native_turn_unknown")
            from .mimo_serve import native_id
            native_id(receipt)
            self.duty.record_receipt(sid,rid,receipt,origin=origin,status="queued" if queued else "accepted")
            self.duty.set_runtime_state(sid,"running",receipt_id=receipt,receipt_status="queued" if queued else "accepted")
            self.finish(sid,submission,"accepted",receipt_id=receipt)
            self.ack(sid,state="queued" if queued else "running",message="指导消息已进入原生队列，将在当前回合后处理。" if queued else "消息已由原生任务接收。",receipt_id=receipt,queued=queued)
            return status,payload
        except BaseException as error:
            definitive=getattr(error,"code","") in ("turn_not_admitted","native_http_400","native_http_401","native_http_403","native_http_404","native_http_409","native_http_422","http_400","http_401","http_403","http_404","http_409","http_422")
            self.finish(sid,submission,"failed" if definitive else "unknown")
            self.ack(sid,state=self.duty.task_info(sid)["task_state"],message="消息未被接收。" if definitive else "提交结果待确认，未自动重发。",error=getattr(error,"code","submission_unknown"))
            raise

    async def recover(self,manager,sid,payload=None):
        controller=manager.require_live_controller(sid)
        payload=payload or {}
        if not isinstance(payload,dict) or any(k not in ("assistantMessageID","userMessageID","attempt") for k in payload):raise NativeAdmissionError("invalid_recovery")
        session=manager._session(sid);rid=session.get("remote_session_id")
        if not rid:raise NativeAdmissionError("no_remote_session")
        client=manager.serve_client_factory();client._admit()
        await client.require_session_idle(rid)
        blockers=self.duty.native_admission_blockers(sid,include_business=True)
        if blockers:raise NativeAdmissionError(blockers[0])
        data=await client._request("GET","/session/"+rid+"/recovery")
        candidates=data.get("candidates",[]) if isinstance(data,dict) else data if isinstance(data,list) else []
        candidates=[c for c in candidates if isinstance(c,dict) and (
            c.get("kind")=="assistant" and isinstance(c.get("assistantMessageID"),str) and isinstance(c.get("parentMessageID"),str)
            or c.get("kind")=="parent-user" and isinstance(c.get("userMessageID"),str))]
        selected=payload.get("assistantMessageID");parent=payload.get("userMessageID")
        if selected and parent:raise NativeAdmissionError("invalid_recovery")
        candidates=[c for c in candidates if (not selected or c.get("assistantMessageID")==selected) and (not parent or c.get("userMessageID")==parent)]
        if not candidates:raise NativeAdmissionError("no_recovery_candidate","当前会话没有可恢复的原生任务。")
        candidate=max(candidates,key=lambda c:c.get("created") or 0)
        messages=await client.messages(rid,limit=200)
        from .mimo_serve import native_id
        target_key="assistantMessageID" if candidate["kind"]=="assistant" else "userMessageID"
        native_id(candidate[target_key])
        parent_id=candidate.get("parentMessageID") or candidate.get("userMessageID")
        original=next((m for m in messages if (m.get("info") or {}).get("id")==candidate[target_key]),None)
        if not original or (candidate["kind"]=="assistant" and original["info"].get("parentID")!=parent_id) or (candidate["kind"]=="parent-user" and original["info"].get("role")!="user"):
            raise NativeAdmissionError("recovery_candidate_mismatch")
        signature=manager.engine_signature()
        context={"candidate":candidate,"parent_id":parent_id,"before_ids":[m["info"].get("id") for m in messages if isinstance(m.get("info"),dict)],"engine":signature,"started_ms":int(time.time()*1000)}
        manager.require_live_controller(sid,controller)
        submission=self.begin(sid,rid,"recovery",context,controller=controller)
        try:
            # MiMo accepts exactly one recovery target. The parent is evidence
            # for local reconciliation, not a second target in the API body.
            response=await client._request("POST","/session/"+rid+"/resume",body={target_key:candidate[target_key]},expect_json=False,include_status=True)
            status=response["status"]
            if status!=202:raise NativeAdmissionError("recovery_unconfirmed")
            self.finish(sid,submission,"recovering")
            self.duty.set_runtime_state(sid,"running",receipt_status="recovering")
            self.ack(sid,state="running",message="原生恢复已接收，正在核对恢复进度。")
            self.db.audit("web_user",(manager._binding(sid) or {}).get("controller") or "operator","agent_native_recovery_requested",detail={"session_id":sid,"submission_id":submission,"candidate":candidate},channel="web")
            return {"ok":True,"accepted":True,"session_id":sid,"submission_id":submission,"tracking":"native_recovery","message":"恢复请求已接收，将核对原生完成状态。"}
        except BaseException as error:
            definitive=getattr(error,"code","") in ("native_http_400","native_http_401","native_http_403","native_http_404","native_http_409","native_http_422","http_400","http_401","http_403","http_404","http_409","http_422")
            with self.db.tx() as conn:
                self.finish(sid,submission,"failed" if definitive else "unknown")
                prior=context["pause_before"]
                if prior["paused_at"]:
                    conn.execute("UPDATE duty_sessions SET paused_at=?,pause_reason=? WHERE id=? AND human_message_revision=?",(prior["paused_at"],prior["pause_reason"],sid,context["human_revision"]))
            if not definitive:self.duty.set_runtime_state(sid,"unknown",receipt_status="unknown")
            raise

    async def reconcile(self,manager):
        rows=self.db.query("SELECT * FROM agent_native_submissions WHERE state IN ('recovering','unknown') OR (state='submitting' AND updated_at<?) ORDER BY updated_at LIMIT 20",(time.time()-30,))
        for raw in rows:
            row=dict(raw);sid=row["session_id"]
            try:
                context=json.loads(row["payload_json"]);client=manager.serve_client_factory()
                client._admit()
                if manager.engine_signature()!=context.get("engine"):
                    self.finish(sid,row["submission_id"],"unknown");continue
                status=await client.session_status(row["remote_session_id"])
                messages=await client.messages(row["remote_session_id"],limit=200)
                if row["kind"]=="prompt":
                    user_id=context.get("messageID")
                    linked=[m for m in messages if (m.get("info") or {}).get("role")=="assistant" and m["info"].get("parentID")==user_id]
                    if status.get("type")=="idle" and user_id and linked:
                        last=max(linked,key=lambda m:(m["info"].get("time") or {}).get("created",0))
                        if _assistant_finished(last["info"]):
                            outcome="failed" if last["info"].get("error") else "completed"
                            self.finish(sid,row["submission_id"],outcome)
                            remaining=self.db.query_one("SELECT 1 FROM agent_native_submissions WHERE session_id=? AND state IN ('submitting','recovering','unknown')",(sid,))
                            if not remaining and not self.db.query_one("SELECT 1 FROM agent_runtime_receipts WHERE session_id=? AND status IN ('accepted','pending','queued','running','unknown')",(sid,)):
                                self.duty.set_runtime_state(sid,"idle",receipt_status=outcome)
                            self.ack(sid,state=self.duty.task_info(sid)["task_state"],message="已核对原生任务结果，未重发原消息。")
                    continue
                parent_id=context.get("parent_id") or context["candidate"].get("parentMessageID")
                new=[m for m in messages if (m.get("info") or {}).get("role")=="assistant" and m["info"].get("parentID")==parent_id and m["info"].get("id") not in context["before_ids"]]
                if not new:continue
                latest=max(new,key=lambda m:(m["info"].get("time") or {}).get("created",0));info=latest["info"]
                completed=_assistant_finished(info)
                if status.get("type")!="idle":continue
                if completed:
                    outcome="failed" if info.get("error") else "completed"
                else:
                    recovery=await client._request("GET","/session/"+row["remote_session_id"]+"/recovery")
                    options=recovery.get("candidates",[]) if isinstance(recovery,dict) else recovery if isinstance(recovery,list) else []
                    if not any(c.get("assistantMessageID")==info.get("id") for c in options if isinstance(c,dict)):continue
                    outcome="cancelled"
                self.finish(sid,row["submission_id"],outcome)
                pending=self.db.query_one("SELECT 1 FROM agent_runtime_receipts WHERE session_id=? AND status IN ('accepted','pending','queued','running','unknown')",(sid,))
                remaining=self.db.query_one("SELECT 1 FROM agent_native_submissions WHERE session_id=? AND state IN ('submitting','recovering','unknown')",(sid,))
                if not pending and not remaining:
                    self.duty.set_runtime_state(sid,"idle",receipt_status=outcome)
                    self.duty.maybe_start_archive_countdown(sid)
                self.ack(sid,state=self.duty.task_info(sid)["task_state"],message="原生恢复已完成。" if outcome=="completed" else "恢复任务已中断或失败，记录已保留。")
            except Exception:
                # A failed observation never authorizes a replay or erases unknown.
                continue
