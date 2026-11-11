"""발자국 리그 | streamlit run app.py
Python 3.11+ 권장. requirements.txt와 함께 GitHub에 업로드합니다.

Streamlit Community Cloud: repository → app.py → Deploy.
실제 다중 사용자 운영은 영구 PostgreSQL과 HTTPS를 사용하세요.
Settings → Secrets 예시 (실제 비밀값은 GitHub에 올리지 마세요):
    DATABASE_URL = "postgresql+psycopg://USER:PASSWORD@HOST:5432/DB?sslmode=require"
    INGEST_HMAC_KEY = "신뢰된 검증 서버만 보유하는 충분히 긴 임의 비밀키"
키는 모바일 앱에 넣지 마세요. 별도 네이티브 앱/검증 서버는 이 파일에 포함되지 않습니다.
키가 없으면 실전 기록 업로드를 잠그며, 데모는 실전 순위에 절대 합산하지 않습니다.
SQLite 기본값은 로컬 체험용: Cloud 재배포/휴면/복제 시 데이터가 사라질 수 있습니다.

서명된 JSON 계약 (하단 '배포 · 모바일 연동' 화면에도 표시):
payload = {schema_version:1, session_id:UUID, user_id:앱의 사용자ID,
           issued_at:UTC ISO8601, segments:[{start:UTC ISO8601,end:UTC ISO8601,
           distance_m:float,duration_s:float,accuracy_m:float,steps:int,
           activity:'walking'|'running'|'vehicle'|'cycling'|'unknown',
           activity_confidence:float,accel_walk_confidence:float,
           location_jump:bool}]}
envelope = {payload:payload, signature:hex HMAC-SHA256}
canonical bytes = json.dumps(payload,sort_keys=True,separators=(',',':'),
                            ensure_ascii=False,allow_nan=False).encode('utf-8')
서버는 계정 바인딩, 시각, 중복, 겹침, 구간 길이, 다중 신호를 다시 검사합니다.
서명은 원본 센서의 진실성을 보장하지 않습니다. 배포 전에 외부 검증 서버에서
기기 무결성 검증/재전송 방지/원시 신호 검증을 구축해야 합니다. 임계값은 보수적인
초기 규칙일 뿐 의학적·과학적 검증된 부정행위 탐지 모델이 아닙니다.
"""
from __future__ import annotations
import hashlib
import hmac
import html
import json
import math
import os
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from sqlalchemy import (create_engine, MetaData, Table, Column, String, Text,
                        Integer, Float, UniqueConstraint, select, update, insert)
from sqlalchemy.exc import IntegrityError

UTC = timezone.utc

def now():
    return datetime.now(UTC)

def iso(dt):
    return dt.astimezone(UTC).isoformat()

def parse_dt(value):
    d = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    if d.tzinfo is None:
        raise ValueError('시간에는 시간대 정보가 필요합니다.')
    return d.astimezone(UTC)

def config(key, default=''):
    try:
        return str(st.secrets.get(key, os.environ.get(key, default)))
    except FileNotFoundError:
        return os.environ.get(key, default)
    except Exception:
        return os.environ.get(key, default)

META = MetaData()
users = Table('users', META,
    Column('id', String(40), primary_key=True),
    Column('login', String(100), unique=True, nullable=False),
    Column('name', String(40), nullable=False),
    Column('password', Text, nullable=False),
    Column('family_id', String(40)), Column('goal', Float, nullable=False),
    Column('created', String(40), nullable=False))
families = Table('families', META,
    Column('id', String(40), primary_key=True), Column('name', String(80)),
    Column('owner', String(40)), Column('tz', String(80)),
    Column('created', String(40)))
invites = Table('invites', META,
    Column('digest', String(64), primary_key=True), Column('family_id', String(40)),
    Column('expires', String(40)), Column('used_by', String(40)))
workouts = Table('workouts', META,
    Column('id', String(40), primary_key=True), Column('user_id', String(40)),
    Column('family_id', String(40)), Column('mode', String(15)),
    Column('fingerprint', String(64), unique=True), Column('created', String(40)))
segments = Table('segments', META,
    Column('id', String(40), primary_key=True), Column('workout_id', String(40)),
    Column('user_id', String(40)), Column('start', String(40)), Column('end', String(40)),
    Column('distance_m', Float), Column('status', String(15)), Column('reason', Text))
appeals = Table('appeals', META,
    Column('id', String(40), primary_key=True), Column('user_id', String(40)),
    Column('segment_id', String(40)), Column('message', Text),
    Column('state', String(30)), Column('reply', Text), Column('created', String(40)),
    UniqueConstraint('user_id', 'segment_id', name='one_appeal_per_segment'))

@st.cache_resource
def db():
    url = config('DATABASE_URL', 'sqlite:///footprint_league.db')
    if url.startswith('postgres://'):
        url = url.replace('postgres://', 'postgresql+psycopg://', 1)
    elif url.startswith('postgresql://'):
        url = url.replace('postgresql://', 'postgresql+psycopg://', 1)
    kwargs = {'pool_pre_ping': True}
    if url.startswith('sqlite'):
        kwargs['connect_args'] = {'check_same_thread': False, 'timeout': 30}
    engine = create_engine(url, **kwargs)
    META.create_all(engine)
    return engine

def rows(query):
    with db().connect() as c:
        return [dict(r) for r in c.execute(query).mappings()]

def user_by_id(uid):
    result = rows(select(users).where(users.c.id == uid))
    return result[0] if result else None

def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 600000).hex()
    return salt + ':' + digest

def password_ok(password, stored):
    return hmac.compare_digest(password_hash(password, stored.split(':')[0]), stored)

def family_for(u):
    result = rows(select(families).where(families.c.id == u['family_id'])) if u['family_id'] else []
    return result[0] if result else None

def week_window(tzname):
    local = now().astimezone(ZoneInfo(tzname))
    monday = (local - timedelta(days=local.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    return monday.astimezone(UTC), (monday + timedelta(days=7)).astimezone(UTC)

def canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()

def finite_num(value, field, low=0, high=1e8):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f'{field}: 숫자가 필요합니다.')
    value = float(value)
    if not math.isfinite(value) or not low <= value <= high:
        raise ValueError(f'{field}: 허용 범위 밖입니다.')
    return value

def classify(s):
    """비정상 점프/차량 제외 → 신호 결손 보류 → 다중 신호 일치 시 인정."""
    a, b = parse_dt(s['start']), parse_dt(s['end'])
    duration = (b-a).total_seconds()
    if not 5 <= duration <= 120:
        raise ValueError('구간 길이는 5~120초여야 합니다.')
    if b > now() + timedelta(seconds=30) or a < now() - timedelta(days=30):
        raise ValueError('기록은 최근 30일 이내이며 미래 시간이 아니어야 합니다.')
    distance = finite_num(s.get('distance_m'), '거리', high=5000)
    declared = finite_num(s.get('duration_s'), '시간', high=120)
    if abs(duration - declared) > 1:
        raise ValueError('타임스탬프와 duration_s가 일치하지 않습니다.')
    if not isinstance(s.get('location_jump'), bool):
        return a, b, distance, 'held', '위치 점프 검사 결과가 없음'
    if s['location_jump'] or distance / duration > 12:
        return a, b, distance, 'excluded', '위치 점프 또는 극단적 이동: 연결 거리 제외'
    activity = s.get('activity', 'unknown')
    conf = s.get('activity_confidence')
    if conf is not None:
        conf = finite_num(conf, '활동 신뢰도', high=1)
    if activity in ('vehicle', 'cycling') and conf is not None and conf >= .8:
        return a, b, distance, 'excluded', '차량/자전거 활동 인식 신호'
    required = ('accuracy_m', 'steps', 'accel_walk_confidence', 'activity_confidence')
    if any(s.get(k) is None for k in required):
        return a, b, distance, 'held', '위치·걸음·활동·가속도 신호 부족'
    accuracy = finite_num(s['accuracy_m'], '위치 정확도', high=100000)
    accel = finite_num(s['accel_walk_confidence'], '보행 패턴 신뢰도', high=1)
    step_count = finite_num(s['steps'], '걸음 수', high=2000)
    if not step_count.is_integer():
        raise ValueError('걸음 수는 정수여야 합니다.')
    if accuracy > 25:
        return a, b, distance, 'held', '위치 정확도 낮음(오차 반경 25m 초과)'
    if activity not in ('walking', 'running') or conf < .8 or accel < .75:
        return a, b, distance, 'held', '활동 인식과 가속도 보행 패턴 불일치/불확실'
    if distance == 0:
        return a, b, 0., 'held', '이동 거리 없음'
    cadence, stride, speed = step_count * 60 / duration, distance / max(step_count, 1), distance/duration
    if step_count < 3 or not 35 <= cadence <= 230 or not .15 <= stride <= 2.5 or not .25 <= speed <= 7:
        return a, b, distance, 'held', '걸음 빈도·보폭·이동 속도 간 일관성 부족'
    return a, b, distance, 'accepted', '양호한 GPS + 보행 활동 인식 + 걸음/가속도 신호 일치'

def ingest(envelope, u, fam):
    key = config('INGEST_HMAC_KEY')
    if len(key) < 32:
        raise ValueError('32자 이상의 검증 서버 비밀키 설정 후 사용할 수 있습니다.')
    if not isinstance(envelope, dict) or not isinstance(envelope.get('payload'), dict):
        raise ValueError('서명 봉투 형식이 올바르지 않습니다.')
    p = envelope['payload']
    expected = hmac.new(key.encode(), canonical(p), hashlib.sha256).hexdigest()
    signature = envelope.get('signature')
    if not isinstance(signature, str) or not hmac.compare_digest(expected, signature):
        raise ValueError('검증 서버 서명이 올바르지 않습니다.')
    if p.get('schema_version') != 1 or p.get('user_id') != u['id']:
        raise ValueError('버전 또는 계정 바인딩 불일치')
    sid = str(uuid.UUID(p['session_id']))
    issued = parse_dt(p['issued_at'])
    if issued > now() + timedelta(seconds=30) or issued < now()-timedelta(days=2):
        raise ValueError('서명 발행 후 48시간 이내 기록만 가져올 수 있습니다.')
    source = p.get('segments')
    if not isinstance(source, list) or not 1 <= len(source) <= 3000:
        raise ValueError('구간 수는 1~3000개여야 합니다.')
    checked = sorted([classify(s) for s in source], key=lambda x:x[0])
    for idx, item in enumerate(checked):
        if item[1] > issued + timedelta(seconds=30):
            raise ValueError('서명 발행 시각 뒤의 구간이 있습니다.')
        if idx and item[0] < checked[idx-1][1]:
            raise ValueError('기록 내부 구간이 겹칩니다.')
    if (checked[-1][1]-checked[0][0]).total_seconds() > 86400:
        raise ValueError('한 기록은 24시간 이내여야 합니다.')
    if checked[0][0] < parse_dt(fam['created']) or checked[0][0] < parse_dt(u['created']):
        raise ValueError('계정/가족 생성 이전 기록은 반영하지 않습니다.')
    fingerprint = hashlib.sha256(canonical({'user_id':u['id'], 'segments':source})).hexdigest()
    with db().begin() as c:
        # 동일 계정 수입 요청을 직렬화. PostgreSQL에서 행 잠금, SQLite에서 쓰기 잠금.
        c.execute(update(users).where(users.c.id == u['id']).values(goal=u['goal']))
        old = c.execute(select(segments.c.start, segments.c.end).join(workouts,
            workouts.c.id == segments.c.workout_id).where(
            workouts.c.user_id == u['id'], workouts.c.mode == 'verified')).all()
        for a,b,_,_,_ in checked:
            if any(a < parse_dt(y) and b > parse_dt(x) for x,y in old):
                raise ValueError('기존 실전 기록과 시간이 겹칩니다. 중복 합산하지 않습니다.')
        c.execute(insert(workouts).values(id=sid, user_id=u['id'], family_id=fam['id'],
            mode='verified', fingerprint=fingerprint, created=iso(now())))
        for a,b,d,status,reason in checked:
            c.execute(insert(segments).values(id=str(uuid.uuid4()), workout_id=sid,
                user_id=u['id'], start=iso(a), end=iso(b), distance_m=d, status=status, reason=reason))
    return checked

def all_segments(fam_id, mode='verified'):
    return rows(select(segments, workouts.c.created.label('recorded')).join(workouts,
        workouts.c.id == segments.c.workout_id).where(workouts.c.family_id == fam_id,
        workouts.c.mode == mode))

def distance_between(data, begin, end):
    total = 0.
    for s in data:
        if s['status'] != 'accepted':
            continue
        a,b = parse_dt(s['start']), parse_dt(s['end'])
        overlap = max(0., (min(b,end)-max(a,begin)).total_seconds())
        total += s['distance_m'] * overlap / (b-a).total_seconds()
    return total / 1000

st.set_page_config(page_title='발자국 리그', page_icon='👟', layout='wide')
st.markdown('''<style>
.stApp {background:#f4f6fa;color:#132039}
h1,h2,h3 {color:#101d35!important;letter-spacing:-.04em}
[data-testid="stSidebar"] {background:#101d35}
[data-testid="stSidebar"] * {color:#fff}
.stButton>button[kind="primary"] {background:#c4f447;color:#10203a;border:none;font-weight:800}
.hero {background:#101d35;border-radius:25px;padding:28px;color:white;margin-bottom:22px}
.hero h1 {color:white!important;font-size:2.6rem;line-height:1.2}
.hero p {color:#d7dfed}.pill {display:inline-block;background:#c4f447;color:#101d35;
 border-radius:30px;padding:6px 12px;font-weight:800;font-size:12px;letter-spacing:.06em}
.footicon{display:inline-flex;width:58px;height:58px;background:#c4f447;border-radius:18px;
 align-items:center;justify-content:center;font-size:34px;transform:rotate(-7deg);margin-bottom:12px}
.track{border-bottom:3px dashed #c4f447;display:flex;gap:25px;padding:15px 0;margin-top:18px}
.runner{font-size:36px;animation:bob 1.7s ease-in-out infinite}.runner:nth-child(2){animation-delay:.2s}
.runner:nth-child(3){animation-delay:.4s}@keyframes bob{50%{transform:translateY(-5px)}}
@media(prefers-reduced-motion:reduce){.runner{animation:none}}
[data-testid="stMetric"] {background:white;border-radius:18px;padding:18px;border:1px solid #e2e8ee}
</style>''', unsafe_allow_html=True)

def hero():
    # 독립 SVG 아이콘은 차트가 아닌 앱 로고입니다. 외부 이미지/네트워크 의존 없음.
    st.markdown('''<div class="hero"><svg width="72" height="72" viewBox="0 0 72 72" role="img" aria-label="발자국 속 결승선 깃발 앱 로고">
    <rect width="72" height="72" rx="21" fill="#c4f447"/>
    <ellipse cx="37" cy="29" rx="15" ry="21" transform="rotate(-22 37 29)" fill="#101d35"/>
    <ellipse cx="46" cy="55" rx="10" ry="7" transform="rotate(-22 46 55)" fill="#101d35"/>
    <path d="M31 39V17h17v13H32" fill="white" stroke="white" stroke-width="2"/>
    <path d="M32 18h5v5h-5zm10 0h5v5h-5zm-5 5h5v5h-5z" fill="#101d35"/>
    </svg><br><span class="pill">FAMILY WALK & RUN CLUB</span><h1>한 걸음씩, 함께.<br>발자국 리그</h1>
    <p>걷고 뛴 거리만 공정하게. 쉬어가는 날도 우리 팀입니다.</p>
    <div class="track" aria-label="출발선에 모인 가족 캐릭터"><span class="runner">🏃‍♀️</span>
    <span class="runner">🏃</span><span class="runner">🚶‍♀️</span><span class="runner">🚶</span><span>START ▰</span></div></div>''', unsafe_allow_html=True)

hero()
try:
    db()
except Exception:
    st.error('데이터베이스 연결 실패. Secrets의 DATABASE_URL 및 연결 허용 설정을 확인하세요. 비밀 연결 문자열은 화면에 표시하지 않습니다.')
    st.stop()
if not config('DATABASE_URL'):
    st.warning('현재 로컬 SQLite 체험 모드입니다. Cloud에서 가족 기록을 영구 보관하려면 PostgreSQL DATABASE_URL을 설정하세요.')

if 'uid' not in st.session_state:
    signin, signup = st.tabs(['로그인', '처음 오셨나요?'])
    with signin:
        with st.form('login'):
            login = st.text_input('아이디', max_chars=80).strip().lower()
            pw = st.text_input('비밀번호', type='password')
            submitted = st.form_submit_button('출발선 입장', type='primary')
        if submitted:
            recent = st.session_state.get('failed_at', 0)
            if time.time()-recent < 2:
                st.error('잠시 후 다시 시도해 주세요.')
            else:
                candidates = rows(select(users).where(users.c.login == login))
                if candidates and password_ok(pw, candidates[0]['password']):
                    st.session_state['uid'] = candidates[0]['id']
                    st.rerun()
                else:
                    st.session_state['failed_at'] = time.time()
                    st.error('아이디 또는 비밀번호를 확인해 주세요.')
    with signup:
        st.caption('민감한 개인정보 대신 별명과 고유 아이디를 사용하세요. 이메일 복구는 제공하지 않습니다.')
        with st.form('signup'):
            name = st.text_input('가족에게 표시할 별명', max_chars=20).strip()
            login2 = st.text_input('새 아이디 (영문·숫자·밑줄 3~40자)', max_chars=40).strip().lower()
            pw2 = st.text_input('새 비밀번호 (12자 이상)', type='password', max_chars=128)
            pw3 = st.text_input('비밀번호 확인', type='password', max_chars=128)
            consent = st.checkbox('계정 및 운동 판정 데이터 저장에 동의합니다. 아동 계정은 보호자와 함께 만듭니다.')
            create = st.form_submit_button('계정 만들기')
        if create:
            import re
            if not name or not re.fullmatch(r'[a-z0-9_]{3,40}', login2) or len(pw2)<12 or pw2!=pw3 or not consent:
                st.error('별명·아이디·12자 이상 비밀번호·확인·동의를 확인해 주세요.')
            else:
                try:
                    uid = str(uuid.uuid4())
                    with db().begin() as c:
                        c.execute(insert(users).values(id=uid,login=login2,name=name,password=password_hash(pw2),
                            family_id=None,goal=10.,created=iso(now())))
                    st.session_state['uid']=uid
                    st.rerun()
                except IntegrityError:
                    st.error('이미 사용 중인 아이디입니다.')
    st.info('이 웹앱은 GPS·가속도·걸음 센서를 백그라운드로 수집하지 않습니다. 실제 운동 자동 측정에는 별도 설치형 앱이 필요합니다.')
    st.stop()

u = user_by_id(st.session_state['uid'])
if not u:
    st.session_state.clear()
    st.rerun()
with st.sidebar:
    st.title('👟 발자국 리그')
    st.write(f"{u['name']} 님")
    page = st.radio('메뉴', ['우리 가족', '주간 리그', '운동 기록', '공동 여행', '판정 · 이의 제기', '설정 · 개인정보', '배포 · 모바일 연동'])
    st.caption('휴식일 벌점 없음 · 건강이 먼저')
    if st.button('로그아웃'):
        st.session_state.clear()
        st.rerun()

fam = family_for(u)
if not fam:
    st.subheader('우리 가족의 출발선을 만들어요')
    a,b=st.tabs(['새 가족 만들기','초대 코드로 참여'])
    with a:
        with st.form('family_create'):
            fname=st.text_input('가족 이름',max_chars=40).strip()
            tzname=st.selectbox('가족 기준 시간대', ['Asia/Seoul','Asia/Tokyo','America/New_York','America/Los_Angeles','Europe/London','Australia/Sydney','UTC'])
            made=st.form_submit_button('가족 만들기',type='primary')
        if made and fname:
            fid=str(uuid.uuid4())
            with db().begin() as c:
                locked=c.execute(update(users).where(users.c.id==u['id'],users.c.family_id.is_(None)).values(family_id=fid))
                if locked.rowcount==1:
                    c.execute(insert(families).values(id=fid,name=fname,owner=u['id'],tz=tzname,created=iso(now())))
            st.rerun()
    with b:
        with st.form('join'):
            code=st.text_input('가족에게 받은 일회용 초대 코드',type='password').strip()
            join=st.form_submit_button('참여하기')
        if join:
            digest=hashlib.sha256(code.encode()).hexdigest()
            try:
                with db().begin() as c:
                    inv=c.execute(select(invites).where(invites.c.digest==digest)).mappings().first()
                    if not inv or inv['used_by'] or parse_dt(inv['expires'])<=now():
                        raise ValueError('만료·사용되었거나 잘못된 초대 코드입니다.')
                    claimed=c.execute(update(invites).where(invites.c.digest==digest,invites.c.used_by.is_(None)).values(used_by=u['id']))
                    joined=c.execute(update(users).where(users.c.id==u['id'],users.c.family_id.is_(None)).values(family_id=inv['family_id']))
                    if claimed.rowcount!=1 or joined.rowcount!=1:
                        raise ValueError('이미 처리된 요청입니다.')
                st.rerun()
            except ValueError as e:
                st.error(str(e))
    st.stop()

members=rows(select(users.c.id,users.c.name,users.c.goal).where(users.c.family_id==fam['id']))
member_names={m['id']:m['name'] for m in members}
start,end=week_window(fam['tz'])
verified=all_segments(fam['id'])
week_label=f"{start.astimezone(ZoneInfo(fam['tz'])):%m/%d %H:%M} ~ {end.astimezone(ZoneInfo(fam['tz'])):%m/%d %H:%M} 미만 · {fam['tz']}"
st.caption(f"{fam['name']} / 이번 주 {week_label}")

if page=='우리 가족':
    st.subheader('함께 뛰는 우리 팀')
    st.write('가족에게 공유되는 운동 정보는 인정 거리와 목표 달성률뿐입니다. 경로·실시간 위치·보류 사유는 본인만 볼 수 있습니다.')
    st.dataframe(pd.DataFrame([{'별명':m['name'],'주간 목표 (km)':m['goal']} for m in members]),hide_index=True,use_container_width=True)
    if fam['owner']==u['id']:
        if st.button('일회용 가족 초대 코드 만들기'):
            token=secrets.token_urlsafe(24)
            with db().begin() as c:
                c.execute(insert(invites).values(digest=hashlib.sha256(token.encode()).hexdigest(),family_id=fam['id'],expires=iso(now()+timedelta(hours=24)),used_by=None))
            st.code(token)
            st.info('24시간 유효 · 한 사람만 사용 가능 · 이 화면을 벗어나기 전에 안전한 경로로 전달하세요.')
    else:
        st.info('가족 초대 코드는 가족 개설자가 발급할 수 있습니다.')
    st.success('오늘 쉬어도 괜찮아요. 연속 출석 압박이나 휴식일 벌점은 없습니다.')

elif page=='주간 리그':
    st.subheader('이번 주, 공정한 발자국')
    totals={m['id']:distance_between([s for s in verified if s['user_id']==m['id']],start,end) for m in members}
    a,b,c=st.columns(3)
    a.metric('가족 주간 인정 거리', f'{sum(totals.values()):.2f} km')
    b.metric('내 주간 인정 거리',f"{totals.get(u['id'],0):.2f} km")
    c.metric('내 목표 달성률',f"{100*totals.get(u['id'],0)/u['goal']:.0f}%")
    data=[{'별명':m['name'],'인정 거리 (km)':round(totals[m['id']],3),'목표 달성률 (%)':round(100*totals[m['id']]/m['goal'],1)} for m in members]
    t1,t2=st.tabs(['🏁 거리 리그','🌱 나의 목표 리그'])
    with t1:
        st.dataframe(pd.DataFrame(sorted(data,key=lambda x:x['인정 거리 (km)'],reverse=True)),hide_index=True,use_container_width=True)
    with t2:
        st.dataframe(pd.DataFrame(sorted(data,key=lambda x:x['목표 달성률 (%)'],reverse=True)),hide_index=True,use_container_width=True)
    st.caption('동점은 공동 순위입니다. 목표 변경은 현재 주에도 반영되므로 가족 간 합의 후 변경하세요. 주 경계 구간은 시간 비율로 거리를 나눕니다(구간 내 일정 속도 가정).')
    if not any(totals.values()):
        st.info('아직 이번 주에 검증된 인정 거리가 없습니다. 데모 기록은 이 순위에 들어가지 않습니다.')

elif page=='운동 기록':
    st.subheader('운동 시작하기')
    st.warning('브라우저 시작 버튼은 타이머 데모입니다. 실제 GPS/걸음 측정이나 거리 인증을 하지 않습니다. 탭을 닫으면 타이머가 사라질 수 있습니다.')
    timer=st.session_state.setdefault('timer',{'state':'idle','elapsed':0.,'since':None})
    def elapsed():
        return timer['elapsed']+(time.monotonic()-timer['since'] if timer['state']=='running' else 0)
    st.metric('타이머 (데모)',f'{int(elapsed())//60:02d}:{int(elapsed())%60:02d}')
    c1,c2,c3,c4=st.columns(4)
    if c1.button('▶ 시작 / 재개',disabled=timer['state']=='running'):
        timer['since']=time.monotonic();timer['state']='running';st.rerun()
    if c2.button('Ⅱ 일시정지',disabled=timer['state']!='running'):
        timer['elapsed']=elapsed();timer['state']='paused';timer['since']=None;st.rerun()
    if c3.button('■ 종료',disabled=timer['state']=='idle'):
        seconds=elapsed()
        st.session_state['last_timer_seconds']=seconds
        st.session_state['timer']={'state':'idle','elapsed':0.,'since':None}
        st.rerun()
    if c4.button('시간 새로고침'):
        st.rerun()
    if 'last_timer_seconds' in st.session_state:
        st.info(f"종료한 데모 타이머: {st.session_state['last_timer_seconds']:.0f}초. 측정 거리는 없습니다.")
    st.divider()
    st.subheader('실전 기록 가져오기')
    st.caption('설치형 앱 → 신뢰된 검증 서버 → 서명된 JSON 파일. 개인 원시 GPS 좌표는 업로드하지 않습니다.')
    enabled=len(config('INGEST_HMAC_KEY'))>=32
    if not enabled:
        st.info('검증 서버가 연결되지 않아 실전 가져오기가 잠겨 있습니다. 배포 · 모바일 연동을 확인하세요.')
    uploaded=st.file_uploader('검증 서버에서 받은 JSON',type=['json'],disabled=not enabled)
    if st.button('서버 검증 후 저장',disabled=not(enabled and uploaded is not None)):
        try:
            if uploaded.size>2_000_000:
                raise ValueError('파일은 2MB 이하여야 합니다.')
            result=ingest(json.loads(uploaded.getvalue()),u,fam)
            st.success(f"저장 완료: 인정 {sum(s[3]=='accepted' for s in result)} / 보류 {sum(s[3]=='held' for s in result)} / 제외 {sum(s[3]=='excluded' for s in result)} 구간")
        except IntegrityError:
            st.error('이미 등록된 기록입니다. 중복 저장하지 않았습니다.')
        except (ValueError,KeyError,TypeError,OverflowError,AttributeError) as e:
            st.error(f'가져오기를 거절했습니다: {e}')
    with st.expander('격리된 데모 기록 만들기'):
        st.caption('가족 실전 순위·공동 여행에 절대 반영되지 않습니다. 내 데모 화면에서만 확인할 수 있습니다.')
        if st.button('1km 샘플 1개 저장'):
            wid=str(uuid.uuid4());b=now();a=b-timedelta(minutes=15)
            with db().begin() as c:
                c.execute(insert(workouts).values(id=wid,user_id=u['id'],family_id=fam['id'],mode='demo',fingerprint=wid,created=iso(now())))
                c.execute(insert(segments).values(id=str(uuid.uuid4()),workout_id=wid,user_id=u['id'],start=iso(a),end=iso(b),distance_m=1000,status='accepted',reason='데모: 센서 미검증, 실전 제외'))
            st.success('데모 전용 공간에 저장했습니다.')
        demo=[s for s in all_segments(fam['id'],'demo') if s['user_id']==u['id']]
        st.metric('내 데모 누적 (실전 제외)',f"{sum(s['distance_m'] for s in demo)/1000:.1f} km")

elif page=='공동 여행':
    st.subheader('우리의 발자국으로 떠나는 가상 여행')
    total=sum(s['distance_m'] for s in verified if s['status']=='accepted')/1000
    course=[('출발 마을',0),('바람 공원',10),('초록 숲',25),('달빛 호수',50),('별빛 전망대',80),('가족의 바다',120)]
    st.metric('가족 전체 누적 인정 거리',f'{total:.2f} km')
    st.progress(min(total/120,1.),text=f'첫 여행 완주까지 {max(120-total,0):.2f} km')
    # 가상 여행 지도이며 실제 위치/경로가 아님. CSS만으로 여행 노선 표현.
    stops=''.join(f'<div class="stop {"done" if total>=km else ""}"><b>{"🏁" if total>=km else "○"}</b><span>{name}</span><small>{km} km</small></div>' for name,km in course)
    components.html('<!doctype html><html lang="ko"><meta charset="utf-8"><style>body{font-family:system-ui;background:#101d35;color:white;margin:0;padding:24px;border-radius:20px}.route{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}.stop{display:flex;flex-direction:column;gap:12px;text-align:center;padding:15px;border-top:4px solid #53617a;flex:1;min-width:85px}.done{border-color:#c4f447}.stop b{font-size:30px}.stop small{color:#d9e4ed}p{color:#c4f447}</style><p>OUR FAMILY JOURNEY · 가상 지도</p><div class="route">'+stops+'</div></html>',height=340)
    st.caption('실제 지리 정보가 아닌 가상의 여행길입니다. 보류·제외·데모는 합산하지 않습니다. 120km를 넘어도 누적 거리는 계속 보존됩니다.')

elif page=='판정 · 이의 제기':
    st.subheader('내 기록의 판정 근거')
    mine=sorted([s for s in verified if s['user_id']==u['id']],key=lambda s:s['start'],reverse=True)
    labels={'accepted':'인정','held':'보류','excluded':'제외'}
    if not mine:
        st.info('아직 검증 서버에서 가져온 내 기록이 없습니다.')
    else:
        st.dataframe(pd.DataFrame([{'구간 ID':s['id'],'시작':parse_dt(s['start']).astimezone(ZoneInfo(fam['tz'])).strftime('%Y-%m-%d %H:%M:%S'),'거리(m)':round(s['distance_m'],1),'판정':labels[s['status']],'이유':s['reason']} for s in mine]),hide_index=True,use_container_width=True)
        disputed=[s for s in mine if s['status']!='accepted']
        if disputed:
            st.caption('접수 시 선택한 구간의 판정 사유와 작성한 설명이 가족 개설자에게 공유됩니다. 상세 위치는 공유하지 않습니다.')
            with st.form('appeal'):
                target=st.selectbox('이의를 제기할 구간',disputed,format_func=lambda s:f"{s['id'][:8]} · {labels[s['status']]} · {s['reason']}")
                text=st.text_area('설명 (주소나 건강정보는 쓰지 마세요)',max_chars=1000)
                send=st.form_submit_button('이의 제기 접수')
            if send and text.strip():
                try:
                    with db().begin() as c:
                        c.execute(insert(appeals).values(id=str(uuid.uuid4()),user_id=u['id'],segment_id=target['id'],message=text.strip(),state='접수',reply='',created=iso(now())))
                    st.success('접수했습니다. 아래 검토함에서 확인할 수 있습니다. 점수는 자동 변경되지 않습니다.')
                except IntegrityError:
                    st.error('이미 이의를 제기한 구간입니다.')
    my_appeals=rows(select(appeals).where(appeals.c.user_id==u['id']))
    if my_appeals:
        st.dataframe(pd.DataFrame([{'구간':a['segment_id'],'내용':a['message'],'상태':a['state'],'답변':a['reply']} for a in my_appeals]),hide_index=True,use_container_width=True)
    st.caption('가족 개설자는 접수·재검증 안내만 처리합니다. 임의 점수 승인은 불가능합니다. 새 검증 결과로 기존 판정을 교정하는 자동 연동은 아직 제공하지 않습니다.')
    if fam['owner']==u['id']:
        st.divider();st.subheader('가족 개설자 검토함')
        st.caption('이의를 제기하면 해당 구간의 사유와 작성한 설명을 개설자에게 공유합니다. 위치와 경로는 공유하지 않습니다.')
        inbox=rows(select(appeals).join(workouts,workouts.c.user_id==appeals.c.user_id).where(workouts.c.family_id==fam['id']).distinct())
        # 멤버와 운동 구간의 실제 소속 모두 확인합니다.
        valid_ids={s['id'] for s in verified}
        inbox=[a for a in inbox if a['user_id'] in member_names and a['segment_id'] in valid_ids]
        if inbox:
            chosen=st.selectbox('접수 건',inbox,format_func=lambda a:f"{member_names.get(a['user_id'],'가족')} · {a['segment_id'][:8]} · {a['state']}")
            st.write(chosen['message'])
            with st.form('review'):
                reply=st.text_area('검토 답변',value=chosen['reply'] or '',max_chars=1000)
                state=st.selectbox('상태',['접수','재검증 요청','답변 완료'])
                save=st.form_submit_button('답변 저장 (점수 불변)')
            if save:
                with db().begin() as c:
                    c.execute(update(appeals).where(appeals.c.id==chosen['id']).values(reply=reply,state=state))
                st.rerun()
        else:
            st.info('접수된 이의 제기가 없습니다.')

elif page=='설정 · 개인정보':
    st.subheader('내 페이스로 달리기')
    with st.form('goal'):
        goal=st.number_input('내 주간 목표 (km)',min_value=.5,max_value=500.,value=float(u['goal']),step=.5)
        if st.form_submit_button('목표 저장'):
            with db().begin() as c:
                c.execute(update(users).where(users.c.id==u['id']).values(goal=goal))
            st.rerun()
    st.info('가족 기준 시간대는 생성 시 고정됩니다. 시간대 변경으로 주간 점수가 바뀌는 혼란을 방지합니다.')
    st.write('저장: 별명, 암호 해시, 가족 소속, 목표, 구간 시작/종료·거리·판정 사유, 이의 제기. 저장하지 않음: 실시간 위치·상세 GPS 좌표·비밀번호 원문. 서명 검증 후 원시 입력 JSON도 저장하지 않습니다.')
    my= [s for s in verified if s['user_id']==u['id']]
    export={'profile':{'id':u['id'],'name':u['name'],'goal_km':u['goal']},'verified_segments':my,'appeals':rows(select(appeals).where(appeals.c.user_id==u['id']))}
    st.download_button('내 기록 JSON 내려받기',json.dumps(export,ensure_ascii=False,indent=2),file_name='my_footprints.json',mime='application/json')
    with st.form('pw_change'):
        oldpw=st.text_input('현재 비밀번호',type='password')
        newpw=st.text_input('새 비밀번호 (12~128자)',type='password',max_chars=128)
        if st.form_submit_button('비밀번호 변경'):
            if password_ok(oldpw,u['password']) and len(newpw)>=12:
                with db().begin() as c:
                    c.execute(update(users).where(users.c.id==u['id']).values(password=password_hash(newpw)))
                st.success('비밀번호를 변경했습니다.')
            else:
                st.error('현재 비밀번호와 새 비밀번호 길이를 확인하세요.')
    with st.expander('내 운동 기록 전체 삭제'):
        st.warning('실전·데모·관련 이의 제기가 영구 삭제되며 가족 순위와 여행 누적 거리에서도 빠집니다. 계정은 유지됩니다.')
        confirm=st.text_input('확인을 위해 “내 기록 삭제” 입력')
        if st.button('영구 삭제',disabled=confirm!='내 기록 삭제'):
            with db().begin() as c:
                c.execute(appeals.delete().where(appeals.c.user_id==u['id']))
                c.execute(segments.delete().where(segments.c.user_id==u['id']))
                c.execute(workouts.delete().where(workouts.c.user_id==u['id']))
            st.success('내 운동 기록을 삭제했습니다. 백업 보존 정책은 DB 운영자에게 확인하세요.')

else:
    st.subheader('GitHub → Streamlit 배포 안내')
    st.markdown('''1. GitHub 저장소에 **app.py**, **requirements.txt**를 올립니다.
2. Streamlit Community Cloud에서 저장소와 `app.py`를 선택해 배포합니다. Python 3.11 이상을 권장합니다.
3. 가족이 계속 사용할 서비스라면 영구 PostgreSQL을 준비하고 앱 **Settings → Secrets**에 연결 정보를 넣습니다.
4. 검증 서버를 별도로 구축한 경우에만 `INGEST_HMAC_KEY`를 설정합니다. 비밀키는 저장소나 모바일 앱에 넣지 않습니다.
5. 운영 전 로그인 속도 제한, 계정 복구, 모니터링, 백업/복원, 개인정보 고지·보존 정책, 검증 서버 테스트를 추가하세요. 현재 앱의 세션별 로그인 지연은 전역 공격 방어가 아닙니다.''')
    st.code('DATABASE_URL = "postgresql+psycopg://USER:PASSWORD@HOST:5432/DB?sslmode=require"\nINGEST_HMAC_KEY = "REPLACE_WITH_32_OR_MORE_RANDOM_CHARACTERS"',language='toml')
    st.subheader('설치형 앱이 담당해야 하는 것')
    st.markdown('''- iOS: 위치/모션 권한 및 백그라운드 위치 정책, Android: 위치/활동 인식 권한과 foreground service 정책에 맞는 구현.
- 사용자 동의하에 GPS 정확도·시간·걸음·가속도 기반 보행 패턴·활동 종류를 수집. 서버에는 가급적 구간 집계만 전송.
- 속도만으로 차량을 단정하지 않고 원시 신호를 교차 확인. 센서 없음/오차 큼/애매함은 보류.
- 신뢰된 서버에서 인증된 계정에 기록을 바인딩하고 기기 무결성·타임스탬프·재전송·조작을 검사한 후 JSON에 서명.
- Streamlit 웹앱만으로 네이티브 백그라운드 수집·완벽한 차량 탐지를 구현할 수 없습니다. 이 파일은 별도의 모바일 바이너리를 포함하지 않습니다.''')
    st.subheader('검증 서버 JSON 연동 계약')
    st.write('내 사용자 ID (외부 검증 서버의 인증 계정과 안전하게 연결해야 함)')
    st.code(u['id'])
    sample={'schema_version':1,'session_id':str(uuid.uuid4()),'user_id':u['id'],'issued_at':iso(now()),'segments':[{'start':iso(now()-timedelta(seconds=60)),'end':iso(now()),'distance_m':80.,'duration_s':60.,'accuracy_m':8.,'steps':100,'activity':'walking','activity_confidence':.95,'accel_walk_confidence':.9,'location_jump':False}]}
    st.code(json.dumps({'payload':sample,'signature':'TRUSTED_SERVER_HMAC_SHA256_HEX'},ensure_ascii=False,indent=2),language='json')
    st.caption('위 예시는 형식 설명용이며 서명이 없어 실전 업로드가 거절됩니다. user_id를 임의로 지정하게 하는 외부 검증 서버는 안전하지 않습니다.')
    st.code("canonical = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')\nsignature = hmac.new(secret.encode(), canonical, hashlib.sha256).hexdigest()",language='python')
    st.markdown('''**기본 판정 규칙**
- 5~120초 구간, 최근 30일 기록, 서명 발행 48시간 이내만 처리합니다.
- 위치 점프 또는 12m/s 초과 극단 이동은 제외. 차량/자전거 인식 신뢰도 0.8 이상은 제외합니다.
- 위치 오차 25m 이하, 걷기/달리기 신뢰도 0.8 이상, 가속도 보행 신뢰도 0.75 이상이어야 인정 후보입니다.
- 분당 35~230걸음, 보폭 0.15~2.5m, 속도 0.25~7m/s가 함께 일치해야 인정합니다. 나머지는 보류합니다.
- 느리게 가는 차량을 완벽히 탐지한다는 보장은 없습니다. 손목/휴대 위치·보행 특성에 따라 정상 운동도 보류될 수 있으므로 실제 기기별 검증이 필요합니다.
- session_id·내용 지문·시간 겹침으로 중복 합산을 방지합니다. 원본 서명 서버가 침해되면 이 검증도 신뢰할 수 없습니다.''')

st.divider()
st.caption('발자국 리그 · 걷고 뛰는 즐거움을 함께. 통증이나 호흡 불편이 있으면 경쟁보다 휴식을 우선하세요. 이 앱은 의료기기가 아닙니다.')
