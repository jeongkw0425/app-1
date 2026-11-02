"""둘의 하루 — Streamlit single-page couple diary.

실행: pip install -r requirements.txt && streamlit run app.py
배포: GitHub에 이 파일과 requirements.txt 업로드 → Streamlit Community Cloud.
운영 시 앱 Settings > Secrets에 아래 값을 설정하세요(저장소에 올리지 마세요).
DATABASE_URL = "postgresql+psycopg://USER:PASSWORD@HOST:5432/DB?sslmode=require"
APP_URL = "https://YOUR-APP.streamlit.app"
Supabase / Neon 등의 PostgreSQL 연결 URL 사용 가능. SQL 테이블은 자동 생성됩니다.
DATABASE_URL 미설정 시 로컬 SQLite 체험 모드입니다. Cloud에서 영구 보관되지 않습니다.
QR에는 공개 앱 주소와 커플 코드만 포함됩니다. 비밀번호와 개인 PIN은 넣지 않습니다.
커플 코드와 공용 비밀번호를 상대에게 전달하고 각자 다른 자리를 선택하세요.
각 자리의 개인 PIN은 첫 접속자가 등록합니다. 신뢰하는 상대에게만 초대하세요.
비밀번호/PIN 복구, 백업, 관리 콘솔은 포함하지 않습니다. 운영자는 DB를 관리해야 합니다.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import os
import re
import secrets
import time
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode, urlsplit, urlunsplit

import qrcode
import streamlit as st
from sqlalchemy import (Column, ForeignKey, Integer, MetaData, String, Table,
                        Text, UniqueConstraint, create_engine, event, select, update)
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

st.set_page_config(page_title="둘의 하루", page_icon="💌", layout="centered", initial_sidebar_state="collapsed")
st.markdown("""<style>
:root {color-scheme:light;}
.stApp {background:linear-gradient(145deg,#fff8f5,#fff0f4);color:#493a43;}
.block-container {max-width:480px;padding:0.8rem 1rem 1rem;}
header[data-testid="stHeader"] {background:transparent;height:0;}
#MainMenu,footer {visibility:hidden;}
[data-testid="stToolbar"] {display:none;}
[data-testid="stVerticalBlock"] {gap:0.42rem;}
h1 {font-size:1.55rem !important;padding:0 !important;}
p {margin-bottom:0.25rem;}
[data-testid="stCaptionContainer"] {font-size:.77rem;}
.stButton>button,.stFormSubmitButton>button {border-radius:14px;min-height:2.35rem;}
[data-testid="stTextArea"] textarea {font-size:16px;}
[data-testid="stTextInput"] input {font-size:16px;}
[data-testid="stForm"] {padding:0.65rem;border-radius:18px;border-color:#ecd8df;}
@media(max-width:480px){.block-container{padding-top:.5rem;padding-bottom:.5rem;}}
</style>""", unsafe_allow_html=True)


def setting(key: str, default: str = "") -> str:
    try:
        return str(st.secrets.get(key, os.getenv(key, default)))
    except (FileNotFoundError, st.errors.StreamlitSecretNotFoundError):
        return os.getenv(key, default)


URL = setting("DATABASE_URL")
DEMO = not URL
if URL.startswith("postgres://"):
    URL = URL.replace("postgres://", "postgresql+psycopg://", 1)
elif URL.startswith("postgresql://"):
    URL = URL.replace("postgresql://", "postgresql+psycopg://", 1)

meta = MetaData()
pairs = Table("cd_pairs", meta,
              Column("code", String(32), primary_key=True),
              Column("password_hash", String(200), nullable=False))
users = Table("cd_users", meta,
              Column("id", String(64), primary_key=True),
              Column("pair_code", String(32), ForeignKey("cd_pairs.code"), nullable=False),
              Column("seat", String(1), nullable=False),
              Column("pin_hash", String(200), nullable=False),
              UniqueConstraint("pair_code", "seat"))
entries = Table("cd_entries", meta,
                Column("id", Integer, primary_key=True, autoincrement=True),
                Column("pair_code", String(32), ForeignKey("cd_pairs.code"), nullable=False),
                Column("author", String(64), ForeignKey("cd_users.id"), nullable=False),
                Column("mood", String(30), nullable=False),
                Column("body", Text, nullable=False),
                Column("created_at", String(40), nullable=False),
                Column("read_at", String(40)))


@st.cache_resource
def database(url: str):
    engine = create_engine(url or "sqlite:///couple_diary.db", pool_pre_ping=True,
                           **({"connect_args": {"check_same_thread": False, "timeout": 20}}
                              if not url else {}))
    if engine.dialect.name == "sqlite":
        @event.listens_for(engine, "connect")
        def sqlite_setup(conn, _):
            conn.execute("PRAGMA foreign_keys=ON")
    meta.create_all(engine)
    return engine


def digest(value: str) -> str:
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", value.encode(), salt.encode(), 260000)
    return salt + ":" + hashed.hex()


def verify(value: str, stored: str) -> bool:
    salt, expected = stored.split(":", 1)
    actual = hashlib.pbkdf2_hmac("sha256", value.encode(), salt.encode(), 260000).hex()
    return hmac.compare_digest(actual, expected)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def local_time(value: str) -> str:
    return datetime.fromisoformat(value).astimezone(timezone(timedelta(hours=9))).strftime("%m.%d %H:%M")


try:
    db = database(URL)
except Exception:
    st.error("데이터베이스 연결에 실패했습니다. 운영자가 Secrets의 DATABASE_URL과 DB 상태를 확인해 주세요.")
    st.stop()

st.title("💌 둘의 하루")
if DEMO:
    st.caption("🧪 체험 모드 · 클라우드 재시작 시 기록이 사라질 수 있어요.")
else:
    st.caption("작은 마음을 남기고, 읽었다는 안심을 전해요.")


def authenticate(code: str, password: str, seat: str, pin: str):
    """First login creates a couple/seat; unique constraints protect concurrent registration."""
    for attempt in range(2):
        try:
            with db.begin() as conn:
                pair = conn.execute(select(pairs).where(pairs.c.code == code)).mappings().first()
                if pair is None:
                    conn.execute(pairs.insert().values(code=code, password_hash=digest(password)))
                elif not verify(password, pair["password_hash"]):
                    return None
                uid = code + ":" + seat
                user = conn.execute(select(users).where(users.c.id == uid)).mappings().first()
                if user is None:
                    conn.execute(users.insert().values(id=uid, pair_code=code, seat=seat, pin_hash=digest(pin)))
                elif not verify(pin, user["pin_hash"]):
                    return None
                return uid
        except IntegrityError:
            if attempt:
                raise
    return None


if time.time() - st.session_state.get("logged_at", 0) > 12 * 3600:
    st.session_state.pop("uid", None)

if "uid" not in st.session_state:
    st.caption("처음이면 방이 만들어져요. 두 사람은 같은 코드·공용 비밀번호, 다른 자리를 사용해요.")
    with st.form("login"):
        code = st.text_input("커플 코드", value=str(st.query_params.get("couple", ""))[:32],
                             placeholder="영문·숫자·밑줄·하이픈 6~32자", max_chars=32).strip().upper()
        password = st.text_input("공용 비밀번호", type="password", max_chars=128,
                                 placeholder="10자 이상 · 상대와 공유")
        left, right = st.columns([1, 1.5])
        seat = left.selectbox("내 자리", ["A", "B"])
        pin = right.text_input("내 개인 PIN", type="password", max_chars=6,
                               placeholder="숫자 6자리")
        st.caption("개인 PIN은 첫 접속 시 등록돼요. 다음에도 같은 자리·PIN으로 접속하세요.")
        login = st.form_submit_button("우리 공간 들어가기", use_container_width=True, type="primary")
    if login:
        if time.time() < st.session_state.get("retry_after", 0):
            st.warning("잠시 후 다시 시도해 주세요.")
        elif not re.fullmatch(r"[A-Z0-9_-]{6,32}", code):
            st.warning("커플 코드는 영문·숫자·밑줄·하이픈으로 6~32자 입력해 주세요.")
        elif len(password) < 10 or not re.fullmatch(r"[0-9]{6}", pin):
            st.warning("공용 비밀번호는 10자 이상, 개인 PIN은 숫자 6자리예요.")
        else:
            try:
                uid = authenticate(code, password, seat, pin)
                if uid:
                    st.session_state.update(uid=uid, pair=code, seat=seat, logged_at=time.time())
                    st.query_params["couple"] = code
                    st.rerun()
                else:
                    st.session_state["retry_after"] = time.time() + 5
                    st.error("공용 비밀번호 또는 개인 PIN을 확인해 주세요.")
            except SQLAlchemyError:
                st.error("접속을 완료하지 못했어요. 잠시 후 다시 시도해 주세요.")
    st.stop()

uid, code, seat = (st.session_state[k] for k in ("uid", "pair", "seat"))


@st.dialog("우리 공간 QR")
def qr_dialog():
    st.caption("QR을 스캔하면 이 커플 코드가 입력된 접속 화면이 열려요. 비밀번호는 별도로 전달하세요.")
    base = st.text_input("배포된 앱 주소", value=setting("APP_URL"), placeholder="https://your-app.streamlit.app")
    parsed = urlsplit(base.strip())
    if parsed.scheme in ("https", "http") and parsed.netloc:
        link = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode({"couple": code}), ""))
        buf = io.BytesIO()
        qrcode.make(link).save(buf, format="PNG")
        st.image(buf.getvalue(), width=220)
        st.code(link, language=None)
        st.download_button("QR 이미지 받기", buf.getvalue(), "couple-qr.png", "image/png")
    elif base:
        st.warning("https://로 시작하는 실제 배포 주소를 입력해 주세요.")
    else:
        st.info("Streamlit 배포 후 주소를 입력하거나 Secrets에 APP_URL을 설정해 주세요.")


left, middle, right = st.columns([2.2, 1, 1])
left.caption(f"{code} · 내 자리 {seat} · 한국시간")
if middle.button("QR", use_container_width=True):
    qr_dialog()
if right.button("나가기", use_container_width=True):
    for key in list(st.session_state):
        del st.session_state[key]
    st.rerun()

if "draft_id" not in st.session_state:
    st.session_state["draft_id"] = 0
if st.session_state.pop("sent", False):
    st.toast("마음을 보냈어요 💗")

with st.form("compose", clear_on_submit=True):
    mood = st.select_slider("오늘의 기분", options=["😊 행복", "🥰 설렘", "😌 평온", "🥺 서운", "😢 슬픔"], value="😌 평온")
    body = st.text_area("전하고 싶은 말", max_chars=300, height=80,
                        placeholder="오늘 당신에게 하고 싶은 말… (300자)", label_visibility="collapsed")
    send = st.form_submit_button("마음 보내기 💗", type="primary", use_container_width=True)
if send:
    if not body.strip():
        st.warning("한 글자라도 마음을 적어 주세요.")
    else:
        try:
            with db.begin() as conn:
                conn.execute(entries.insert().values(pair_code=code, author=uid, mood=mood,
                                                      body=body.strip(), created_at=now()))
            st.session_state["sent"] = True
            st.rerun()
        except SQLAlchemyError:
            st.error("저장하지 못했어요. 연결을 확인하고 다시 작성해 주세요.")


@st.fragment(run_every="15s")
def diary_feed():
    try:
        with db.connect() as conn:
            all_rows = conn.execute(select(entries).where(entries.c.pair_code == code)
                                    .order_by(entries.c.id.desc()).limit(500)).mappings().all()
    except SQLAlchemyError:
        st.warning("일기를 불러오지 못했어요. 잠시 후 새로고침해 주세요.")
        return
    a, b = st.columns([3.6, 1])
    which = a.radio("일기 보기", ["상대 일기", "내 일기"], horizontal=True, label_visibility="collapsed")
    b.button("↻", key="refresh", help="지금 새로고침", use_container_width=True)
    rows = [r for r in all_rows if (r["author"] != uid if which == "상대 일기" else r["author"] == uid)]
    if not rows:
        st.info("아직 상대 일기가 없어요 💌" if which == "상대 일기" else "첫 마음을 남겨 보세요 💌")
        return
    labels = {r["id"]: f'{local_time(r["created_at"])} · {r["mood"]}' for r in rows}
    entry_id = st.selectbox("일기 선택 · 최근 500개 전체 기록 중", list(labels),
                            format_func=labels.get, label_visibility="collapsed", key="pick_" + which)
    row = next(r for r in rows if r["id"] == entry_id)
    with st.container(height=118, border=True):
        # Render diary as text, never as HTML or executable Markdown.
        st.text(row["body"])
    if row["author"] == uid:
        st.caption("💗 상대가 확인했어요 · " + local_time(row["read_at"]) if row["read_at"] else "💭 상대가 아직 확인하지 않았어요")
    elif row["read_at"]:
        st.caption("✅ 내가 확인한 일기 · " + local_time(row["read_at"]))
    elif st.button("✓ 읽었어요 · 상대에게 알려주기", use_container_width=True, key="read_" + str(entry_id)):
        try:
            with db.begin() as conn:
                conn.execute(update(entries).where(entries.c.id == entry_id,
                                                   entries.c.pair_code == code,
                                                   entries.c.author != uid,
                                                   entries.c.read_at.is_(None)).values(read_at=now()))
            st.rerun(scope="fragment")
        except SQLAlchemyError:
            st.warning("읽음 표시를 저장하지 못했어요. 다시 눌러 주세요.")
    st.caption("15초마다 자동 갱신 · 읽음은 버튼을 눌러야 전달돼요.")


diary_feed()
