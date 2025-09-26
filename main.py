import asyncio
import re
from datetime import datetime, UTC
import requests
from bs4 import BeautifulSoup
from aiogram import Bot, Dispatcher, types, F
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties
import html

import config
import db

# init db
db.init_db()

# aiogram bot
bot = Bot(token=config.BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
dp = Dispatcher()

# requests session
session = requests.Session()

# worker control
_worker_task = None
_worker_running = False

# =========================================================
# Logic don shiga da karɓar token
# =========================================================
def login_and_fetch_token():
    print("Ana ƙoƙarin shiga da karɓar sabon zaman/token...")
    try:
        r = session.get(config.LOGIN_URL, timeout=15)
        r.raise_for_status()

        soup = BeautifulSoup(r.text, 'html.parser')
        token_input = soup.find('input', {'name': '_token'})
        
        if not token_input or not token_input.get('value'):
            db.save_error("Shiga ya kasa: Ba a iya samun asalin CSRF token ba.")
            print("Shiga ya kasa: Ba a iya samun asalin CSRF token ba.")
            return False

        initial_csrf_token = token_input.get('value')
        
        login_data = {
            '_token': initial_csrf_token,
            'email': config.LOGIN_EMAIL,
            'password': config.LOGIN_PASSWORD,
            'g-recaptcha-response': '',
            'submit': 'login'
        }
        
        session.headers.update(config.HEADERS)

        r_login = session.post(config.LOGIN_URL, data=login_data, timeout=15, allow_redirects=False)

        if r_login.status_code == 302 and 'location' in r_login.headers and 'portal' in r_login.headers['location']:
            print("Shiga ya yi nasara! Yanzu za a karɓi sabon token daga shafin portal.")
            
            r_portal = session.get(r_login.headers['location'], timeout=15)
            r_portal.raise_for_status()
            
            soup_portal = BeautifulSoup(r_portal.text, 'html.parser')
            new_token_input = soup_portal.find('input', {'name': '_token'})
            
            if not new_token_input or not new_token_input.get('value'):
                db.save_error("Shiga ya yi nasara amma ba a iya samun sabon CSRF token ba.")
                print("Shiga ya yi nasara amma ba a iya samun sabon CSRF token ba.")
                return False

            config.CSRF_TOKEN = new_token_input.get('value')
            print("An sabunta cookie na zaman da CSRF token cikin nasara.")
            return True
        else:
            db.save_error(f"Buƙatar shiga ta POST ta kasa. Status code: {r_login.status_code}. Response: {r_login.text}")
            print(f"Buƙatar shiga ta POST ta kasa. Status code: {r_login.status_code}")
            return False

    except requests.exceptions.RequestException as e:
        db.save_error(f"Tsarin shiga ya kasa da wani kuskure: {e}")
        print(f"Tsarin shiga ya kasa da wani kuskure: {e}")
        return False

# masu taimakawa
def mask_number(num: str) -> str:
    s = num.strip()
    if len(s) <= (config.MASK_PREFIX_LEN + config.MASK_SUFFIX_LEN):
        return s
    return s[:config.MASK_PREFIX_LEN] + "****" + s[-config.MASK_SUFFIX_LEN:]

def detect_service(text: str) -> str:
    t = (text or "").lower()
    # Muna amfani da `sorted` tare da `len` don tabbatar da an fara gwada kalmomi masu tsawo
    for k in sorted(config.SERVICES.keys(), key=len, reverse=True):
        if k in t:
            return config.SERVICES[k]
    # Sabon ƙari don gano Twilio, ko da ba a saita a config ba
    if "twilio" in t:
        return "Twilio"
    return "Service"

def detect_country(number: str, extra_text: str = "") -> str:
    s = number.lstrip("+")
    for prefix, flagname in config.COUNTRY_FLAGS.items():
        if s.startswith(prefix):
            return flagname
    txt = (extra_text or "").upper()
    if "PERU" in txt:
        return config.COUNTRY_FLAGS.get("51", "🇵🇪 Peru")
    if "BANGLADESH" in txt or "+880" in number:
        return config.COUNTRY_FLAGS.get("880", "🇧🇩 Bangladesh")
    return "🌍 Unknown"

def extract_otps(text: str):
    """
    Wannan aikin yana ciro OTPs daga rubutu.
    Yanzu an inganta shi don ware lambobi masu ma'ana kawai.
    """
    text = text.strip()
    
    # 1. Gwaji na farko: Nemi lambobin da suka hada da kalmomi masu muhimmanci
    match = re.search(r"(?:code|is|is:?|:)\s*(\b\d{4,8}\b)", text, re.IGNORECASE)
    if match:
        return [match.group(1)]
    
    # Sabon ƙari don kama tsari kamar 546-437 ko 564 786
    match_with_separator = re.search(r"\b\d{3}\s*[- ]\s*\d{3}\b", text)
    if match_with_separator:
        # A Tura shi kamar yadda Yake
        return [match_with_separator.group(0)]
    
    # 2. Gwaji na biyu: Nemi lambobi masu hada-hadar haruffa da lambobi
    match = re.search(r"\b([a-zA-Z0-9]{6,12})\b", text, re.IGNORECASE)
    if match:
        # Tabbatar OTP din ba kalma bace mara amfani
        if not re.search(r"[a-zA-Z]", match.group(1)) or re.search(r"\d", match.group(1)):
             return [match.group(1)]

    # 3. Gwaji na karshe: Nemi duk wata lamba mai tsayi 4-8 a cikin saƙo
    matches = re.findall(r"\b(\d{4,8})\b", text)
    if matches:
        return matches

    # Idan ba a samu komai ba, koma da fanko
    return []

# parsing helpers
def parse_ranges(html_text: str):
    soup = BeautifulSoup(html_text, "html.parser")
    ranges = []
    for opt in soup.select("select#range option"):
        val = opt.get_text(strip=True)
        if val:
            ranges.append(val)
    if not ranges:
        for m in re.finditer(r"([A-Z][A-Z\s]{2,}\s+\d{2,6})", html_text):
            ranges.append(m.group(1).strip())
    return list(dict.fromkeys(ranges))

def parse_numbers(html_text: str):
    soup = BeautifulSoup(html_text, "html.parser")
    nums = []
    for tr in soup.select("table tr"):
        tds = [td.get_text(" ", strip=True) for td in tr.find_all("td")]
        for txt in tds:
            m = re.search(r"(\+?\d{6,15})", txt)
            if m:
                nums.append(m.group(1))
                break
    if not nums:
        for m in re.finditer(r"(\+?\d{6,15})", html_text):
            nums.append(m.group(1))
    return list(dict.fromkeys(nums))

def parse_messages_with_timestamps(html_text: str):
    soup = BeautifulSoup(html_text, "html.parser")
    msgs = []
    for tr in soup.select("table tbody tr"):
        tds = tr.find_all("td")
        if len(tds) >= 3:
            timestamp_str = tds[0].get_text(strip=True)
            full_msg = tds[2].get_text(strip=True)
            if timestamp_str and full_msg:
                try:
                    fetched_at = timestamp_str
                except ValueError:
                    fetched_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
                msgs.append({"message": full_msg, "fetched_at": fetched_at})
    if not msgs:
        for m in re.finditer(r"([A-Za-z0-9\W\s]{10,})", html_text):
            t = m.group(1).strip()
            if re.search(r"\d{4,8}", t):
                msgs.append({"message": t, "fetched_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")})
    return msgs

def fetch_once():
    entries = []
    try:
        r = session.post(config.GET_SMS_URL, data={"_token": config.CSRF_TOKEN, "from": datetime.now(UTC).date().isoformat(), "to": datetime.now(UTC).date().isoformat()}, timeout=20)
        
        if r.status_code == 419 or r.status_code == 403 or r.status_code == 401:
            db.save_error(f"GET_SMS status {r.status_code} - session/token ya ƙare. Ana ƙoƙarin sake shiga...")
            if login_and_fetch_token():
                print("Sake shiga ya yi nasara. Ana sake gwadawa.")
                r = session.post(config.GET_SMS_URL, data={"_token": config.CSRF_TOKEN, "from": datetime.now(UTC).date().isoformat(), "to": datetime.now(UTC).date().isoformat()}, timeout=20)
            else:
                db.save_error("Sake shiga ya kasa. Za a tsallake wannan zagayen.")
                return entries

        if r.status_code != 200:
            db.save_error(f"GET_SMS status {r.status_code}")
            return entries

        ranges = parse_ranges(r.text)
        if not ranges:
            try:
                j = r.json()
                if isinstance(j, list):
                    ranges = [str(x) for x in j]
            except Exception:
                pass
        
        if not ranges:
            ranges = [""]

        for rng in ranges:
            r2 = session.post(config.GET_NUMBER_URL, data={"_token": config.CSRF_TOKEN, "start": datetime.now(UTC).date().isoformat(), "end": datetime.now(UTC).date().isoformat(), "range": rng}, timeout=20)
            if r2.status_code != 200:
                db.save_error(f"GET_NUMBER failed for range={rng} status={r2.status_code}")
                continue
            numbers = parse_numbers(r2.text)
            if not numbers:
                try:
                    j2 = r2.json()
                    if isinstance(j2, list):
                        for item in j2:
                            if isinstance(item, dict):
                                num = item.get("Number") or item.get("number") or item.get("msisdn")
                                if num:
                                    numbers.append(str(num))
                except Exception:
                    pass

            for number in numbers:
                r3 = session.post(config.GET_OTP_URL, data={"_token": config.CSRF_TOKEN, "start": datetime.now(UTC).date().isoformat(), "Number": number, "Range": rng}, timeout=20)
                if r3.status_code != 200:
                    db.save_error(f"GET_OTP failed number={number} range={rng} status={r3.status_code}")
                    continue
                msgs_and_times = parse_messages_with_timestamps(r3.text)
                if not msgs_and_times:
                    try:
                        j3 = r3.json()
                        if isinstance(j3, list):
                            for it in j3:
                                if isinstance(it, dict):
                                    text = it.get("sms") or it.get("message") or it.get("full")
                                    if text:
                                        msgs_and_times.append({"message": text, "fetched_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")})
                    except Exception:
                        pass
                for item in msgs_and_times:
                    m = item['message']
                    fetched_at = item['fetched_at']
                    otps = extract_otps(m)
                    if not otps:
                        continue
                    
                    # Ɗauki OTP na farko kawai
                    otp = otps[0] 
                    
                    service = detect_service(m)
                    country = detect_country(number, rng)
                    entries.append({
                        "number": number,
                        "otp": otp,
                        "full_msg": m,
                        "service": service,
                        "country": country,
                        "range": rng,
                        "fetched_at": fetched_at
                    })
    except Exception as e:
        db.save_error(f"fetch_once exception: {e}")
    return entries

# Sabon tsarin tura saƙo tare da ingantaccen bayani
async def forward_entry(e):
    num_display = mask_number(e["number"])
    
    # Tsarkake saƙon ta cire duk wani HTML tag da bayanan marasa amfani
    full_msg_text = e.get('full_msg', '')
    
    # Idan saƙon yana da HTML tags, cire su
    if '<' in full_msg_text and '>' in full_msg_text:
        soup = BeautifulSoup(full_msg_text, 'html.parser')
        # Nemo ainihin rubutun saƙon
        message_content = soup.find('p', {'class': 'mb-0'})
        if message_content:
            full_msg_text = message_content.get_text(strip=True)
        else:
            # Idan ba a samu ba, cire duk HTML tags
            full_msg_text = soup.get_text(strip=True)
    
    # Cire duk wani bayanan marasa amfani kamar "SMS received" da sauransu
    if full_msg_text.startswith('SMS received') or full_msg_text.startswith('Message received'):
        # Nemo ainihin saƙon ta hanyar cire farkon kalmomi
        parts = full_msg_text.split(':', 1)
        if len(parts) > 1:
            full_msg_text = parts[1].strip()
    
    full_msg_text = full_msg_text.strip()
    
    # Idan saƙon ya rage gajere sosai ko babu shi, za a saka saƙo mai bayani
    if len(full_msg_text) < 5:
        full_msg_text = "Babu cikakken saƙo da aka samu"
    
    escaped_full_msg = html.escape(full_msg_text)
    otp_to_display = e.get('otp', '')
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")

    # Sabon tsarin saƙo kamar yadda aka buƙata
    text = (
        f"🔔 <b> NEW OTP DETECTED </b>\n🆕\n\n"
        f"🕰 <b>Time:</b> {now}\n"
        f"🌍 <b>Country:</b> {e.get('country')}\n"
        f"⚙️ <b>Service:</b> {e.get('service')}\n"
        f"☎️ <b>Number:</b> {num_display}\n"
        f"🔑 <b>OTP:</b> <code>{otp_to_display}</code>\n\n"
        f"📩 <b>Full Message:</b>\n"
        f"<pre>{escaped_full_msg}</pre>"
    )
    
    # Sabbin maɓallai kamar yadda ka nema
    kb = types.InlineKeyboardMarkup(inline_keyboard=[
        [types.InlineKeyboardButton(text="👑 ×°𝓞𝔀𝓷𝓮𝓻°× 👑", url=config.OWNER_LINK),
         types.InlineKeyboardButton(text="༄ 𝐃𝐞𝐯𝐞𝐥𝐨𝐩𝐞𝐫 𒆜", url="https://t.me/BashOnChain")],
        [types.InlineKeyboardButton(text="★彡[ᴀʟʟ ɴᴜᴍʙᴇʀꜱ]彡★", url="https://t.me/oxfreebackup")]
    ])
    
    try:
        await bot.send_message(config.GROUP_ID, text, reply_markup=kb)
    except Exception as exc:
        db.save_error(f"Gabaɗayan saƙo ya kasa zuwa group: {exc}")
        try:
            await bot.send_message(config.ADMIN_ID, f"Gabaɗayan saƙo ya kasa: {exc}")
        except Exception:
            pass

# worker
async def worker():
    db.set_status("online")
    await bot.send_message(config.ADMIN_ID, "✅ Worker ya fara aiki.")
    global _worker_running
    _worker_running = True
    while _worker_running:
        entries = fetch_once()
        for e in entries:
            if not db.otp_exists(e["number"], e["otp"]):
                db.save_otp(e["number"], e["otp"], e["full_msg"], e["service"], e["country"])
                await forward_entry(e)
        await asyncio.sleep(config.FETCH_INTERVAL)
    db.set_status("offline")
    await bot.send_message(config.ADMIN_ID, "🛑 Worker ya daina aiki.")

def stop_worker_task():
    global _worker_running, _worker_task
    if not _worker_running:
        return
    _worker_running = False
    if _worker_task and not _worker_task.done():
        _worker_task.cancel()

# commands
@dp.message(F.text == "/start")
async def cmd_start(m: types.Message):
    if m.from_user.id != config.ADMIN_ID:
        await m.answer("⛔ Ba ka da izini.")
        return
    st = db.get_status()
    kb = types.InlineKeyboardMarkup(inline_keyboard=[
        [types.InlineKeyboardButton(text="▶️ Fara", callback_data="start_worker"),
         types.InlineKeyboardButton(text="⏸ Tsaya", callback_data="stop_worker")],
        [types.InlineKeyboardButton(text="🧹 Share DB", callback_data="clear_db"),
         types.InlineKeyboardButton(text="❗ Kurakurai", callback_data="show_errors")],
        [types.InlineKeyboardButton(text="🔄 Sake shiga", callback_data="relogin")]
    ])
    await m.answer(f"⚙️ <b>OTP Receiver</b>\nStatus: <b>{st}</b>\nStored OTPs: <b>{db.count_otps()}</b>", reply_markup=kb)

@dp.callback_query()
async def cb(q: types.CallbackQuery):
    if q.from_user.id != config.ADMIN_ID:
        await q.answer("⛔ Ba ka da izini", show_alert=True)
        return
    if q.data == "start_worker":
        global _worker_task
        if _worker_task is None or _worker_task.done():
            _worker_task = asyncio.create_task(worker())
            await q.message.answer("✅ Worker ya fara aiki.")
        else:
            await q.message.answer("ℹ️ Worker yana aiki tuni.")
        await q.answer()
    elif q.data == "stop_worker":
        stop_worker_task()
        await q.message.answer("🛑 Worker yana tsayawa...")
        await q.answer()
    elif q.data == "clear_db":
        db.clear_otps()
        await q.message.answer("🗑 OTP DB an share shi.")
        await q.answer()
    elif q.data == "show_errors":
        rows = db.get_errors(10)
        if not rows:
            await q.message.answer("✅ Babu kurakurai da aka rubuta.")
        else:
            text = "\n\n".join([f"{r[1]} — {r[0]}" for r in rows])
            await q.message.answer(f"<b>Kurakurai na ƙarshe</b>:\n\n{text}")
        await q.answer()
    elif q.data == "relogin":
        if login_and_fetch_token():
            await q.message.answer("✅ Sake shiga na hannu ya yi nasara!")
        else:
            await q.message.answer("❌ Sake shiga na hannu ya kasa! Duba logs.")
        await q.answer()

@dp.message(F.text == "/on")
async def cmd_on(m: types.Message):
    if m.from_user.id != config.ADMIN_ID:
        await m.answer("⛔ Ba ka da izini.")
        return
    global _worker_task
    if _worker_task is None or _worker_task.done():
        _worker_task = asyncio.create_task(worker())
        await m.answer("✅ Worker ya fara aiki.")
    else:
        await m.answer("ℹ️ Worker yana aiki tuni.")

@dp.message(F.text == "/off")
async def cmd_off(m: types.Message):
    if m.from_user.id != config.ADMIN_ID:
        await m.answer("⛔ Ba ka da izini.")
        return
    stop_worker_task()
    await m.answer("🛑 Worker yana tsayawa...")

@dp.message(F.text == "/status")
async def cmd_status(m: types.Message):
    if m.from_user.id != config.ADMIN_ID:
        await m.answer("⛔ Ba ka da izini.")
        return
    await m.answer(f"📡 Status: <b>{db.get_status()}</b>\n📥 OTPs da aka ajiye: <b>{db.count_otps()}</b>")

@dp.message(F.text == "/check")
async def cmd_check(m: types.Message):
    if m.from_user.id != config.ADMIN_ID:
        await m.answer("⛔ Ba ka da izini.")
        return
    await m.answer(f"OTPs da aka ajiye: <b>{db.count_otps()}</b>")

@dp.message(F.text == "/clear")
async def cmd_clear(m: types.Message):
    if m.from_user.id != config.ADMIN_ID:
        await m.answer("⛔ Ba ka da izini.")
        return
    db.clear_otps()
    await m.answer("🗑 OTP DB an share shi.")

@dp.message(F.text == "/errors")
async def cmd_errors(m: types.Message):
    if m.from_user.id != config.ADMIN_ID:
        await m.answer("⛔ Ba ka da izini.")
        return
    rows = db.get_errors(20)
    if not rows:
        await m.answer("✅ Babu kurakurai da aka rubuta.")
    else:
        text = "\n\n".join([f"{r[1]} — {r[0]}" for r in rows])
        await m.answer(f"<b>Kurakurai na ƙarshe</b>:\n\n{text}")

async def on_startup():
    print("Ana ƙoƙarin shiga da karɓar sabon zaman/token a farkon aiki.")
    if login_and_fetch_token():
        print("Shiga na farko ya yi nasara.")
    else:
        print("Shiga na farko ya kasa. Bot bazai iya aiki yadda ya kamata ba.")
        db.save_error("Shiga na farko ya kasa. Bot bazai iya aiki yadda ya kamata ba.")

    if db.get_status() == "online":
        global _worker_task
        _worker_task = asyncio.create_task(worker())

if __name__ == "__main__":
    try:
        import logging
        logging.basicConfig(level=logging.INFO)
        dp.startup.register(on_startup)
        dp.run_polling(bot)
    except KeyboardInterrupt:
        print("Fita...")
