"""
LICENSE SERVER - SoundOn Upload
================================
Chạy file này trên máy chủ hoặc VPS của bạn.
Người thuê khi mở app sẽ gọi về server này để xác thực key.

Cài đặt:
    pip install flask

Chạy:
    python license_server.py

Mặc định chạy ở port 5001.
Bạn nên deploy lên server/VPS và dùng tên miền hoặc IP tĩnh.
Sau đó cập nhật LICENSE_SERVER_URL trong app.py của người thuê.
"""

import json, os, secrets, string, hashlib
from datetime import datetime, timedelta
from flask import Flask, request, jsonify

app = Flask(__name__)

# ============================================================
# CONFIG - ĐỔI MẬT KHẨU ADMIN TRƯỚC KHI DÙNG!
# ============================================================
ADMIN_PASSWORD = "Phamhuan113@"   # <-- ĐỔI CÁI NÀY
KEYS_FILE = "license_keys.json"                   # File lưu danh sách key
SECRET_SALT = "soundon_salt_abc123xyz"            # Salt bảo mật (không đổi sau khi dùng)


# ============================================================
# HELPERS
# ============================================================
def load_keys():
    if os.path.exists(KEYS_FILE):
        with open(KEYS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_keys(keys):
    with open(KEYS_FILE, "w", encoding="utf-8") as f:
        json.dump(keys, f, indent=2, ensure_ascii=False)


def generate_key():
    """Tạo key dạng: XXXX-XXXX-XXXX-XXXX"""
    chars = string.ascii_uppercase + string.digits
    segments = [''.join(secrets.choice(chars) for _ in range(4)) for _ in range(4)]
    return '-'.join(segments)


def hash_key(key: str) -> str:
    """Hash key để lưu an toàn"""
    return hashlib.sha256((key + SECRET_SALT).encode()).hexdigest()


def check_admin(req):
    return req.headers.get("X-Admin-Password") == ADMIN_PASSWORD


# ============================================================
# PUBLIC API - App của người thuê gọi vào đây
# ============================================================

@app.route("/api/verify", methods=["POST"])
def verify_key():
    """App gọi để xác thực key khi khởi động"""
    data = request.get_json(silent=True) or {}
    key = data.get("key", "").strip().upper()
    machine_id = data.get("machine_id", "")

    if not key:
        return jsonify({"valid": False, "message": "Không có key"}), 400

    keys = load_keys()
    key_hash = hash_key(key)

    if key_hash not in keys:
        return jsonify({"valid": False, "message": "Key không tồn tại hoặc không hợp lệ"}), 200

    info = keys[key_hash]

    # Kiểm tra key đã bị vô hiệu hóa
    if info.get("disabled"):
        return jsonify({"valid": False, "message": "Key đã bị vô hiệu hóa"}), 200

    # Kiểm tra hạn
    expire_date = datetime.fromisoformat(info["expire_date"])
    now = datetime.now()
    if now > expire_date:
        return jsonify({
            "valid": False,
            "message": f"Key đã hết hạn từ {expire_date.strftime('%d/%m/%Y')}. Vui lòng liên hệ để gia hạn."
        }), 200

    # Kiểm tra machine binding (nếu key đã bind máy)
    if info.get("machine_id") and info["machine_id"] != machine_id:
        return jsonify({
            "valid": False,
            "message": "Key này đã được kích hoạt trên máy khác. Liên hệ admin để reset."
        }), 200

    # Bind máy nếu chưa bind
    if not info.get("machine_id") and machine_id:
        info["machine_id"] = machine_id
        info["first_activated"] = now.isoformat()

    # Cập nhật lần dùng cuối
    info["last_check"] = now.isoformat()
    info["check_count"] = info.get("check_count", 0) + 1
    keys[key_hash] = info
    save_keys(keys)

    days_left = (expire_date - now).days
    return jsonify({
        "valid": True,
        "message": "OK",
        "customer": info.get("customer", ""),
        "expire_date": expire_date.strftime("%d/%m/%Y"),
        "days_left": days_left,
    }), 200


# ============================================================
# ADMIN API - Chỉ bạn dùng để quản lý key
# ============================================================

@app.route("/admin/create", methods=["POST"])
def create_key():
    """Tạo key mới cho người thuê"""
    if not check_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    days = int(data.get("days", 30))
    customer = data.get("customer", "")  # Tên khách hàng để ghi nhớ
    note = data.get("note", "")

    key = generate_key()
    key_hash = hash_key(key)
    expire_date = datetime.now() + timedelta(days=days)

    keys = load_keys()
    keys[key_hash] = {
        "customer": customer,
        "note": note,
        "created": datetime.now().isoformat(),
        "expire_date": expire_date.isoformat(),
        "days": days,
        "machine_id": None,
        "first_activated": None,
        "last_check": None,
        "check_count": 0,
        "disabled": False,
    }
    save_keys(keys)

    return jsonify({
        "key": key,  # Chỉ hiện 1 lần, server không lưu key gốc!
        "customer": customer,
        "expire_date": expire_date.strftime("%d/%m/%Y"),
        "days": days,
    }), 200


@app.route("/admin/list", methods=["GET"])
def list_keys():
    """Xem danh sách tất cả key"""
    if not check_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    keys = load_keys()
    now = datetime.now()
    result = []
    for key_hash, info in keys.items():
        expire_date = datetime.fromisoformat(info["expire_date"])
        result.append({
            "key_hash": key_hash[:8] + "...",  # Chỉ hiện 8 ký tự đầu
            "customer": info.get("customer", ""),
            "note": info.get("note", ""),
            "expire_date": expire_date.strftime("%d/%m/%Y"),
            "days_left": max(0, (expire_date - now).days),
            "status": "Hết hạn" if now > expire_date else ("Vô hiệu" if info.get("disabled") else "Hoạt động"),
            "machine_id": info.get("machine_id", "Chưa kích hoạt"),
            "check_count": info.get("check_count", 0),
            "last_check": info.get("last_check", "")[:16] if info.get("last_check") else "Chưa dùng",
            "first_activated": info.get("first_activated", "")[:16] if info.get("first_activated") else "Chưa",
        })
    # Sắp xếp theo ngày hết hạn
    result.sort(key=lambda x: x["expire_date"])
    return jsonify({"total": len(result), "keys": result}), 200


@app.route("/admin/extend", methods=["POST"])
def extend_key():
    """Gia hạn key thêm N ngày"""
    if not check_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    key = data.get("key", "").strip().upper()
    days = int(data.get("days", 30))

    keys = load_keys()
    key_hash = hash_key(key)

    if key_hash not in keys:
        return jsonify({"error": "Key không tồn tại"}), 404

    info = keys[key_hash]
    old_expire = datetime.fromisoformat(info["expire_date"])
    # Nếu key đã hết hạn thì tính từ hôm nay, nếu còn hạn thì cộng thêm
    base = max(old_expire, datetime.now())
    new_expire = base + timedelta(days=days)
    info["expire_date"] = new_expire.isoformat()
    info["disabled"] = False
    keys[key_hash] = info
    save_keys(keys)

    return jsonify({
        "customer": info.get("customer", ""),
        "new_expire_date": new_expire.strftime("%d/%m/%Y"),
        "extended_days": days,
    }), 200


@app.route("/admin/disable", methods=["POST"])
def disable_key():
    """Vô hiệu hóa key (khóa ngay lập tức)"""
    if not check_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    key = data.get("key", "").strip().upper()

    keys = load_keys()
    key_hash = hash_key(key)

    if key_hash not in keys:
        return jsonify({"error": "Key không tồn tại"}), 404

    keys[key_hash]["disabled"] = True
    save_keys(keys)
    return jsonify({"message": f"Đã vô hiệu hóa key của: {keys[key_hash].get('customer', '')}"}), 200


@app.route("/admin/reset-machine", methods=["POST"])
def reset_machine():
    """Reset binding máy (khi khách đổi máy)"""
    if not check_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    key = data.get("key", "").strip().upper()

    keys = load_keys()
    key_hash = hash_key(key)

    if key_hash not in keys:
        return jsonify({"error": "Key không tồn tại"}), 404

    keys[key_hash]["machine_id"] = None
    keys[key_hash]["first_activated"] = None
    save_keys(keys)
    return jsonify({"message": "Đã reset binding máy. Khách có thể kích hoạt lại trên máy mới."}), 200


# ============================================================
# ADMIN WEB UI - Giao diện quản lý đơn giản
# ============================================================
@app.route("/admin", methods=["GET"])
def admin_ui():
    """Giao diện HTML đơn giản để quản lý key"""
    html = """<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<title>License Manager - SoundOn</title>
<style>
body{font-family:Arial,sans-serif;background:#1a1a2e;color:#eee;padding:20px;max-width:1000px;margin:0 auto}
h1{color:#e94560}h2{color:#0f3460;background:#16213e;padding:10px;border-radius:5px}
input,select{background:#16213e;border:1px solid #0f3460;color:#eee;padding:8px;border-radius:4px;width:200px}
button{background:#e94560;color:#fff;border:none;padding:9px 18px;border-radius:4px;cursor:pointer;margin:4px}
button:hover{background:#c73652}
.card{background:#16213e;border-radius:8px;padding:15px;margin:15px 0}
.result{background:#0f3460;padding:10px;border-radius:4px;font-family:monospace;white-space:pre-wrap;margin-top:10px}
label{display:inline-block;width:130px;color:#aaa}
</style>
</head>
<body>
<h1>🔑 License Manager - SoundOn Upload</h1>
<p>Nhập mật khẩu admin vào tất cả các form để sử dụng.</p>

<div class="card">
<h2>➕ Tạo Key Mới</h2>
<div><label>Admin Password:</label><input id="c_pass" type="password" placeholder="Mật khẩu admin"></div>
<div><label>Tên khách hàng:</label><input id="c_cust" placeholder="VD: Nguyen Van A"></div>
<div><label>Số ngày:</label><input id="c_days" type="number" value="30" style="width:80px"></div>
<div><label>Ghi chú:</label><input id="c_note" placeholder="(tuỳ chọn)"></div>
<button onclick="createKey()">Tạo Key</button>
<div class="result" id="c_result">Kết quả hiện ở đây...</div>
</div>

<div class="card">
<h2>📋 Danh Sách Key</h2>
<div><label>Admin Password:</label><input id="l_pass" type="password" placeholder="Mật khẩu admin"></div>
<button onclick="listKeys()">Tải Danh Sách</button>
<div class="result" id="l_result">Danh sách hiện ở đây...</div>
</div>

<div class="card">
<h2>🔄 Gia Hạn Key</h2>
<div><label>Admin Password:</label><input id="e_pass" type="password" placeholder="Mật khẩu admin"></div>
<div><label>Key:</label><input id="e_key" placeholder="XXXX-XXXX-XXXX-XXXX"></div>
<div><label>Thêm số ngày:</label><input id="e_days" type="number" value="30" style="width:80px"></div>
<button onclick="extendKey()">Gia Hạn</button>
<div class="result" id="e_result">Kết quả hiện ở đây...</div>
</div>

<div class="card">
<h2>🔧 Công Cụ Khác</h2>
<div><label>Admin Password:</label><input id="o_pass" type="password" placeholder="Mật khẩu admin"></div>
<div><label>Key:</label><input id="o_key" placeholder="XXXX-XXXX-XXXX-XXXX"></div>
<button onclick="disableKey()">🚫 Vô Hiệu Hóa</button>
<button onclick="resetMachine()">🖥️ Reset Máy</button>
<div class="result" id="o_result">Kết quả hiện ở đây...</div>
</div>

<script>
async function api(url, method, pass, body){
    const r = await fetch(url,{method,headers:{'Content-Type':'application/json','X-Admin-Password':pass},body:JSON.stringify(body)});
    return r.json();
}
async function createKey(){
    const r = await api('/admin/create','POST',document.getElementById('c_pass').value,{
        customer:document.getElementById('c_cust').value,
        days:+document.getElementById('c_days').value,
        note:document.getElementById('c_note').value
    });
    document.getElementById('c_result').textContent = r.error ? '❌ '+r.error : 
        `✅ KEY: ${r.key}\\nKhách: ${r.customer}\\nHết hạn: ${r.expire_date} (${r.days} ngày)\\n\\n⚠️ Sao chép key ngay! Server không lưu key gốc.`;
}
async function listKeys(){
    const r = await api('/admin/list','GET',document.getElementById('l_pass').value);
    if(r.error){document.getElementById('l_result').textContent='❌ '+r.error;return;}
    let txt = `Tổng: ${r.total} key\\n${'='.repeat(80)}\\n`;
    for(const k of r.keys){
        txt += `👤 ${k.customer||'(không tên)'} | ${k.status} | Hết hạn: ${k.expire_date} (còn ${k.days_left} ngày)\\n`;
        txt += `   Máy: ${k.machine_id} | Kích hoạt: ${k.first_activated} | Lần check cuối: ${k.last_check} (${k.check_count} lần)\\n`;
        txt += `   Ghi chú: ${k.note||'—'}\\n${'─'.repeat(80)}\\n`;
    }
    document.getElementById('l_result').textContent = txt;
}
async function extendKey(){
    const r = await api('/admin/extend','POST',document.getElementById('e_pass').value,{
        key:document.getElementById('e_key').value,days:+document.getElementById('e_days').value
    });
    document.getElementById('e_result').textContent = r.error ? '❌ '+r.error :
        `✅ Gia hạn thành công!\\nKhách: ${r.customer}\\nHết hạn mới: ${r.new_expire_date} (+${r.extended_days} ngày)`;
}
async function disableKey(){
    if(!confirm('Chắc chắn vô hiệu hóa key này?'))return;
    const r = await api('/admin/disable','POST',document.getElementById('o_pass').value,{key:document.getElementById('o_key').value});
    document.getElementById('o_result').textContent = r.error ? '❌ '+r.error : '✅ '+r.message;
}
async function resetMachine(){
    const r = await api('/admin/reset-machine','POST',document.getElementById('o_pass').value,{key:document.getElementById('o_key').value});
    document.getElementById('o_result').textContent = r.error ? '❌ '+r.error : '✅ '+r.message;
}
</script>
</body>
</html>"""
    return html


if __name__ == "__main__":
    print("=" * 50)
    print("  License Server - SoundOn Upload")
    print(f"  Admin UI: http://localhost:5001/admin")
    print(f"  Verify API: http://localhost:5001/api/verify")
    print("=" * 50)
    app.run(host="0.0.0.0", port=5001, debug=False)
