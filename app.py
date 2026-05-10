from flask import Flask, send_from_directory, request, jsonify
import json, os, time

app = Flask(__name__, static_folder='.', static_url_path='')

MENU_FILE = 'custom_menu.json'
ADMIN_PASS = 'Tort@Praha51'

def load_custom():
    try:
        if os.path.exists(MENU_FILE):
            with open(MENU_FILE, encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        pass
    return []

def save_custom(items):
    with open(MENU_FILE, 'w', encoding='utf-8') as f:
        json.dump(items, f, ensure_ascii=False, indent=2)

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/api/menu', methods=['GET'])
def api_get():
    return jsonify(load_custom())

@app.route('/api/menu', methods=['POST'])
def api_add():
    d = request.get_json(force=True, silent=True) or {}
    if d.get('pass') != ADMIN_PASS:
        return jsonify({'error': 'Unauthorized'}), 401
    name_cs = (d.get('name_cs') or '').strip()
    if not name_cs:
        return jsonify({'error': 'name_cs required'}), 400
    item = {
        'id': int(time.time() * 1000),
        'cat': d.get('cat', 'desserts'),
        'price': (d.get('price') or '').strip(),
        'badge': (d.get('badge') or '').strip(),
        'img': (d.get('img') or '').strip(),
        'name': {
            'cs': name_cs,
            'uk': (d.get('name_uk') or '').strip() or name_cs,
            'en': (d.get('name_en') or '').strip() or name_cs
        },
        'desc': {
            'cs': (d.get('desc_cs') or '').strip(),
            'uk': (d.get('desc_uk') or '').strip() or (d.get('desc_cs') or '').strip(),
            'en': (d.get('desc_en') or '').strip() or (d.get('desc_cs') or '').strip()
        }
    }
    items = load_custom()
    items.append(item)
    save_custom(items)
    return jsonify({'ok': True, 'item': item})

@app.route('/api/menu/<int:item_id>', methods=['DELETE'])
def api_delete(item_id):
    d = request.get_json(force=True, silent=True) or {}
    if d.get('pass') != ADMIN_PASS:
        return jsonify({'error': 'Unauthorized'}), 401
    items = [i for i in load_custom() if i.get('id') != item_id]
    save_custom(items)
    return jsonify({'ok': True})

@app.route('/<path:path>')
def serve(path):
    return send_from_directory('.', path)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
