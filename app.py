from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_socketio import SocketIO, emit
import uuid
import webbrowser
import threading
from werkzeug.security import generate_password_hash
from firebase_config import firestore_db, firestore
from modules.users import get_all_users, get_user, create_user, update_user, delete_user, verify_user
from modules.magazyny import get_all_magazyny, create_magazyn, update_magazyn as update_magazyn_fn, delete_magazyn as delete_magazyn_fn
from modules.linie import filter_zgloszenia, add_zgloszenie as add_zgloszenie_fn, update_zgloszenie as update_zgloszenie_fn, get_statusy, get_all_zgloszenia, delete_zgloszenie_fn, get_zgloszenie_by_id
from modules.przyjazdy import get_przyjazdy, store_przyjazd, update_przyjazd_hidden, synchronize_przyjazdy
import logging
import os
import sys

# Konfiguracja dla PyInstaller
if getattr(sys, 'frozen', False):
    template_folder = os.path.join(sys._MEIPASS, 'templates')
    static_folder = os.path.join(sys._MEIPASS, 'static')
    app = Flask(__name__, template_folder=template_folder, static_folder=static_folder)
else:
    app = Flask(__name__)

logging.basicConfig(level=logging.DEBUG)

app.config['SECRET_KEY'] = 'tajny_klucz_aplikacji'

# Używamy threading jako async_mode - jest najbardziej kompatybilny z PyInstaller
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Inicjalizacja danych – jeżeli baza Firestore jest pusta, utworzymy domyślnego admina oraz magazyny.
def init_data():
    users = get_all_users()
    if not users:
        create_user("admin", "admin123", "admin", None, [])
    magazyny = get_all_magazyny()
    if not magazyny:
        default_magazyny = ["Warszawa", "Kraków", "Poznań", "Gdańsk", "Wrocław", "Łódź", "Szczecin"]
        for m in default_magazyny:
            create_magazyn(m)
        for m in default_magazyny:
            username = f"dyspozytor_{m.lower()}"
            if not get_user(username):
                create_user(username, f"pass_{m.lower()}", "dyspozytor", m, [m])

init_data()

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    user = get_user(username)
    if not user:
        session.clear()
        return redirect(url_for('login'))
    user_role = user['role']
    user_magazyn = user.get('magazyn')
    user_magazyny = user.get('magazyny', [])
    magazyny = get_all_magazyny()
    return render_template('index.html', username=username, user_role=user_role, user_magazyn=user_magazyn,
                          user_magazyny=user_magazyny, magazyny=magazyny)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if get_user(username) and verify_user(username, password):
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Nieprawidłowe dane logowania")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/admin/magazyny')
def admin_magazyny():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    user = get_user(username)
    if user['role'] != 'admin':
        return redirect(url_for('index'))
    magazyny = get_all_magazyny()
    return render_template('admin_magazyny.html', username=username, user_role=user['role'], magazyny=magazyny)

@app.route('/admin/users')
def admin_users():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    user = get_user(username)
    if user['role'] != 'admin':
        return redirect(url_for('index'))
    users = get_all_users()
    magazyny = get_all_magazyny()
    # Usuwamy hashe haseł przed wyświetleniem
    for u in users:
        users[u].pop('password', None)
    return render_template('admin_users.html', username=username, user_role=user['role'], users=users, magazyny=magazyny)

@app.route('/api/zgloszenia', methods=['GET'])
def api_zgloszenia():
    if 'username' not in session:
        logging.warning("Brak zalogowania przy /api/zgloszenia")
        return jsonify({"error": "Nie zalogowano"}), 401

    data_param = request.args.get('data')
    magazyny_param = request.args.get('magazyny')
    logging.info(f"api_zgloszenia: data_param={data_param}, magazyny_param={magazyny_param}")
    
    if not data_param:
        logging.error("Brak parametru 'data' w /api/zgloszenia")
        return jsonify({"error": "Brak parametru data"}), 400

    username = session['username']
    user = get_user(username)
    logging.debug(f"Użytkownik: {username}, rola: {user['role']}, magazyny: {user.get('magazyny', [])}")
    
    try:
        filtered = filter_zgloszenia(data_param, user['role'], user.get('magazyny', []), magazyny_param)
        logging.info(f"Liczba filtrowanych zgłoszeń: {len(filtered)}")
        return jsonify(filtered)
    except Exception as e:
        logging.exception("Błąd podczas filtrowania zgłoszeń")
        return jsonify({"error": f"Błąd: {str(e)}"}), 500


@app.route('/api/przyjazdy', methods=['GET'])
def api_przyjazdy():
    if 'username' not in session:
        logging.warning("Brak zalogowania przy /api/przyjazdy")
        return jsonify({"error": "Nie zalogowano"}), 401

    data_param = request.args.get('data')
    magazyny_param = request.args.get('magazyny')
    logging.info(f"api_przyjazdy: data_param={data_param}, magazyny_param={magazyny_param}")
    
    if not data_param:
        logging.error("Brak parametru 'data' w /api/przyjazdy")
        return jsonify({"error": "Brak parametru data"}), 400

    username = session['username']
    user = get_user(username)
    logging.debug(f"Użytkownik: {username}, rola: {user['role']}, magazyny: {user.get('magazyny', [])}")
    
    try:
        # Get arrivals using Firestore
        przyjazdy = get_przyjazdy(data_param, user['role'], user.get('magazyny', []), magazyny_param)
        logging.info(f"Liczba znalezionych przyjazdów: {len(przyjazdy)}")
        return jsonify(przyjazdy)
    except Exception as e:
        logging.exception("Błąd podczas pobierania przyjazdów")
        return jsonify({"error": f"Błąd: {str(e)}"}), 500


@app.route('/api/zgloszenia-statusy', methods=['GET'])
def api_zgloszenia_statusy():
    if 'username' not in session:
        logging.warning("Brak zalogowania przy /api/zgloszenia-statusy")
        return jsonify({"error": "Nie zalogowano"}), 401

    start_date = request.args.get('start')
    end_date = request.args.get('end')
    magazyny_param = request.args.get('magazyny')
    logging.info(f"api_zgloszenia-statusy: start_date={start_date}, end_date={end_date}, magazyny_param={magazyny_param}")
    
    if not start_date or not end_date:
        logging.error("Brak parametrów zakresu dat przy /api/zgloszenia-statusy")
        return jsonify({"error": "Brak parametrów zakresu dat"}), 400

    username = session['username']
    user = get_user(username)
    try:
        statusy = get_statusy(start_date, end_date, user['role'], user.get('magazyny', []), magazyny_param)
        logging.info(f"Statusy dla zakresu: {statusy}")
        return jsonify(statusy)
    except Exception as e:
        logging.exception("Błąd podczas pobierania statusów zgłoszeń")
        return jsonify({"error": f"Błąd: {str(e)}"}), 500


@app.route('/api/zgloszenie', methods=['POST'])
def api_add_zgloszenie():
    if 'username' not in session:
        logging.warning("Brak zalogowania przy dodawaniu zgłoszenia")
        return jsonify({"error": "Nie zalogowano"}), 401

    username = session['username']
    user = get_user(username)
    if user['role'] != 'dyspozytor':
        logging.warning(f"Użytkownik {username} nie ma uprawnień do dodawania zgłoszenia")
        return jsonify({"error": "Brak uprawnień"}), 403

    data = request.json
    logging.info(f"Otrzymano dane do dodania zgłoszenia: {data}")
    
    required_fields = ['data', 'magazyn_wyjazdowy', 'magazyn_koncowy', 'linia', 'godzina_wyjazdu']
    for field in required_fields:
        if field not in data or not data[field]:
            logging.error(f"Brak wymaganego pola: {field}")
            return jsonify({"error": f"Brak wymaganego pola: {field}"}), 400

    if data.get('magazyn_wyjazdowy') == data.get('magazyn_koncowy'):
        logging.error("Magazyn wyjazdowy nie może być taki sam jak końcowy")
        return jsonify({"error": "Magazyn wyjazdowy nie może być taki sam jak końcowy"}), 400

    new_zgloszenie = {
        'id': str(uuid.uuid4()),
        'data': data['data'],
        'magazyn_wyjazdowy': data['magazyn_wyjazdowy'],
        'magazyn_koncowy': data['magazyn_koncowy'],
        'linia': data['linia'],
        'godzina_wyjazdu': data['godzina_wyjazdu'],
        'kierowca': '',
        'nr_rejestracyjny': '',
        'opis': '',
        'status': 'Nowe',
        'created_by': username,  # <-- DODANE pole informujące o autorze zgłoszenia
        'hidden': False
    }

    try:
        add_zgloszenie_fn(new_zgloszenie)
        logging.info(f"Zgłoszenie dodane, id: {new_zgloszenie['id']}")
        socketio.emit('new_zgloszenie', new_zgloszenie)
        socketio.emit('status_update')
        return jsonify({"success": True, "id": new_zgloszenie["id"]})
    except Exception as e:
        logging.exception("Błąd podczas dodawania zgłoszenia")
        return jsonify({"error": f"Błąd podczas dodawania zgłoszenia: {str(e)}"}), 500

@app.route('/api/zgloszenie/<zgloszenie_id>/hide', methods=['PUT'])
def api_hide_zgloszenie(zgloszenie_id):
    if 'username' not in session:
        logging.warning("Brak zalogowania przy ukrywaniu zgłoszenia")
        return jsonify({"error": "Nie zalogowano"}), 401

    username = session['username']
    user = get_user(username)
    if user['role'] not in ['admin', 'dyspozytor']:
        logging.warning(f"Użytkownik {username} nie ma uprawnień do ukrywania zgłoszenia")
        return jsonify({"error": "Brak uprawnień"}), 403

    data = request.json
    hidden = data.get('hidden', True)
    
    try:
        # Update the hidden status in both Realtime DB and Firestore
        # Realtime DB for consistency with other operations
        success_realtime = update_zgloszenie_fn(zgloszenie_id, {"hidden": hidden})
        
        # Firestore for the arrivals
        success_firestore = update_przyjazd_hidden(zgloszenie_id, hidden)
        
        if success_realtime or success_firestore:
            logging.info(f"Zgłoszenie {zgloszenie_id} zostało {'ukryte' if hidden else 'odkryte'}")
            return jsonify({"success": True})
        else:
            logging.error(f"Zgłoszenie {zgloszenie_id} nie zostało znalezione")
            return jsonify({"error": "Nie znaleziono zgłoszenia"}), 404
    except Exception as e:
        logging.exception(f"Błąd podczas ukrywania zgłoszenia {zgloszenie_id}")
        return jsonify({"error": f"Błąd: {str(e)}"}), 500

@app.route('/api/zgloszenie/<zgloszenie_id>', methods=['DELETE'])
def api_delete_zgloszenie(zgloszenie_id):
    if 'username' not in session:
        logging.warning("Brak zalogowania przy usuwaniu zgłoszenia")
        return jsonify({"error": "Nie zalogowano"}), 401

    username = session['username']
    user = get_user(username)
    if user['role'] != 'admin':
        logging.warning(f"Użytkownik {username} nie ma uprawnień do usuwania zgłoszenia")
        return jsonify({"error": "Brak uprawnień"}), 403

    try:
        success = delete_zgloszenie_fn(zgloszenie_id)
        if success:
            logging.info(f"Zgłoszenie {zgloszenie_id} zostało usunięte przez {username}")
            socketio.emit('delete_zgloszenie', {"id": zgloszenie_id})
            return jsonify({"success": True})
        else:
            logging.error(f"Zgłoszenie {zgloszenie_id} nie zostało znalezione")
            return jsonify({"error": "Nie znaleziono zgłoszenia"}), 404
    except Exception as e:
        logging.exception(f"Błąd podczas usuwania zgłoszenia {zgloszenie_id}")
        return jsonify({"error": f"Błąd podczas usuwania zgłoszenia: {str(e)}"}), 500

@app.route('/admin/logs')
def admin_logs():
    if 'username' not in session:
        logging.warning("Brak zalogowania przy przeglądaniu logów")
        return redirect(url_for('login'))
    
    username = session['username']
    user = get_user(username)
    if user['role'] != 'admin':
        logging.warning(f"Użytkownik {username} nie ma uprawnień do przeglądania logów")
        return redirect(url_for('index'))
    
    try:
        # Pobierz logi z kolekcji "logs", sortując malejąco po timestamp
        logs_ref = firestore_db.collection("logs").order_by("timestamp", direction=firestore.Query.DESCENDING)
        docs = logs_ref.stream()
        logs = []
        for doc in docs:
            log_data = doc.to_dict()
            log_data['id'] = doc.id
            logs.append(log_data)
        logging.info(f"Pobrano {len(logs)} logów")
        return render_template('admin_logs.html', logs=logs)
    except Exception as e:
        logging.exception("Błąd podczas pobierania logów")
        return jsonify({"error": f"Błąd podczas pobierania logów: {str(e)}"}), 500
    
def log_action(action, details=None):
    """
    Loguje akcję w kolekcji 'logs' w Firestore.
    :param action: Opis akcji, np. "ADD_ZGLOSZENIE", "DELETE_ZGLOSZENIE", "UPDATE_USER", itp.
    :param details: Dodatkowe informacje (słownik), np. id wpisu czy inne dane.
    """
    try:
        firestore_db.collection("logs").add({
            "action": action,
            "details": details,
            "timestamp": firestore.SERVER_TIMESTAMP,
            "user": session.get('username')
        })
        logging.info(f"Zalogowano akcję: {action} dla użytkownika: {session.get('username')}")
    except Exception as e:
        logging.exception(f"Błąd podczas logowania akcji: {action}")

@app.route('/api/zgloszenie/<zgloszenie_id>', methods=['PUT'])
def api_update_zgloszenie(zgloszenie_id):
    if 'username' not in session:
        logging.warning("Brak zalogowania przy aktualizacji zgłoszenia")
        return jsonify({"error": "Nie zalogowano"}), 401

    username = session['username']
    user = get_user(username)
    
    # Pozwalamy na edycję tylko adminom i dyspozytorom
    if user['role'] not in ['admin', 'dyspozytor']:
        logging.warning(f"Użytkownik {username} nie ma uprawnień do aktualizacji zgłoszenia")
        return jsonify({"error": "Brak uprawnień"}), 403

    data = request.json
    logging.info(f"Aktualizacja zgłoszenia {zgloszenie_id} danymi: {data}")
    
    update_fields = {}
    
    # Include existing fields
    for field in ['kierowca', 'nr_rejestracyjny', 'opis', 'godzina_wyjazdu']:
        if field in data:
            update_fields[field] = data[field]
    
    # Add new fields
    for field in ['data', 'data_przyjazdu', 'godzina_przyjazdu']:
        if field in data:
            update_fields[field] = data[field]
    
    # If arrival date and time are provided, add arrival record to Firestore
    if 'data_przyjazdu' in update_fields and 'godzina_przyjazdu' in update_fields:
        try:
            # Get the full zgloszenie data first
            zgloszenie = get_zgloszenie_by_id(zgloszenie_id)
            if zgloszenie:
                # Update with the new fields
                zgloszenie.update(update_fields)
                # Store in Firestore for incoming vehicles
                store_przyjazd(zgloszenie)
        except Exception as e:
            logging.exception(f"Błąd podczas dodawania wpisu przyjazdu: {e}")
            # Continue with the update even if storing przyjazd fails
    
    # Set status to "Przydzielone" if both driver and registration are provided
    if (
        update_fields.get('kierowca') and 
        update_fields.get('nr_rejestracyjny')
    ):
        update_fields['status'] = 'Przydzielone'
    
    try:
        if update_zgloszenie_fn(zgloszenie_id, update_fields):
            logging.info(f"Zgłoszenie {zgloszenie_id} zostało zaktualizowane")
            socketio.emit('update_zgloszenie', {"id": zgloszenie_id, **update_fields})
            socketio.emit('status_update')
            return jsonify({"success": True})
        else:
            logging.error(f"Zgłoszenie {zgloszenie_id} nie zostało znalezione")
            return jsonify({"error": "Nie znaleziono zgłoszenia"}), 404
    except Exception as e:
        logging.exception(f"Błąd podczas aktualizacji zgłoszenia {zgloszenie_id}")
        return jsonify({"error": f"Błąd podczas aktualizacji: {str(e)}"}), 500

@app.route('/api/magazyny', methods=['GET', 'POST', 'PUT', 'DELETE'])
def api_magazyny_route():
    if 'username' not in session:
        return jsonify({"error": "Nie zalogowano"}), 401
    username = session['username']
    user = get_user(username)
    if user['role'] != 'admin':
        return jsonify({"error": "Brak uprawnień"}), 403
    if request.method == 'GET':
        return jsonify(get_all_magazyny())
    elif request.method == 'POST':
        data = request.json
        new_magazyn = data.get('nazwa')
        if not new_magazyn:
            return jsonify({"error": "Brak nazwy magazynu"}), 400
        if new_magazyn in get_all_magazyny():
            return jsonify({"error": "Magazyn o tej nazwie już istnieje"}), 400
        create_magazyn(new_magazyn)
        # Utworzenie domyślnego użytkownika dla nowego magazynu
        user_name = f"dyspozytor_{new_magazyn.lower()}"
        if not get_user(user_name):
            create_user(user_name, f"pass_{new_magazyn.lower()}", "dyspozytor", new_magazyn, [new_magazyn])
        return jsonify({"success": True, "magazyn": new_magazyn})
    elif request.method == 'PUT':
        data = request.json
        old_name = data.get('old_name')
        new_name = data.get('new_name')
        if not old_name or not new_name:
            return jsonify({"error": "Brak starej lub nowej nazwy magazynu"}), 400
        if old_name not in get_all_magazyny():
            return jsonify({"error": "Magazyn o tej nazwie nie istnieje"}), 404
        if new_name in get_all_magazyny():
            return jsonify({"error": "Magazyn o nowej nazwie już istnieje"}), 400
        update_magazyn_fn(old_name, new_name)
        # Aktualizacja użytkowników – przykładowo:
        users = get_all_users()
        for u, data_u in users.items():
            if data_u.get("magazyn") == old_name:
                update_user(u, {"magazyn": new_name})
            if "magazyny" in data_u and old_name in data_u["magazyny"]:
                new_list = [new_name if m == old_name else m for m in data_u["magazyny"]]
                update_user(u, {"magazyny": new_list})
        return jsonify({"success": True, "magazyn": new_name})
    elif request.method == 'DELETE':
        data = request.json
        magazyn_name = data.get('nazwa')
        if not magazyn_name:
            return jsonify({"error": "Brak nazwy magazynu"}), 400
        if magazyn_name not in get_all_magazyny():
            return jsonify({"error": "Magazyn o tej nazwie nie istnieje"}), 404
        # Sprawdzenie czy zgłoszenia korzystają z tego magazynu
        zgloszenia = list(get_all_zgloszenia().values())
        if any(z.get("magazyn_wyjazdowy") == magazyn_name or z.get("magazyn_koncowy") == magazyn_name for z in zgloszenia):
            return jsonify({"error": "Nie można usunąć magazynu, który jest używany w zgłoszeniach"}), 400
        delete_magazyn_fn(magazyn_name)
        # Aktualizacja użytkowników przypisanych do magazynu
        users = get_all_users()
        for u, data_u in users.items():
            if data_u.get("magazyn") == magazyn_name:
                if len(data_u.get("magazyny", [])) <= 1:
                    delete_user(u)
                else:
                    new_list = [m for m in data_u["magazyny"] if m != magazyn_name]
                    new_default = new_list[0] if new_list else None
                    update_user(u, {"magazyny": new_list, "magazyn": new_default})
        return jsonify({"success": True})

@app.route('/api/users', methods=['GET', 'POST', 'PUT', 'DELETE'])
def api_users_route():
    if 'username' not in session:
        return jsonify({"error": "Nie zalogowano"}), 401
    session_username = session['username']
    user = get_user(session_username)
    if user['role'] != 'admin':
        return jsonify({"error": "Brak uprawnień"}), 403
    if request.method == 'GET':
        users = get_all_users()
        for u in users:
            users[u].pop('password', None)
        return jsonify(users)
    elif request.method == 'POST':
        data = request.json
        username = data.get('username')
        password = data.get('password')
        role = data.get('role')
        magazyn = data.get('magazyn')
        if not username or not password or not role:
            return jsonify({"error": "Brak wymaganych danych"}), 400
        if get_user(username):
            return jsonify({"error": "Użytkownik o tej nazwie już istnieje"}), 400
        if role == 'dyspozytor':
            if not magazyn:
                return jsonify({"error": "Dyspozytor musi mieć przypisany magazyn"}), 400
            create_user(username, password, role, magazyn, [magazyn])
        else:
            create_user(username, password, role, None, [])
        return jsonify({"success": True, "username": username})
    elif request.method == 'PUT':
        data = request.json
        username = data.get('username')
        new_password = data.get('password')
        new_role = data.get('role')
        magazyn = data.get('magazyn')
        if not username:
            return jsonify({"error": "Brak nazwy użytkownika"}), 400
        if not get_user(username):
            return jsonify({"error": "Użytkownik o tej nazwie nie istnieje"}), 404
        if username == session_username:
            return jsonify({"error": "Nie można edytować aktualnie zalogowanego administratora"}), 400
        update_data = {}
        if new_password:
            update_data["password"] = generate_password_hash(new_password)
        if new_role:
            update_data["role"] = new_role
        if new_role == 'dyspozytor':
            if not magazyn:
                return jsonify({"error": "Dyspozytor musi mieć przypisany magazyn"}), 400
            update_data["magazyn"] = magazyn
            update_data["magazyny"] = [magazyn]
        else:
            update_data["magazyn"] = None
            update_data["magazyny"] = []
        update_user(username, update_data)
        return jsonify({"success": True, "username": username})
    elif request.method == 'DELETE':
        data = request.json
        username = data.get('username')
        if not username:
            return jsonify({"error": "Brak nazwy użytkownika"}), 400
        if not get_user(username):
            return jsonify({"error": "Użytkownik o tej nazwie nie istnieje"}), 404
        if username == session_username:
            return jsonify({"error": "Nie można usunąć aktualnie zalogowanego administratora"}), 400
        user_to_delete = get_user(username)
        if user_to_delete['role'] == 'admin':
            users = get_all_users()
            admin_count = sum(1 for u in users.values() if u.get("role") == "admin")
            if admin_count <= 1:
                return jsonify({"error": "Nie można usunąć ostatniego administratora"}), 400
        delete_user(username)
        return jsonify({"success": True})
        
# Przykładowy filtr w app.py:
@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
    if value is None:
        return "-"
    return value.strftime(format)


@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

def open_browser():
    # Otwiera w domyślnej przeglądarce podstronę "/login"
    webbrowser.open_new("http://127.0.0.1:8000/login")

if __name__ == '__main__':
    print("Uruchamianie serwera...")
    # Uruchomi przeglądarkę po 1.25 sekundy
    threading.Timer(1.25, open_browser).start()
    print("Timer uruchomiony, startuje serwer na porcie 8000")
    socketio.run(app, debug=False, host='127.0.0.1', port=8000)