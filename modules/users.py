# modules/users.py
from werkzeug.security import generate_password_hash, check_password_hash
from firebase_config import firestore_db

def get_all_users():
    """
    Pobiera wszystkich użytkowników z bazy
    """
    users_ref = firestore_db.collection('users')
    users = {}
    for doc in users_ref.stream():
        users[doc.id] = doc.to_dict()
    return users

def get_user(username):
    """
    Pobiera dane użytkownika o podanej nazwie
    """
    doc = firestore_db.collection('users').document(username).get()
    if doc.exists:
        return doc.to_dict()
    return None

def create_user(username, password, role, magazyn=None, magazyny=None):
    """
    Tworzy nowego użytkownika w bazie
    """
    # Używamy stałej metody haszowania, która działa we wszystkich wersjach Werkzeug
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    
    user_data = {
        'username': username,
        'password': hashed_password,
        'role': role
    }
    
    if magazyn:
        user_data['magazyn'] = magazyn
    
    if magazyny:
        user_data['magazyny'] = magazyny
    
    firestore_db.collection('users').document(username).set(user_data)
    return user_data

def update_user(username, update_data):
    """
    Aktualizuje dane użytkownika
    """
    # Jeśli aktualizujemy hasło, zabezpieczamy je
    if 'password' in update_data and not update_data['password'].startswith('pbkdf2:'):
        update_data['password'] = generate_password_hash(update_data['password'], method='pbkdf2:sha256')
    
    firestore_db.collection('users').document(username).update(update_data)
    return True

def delete_user(username):
    """
    Usuwa użytkownika z bazy
    """
    firestore_db.collection('users').document(username).delete()
    return True

def verify_user(username, password):
    """
    Weryfikuje hasło użytkownika
    """
    user = get_user(username)
    if not user:
        return False
    
    # Obsługa różnych metod haszowania
    stored_password = user.get('password', '')
    
    # Próba standardowego sprawdzenia
    try:
        return check_password_hash(stored_password, password)
    except ValueError as e:
        # Jeśli wystąpił błąd (np. nieobsługiwany algorytm haszowania)
        print(f"Błąd weryfikacji hasła: {e}")
        
        # Awaryjnie, jeśli hasło jest przechowywane jako plain text (nie zalecane!)
        if stored_password == password:
            return True
            
        return False