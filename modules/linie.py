import uuid
from firebase_config import realtime_db, firestore_db
import logging



def get_all_zgloszenia():
    # Pobierz wszystkie zgłoszenia; jeżeli nic nie ma, zwróć pusty słownik
    data = realtime_db.child("linie").get()
    return data if data else {}

def get_zgloszenie_by_id(zgloszenie_id):
    # Pobierz konkretne zgłoszenie po ID
    return realtime_db.child("linie").child(zgloszenie_id).get()

def filter_zgloszenia(data_param, user_role, user_magazyny, magazyny_param=None):
    all_zgloszenia = get_all_zgloszenia()
    zgloszenia_list = list(all_zgloszenia.values())
    # Filtrowanie po dacie
    filtered = [z for z in zgloszenia_list if z.get("data") == data_param]
    if user_role == "dyspozytor":
        if magazyny_param:
            selected = [m.strip() for m in magazyny_param.split(',')]
            if not all(m in user_magazyny for m in selected):
                selected = user_magazyny
        else:
            selected = user_magazyny
        filtered = [z for z in filtered if z.get("magazyn_wyjazdowy") in selected or z.get("magazyn_koncowy") in selected]
    return filtered

def get_statusy(start_date, end_date, user_role, user_magazyny, magazyny_param=None):
    all_zgloszenia = get_all_zgloszenia()
    zgloszenia_list = list(all_zgloszenia.values())
    # Filtrowanie wg zakresu dat – zakładając, że daty są w formacie 'YYYY-MM-DD'
    filtered = [z for z in zgloszenia_list if start_date <= z.get("data", "") <= end_date]
    if user_role == "dyspozytor":
        if magazyny_param:
            selected = [m.strip() for m in magazyny_param.split(',')]
            selected = [m for m in selected if m in user_magazyny]
        else:
            selected = user_magazyny
        filtered = [z for z in filtered if z.get("magazyn_wyjazdowy") in selected or z.get("magazyn_koncowy") in selected]
    statusy_po_dacie = {}
    for z in filtered:
        d = z.get("data")
        status = z.get("status")
        if d and status:
            statusy_po_dacie.setdefault(d, []).append(status)
    return statusy_po_dacie

def add_zgloszenie(new_zgloszenie):
    if "id" not in new_zgloszenie:
        new_zgloszenie["id"] = str(uuid.uuid4())
    z_id = new_zgloszenie["id"]
    realtime_db.child("linie").child(z_id).set(new_zgloszenie)
    return new_zgloszenie

def update_zgloszenie(zgloszenie_id, update_data):
    ref = realtime_db.child("linie").child(zgloszenie_id)
    if ref.get() is None:
        return False
    ref.update(update_data)
    return True

def delete_zgloszenie_fn(zgloszenie_id):
    """
    Usuwa zgłoszenie o podanym ID z Realtime DB oraz odpowiadający mu dokument
    w kolekcji 'przyjazdy' we Firestore.
    Zwraca True jeśli obie operacje się powiodły, False jeśli zgłoszenie nie istniało.
    """
    try:
        # 1) Realtime DB: usuń zgłoszenie
        zg_ref = realtime_db.child("linie").child(zgloszenie_id)
        if zg_ref.get() is None:
            logging.error(f"[linie] Zgłoszenie {zgloszenie_id} nie znalezione.")
            return False
        zg_ref.delete()
        logging.info(f"[linie] Usunięto zgłoszenie {zgloszenie_id}.")

        # 2) Firestore: usuń przyjazd o tym samym ID
        arr_doc = firestore_db.collection("przyjazdy").document(zgloszenie_id)
        if arr_doc.get().exists:
            arr_doc.delete()
            logging.info(f"[przyjazdy] Usunięto dokument przyjazdu {zgloszenie_id}.")
        else:
            logging.debug(f"[przyjazdy] Brak dokumentu przyjazdu {zgloszenie_id}, pomijam.")

        return True

    except Exception as e:
        logging.exception(f"Błąd podczas usuwania zgłoszenia/przyjazdu {zgloszenie_id}: {e}")
        raise