from firebase_config import firestore_db

def get_all_magazyny():
    magazyny_ref = firestore_db.collection("magazyny")
    docs = magazyny_ref.stream()
    return [doc.id for doc in docs]

def create_magazyn(nazwa):
    doc_ref = firestore_db.collection("magazyny").document(nazwa)
    if doc_ref.get().exists:
        return False
    doc_ref.set({"name": nazwa})
    return True

def update_magazyn(old_name, new_name):
    old_doc_ref = firestore_db.collection("magazyny").document(old_name)
    if not old_doc_ref.get().exists:
        return False
    new_doc_ref = firestore_db.collection("magazyny").document(new_name)
    new_doc_ref.set({"name": new_name})
    old_doc_ref.delete()
    return True

def delete_magazyn(nazwa):
    doc_ref = firestore_db.collection("magazyny").document(nazwa)
    if doc_ref.get().exists:
        doc_ref.delete()
        return True
    return False
