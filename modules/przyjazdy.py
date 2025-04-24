# modules/przyjazdy.py
from firebase_config import firestore_db
import logging
from modules.linie import get_all_zgloszenia, get_zgloszenie_by_id

def store_przyjazd(zgloszenie):
    """
    Store an arrival record in Firestore.
    
    Args:
        zgloszenie: A dictionary containing the zgloszenie data
    
    Returns:
        bool: True if the operation succeeded, False otherwise
    """
    try:
        # Create a reference to the 'przyjazdy' collection
        przyjazdy_ref = firestore_db.collection('przyjazdy')
        
        # Use the same ID as the zgloszenie
        doc_ref = przyjazdy_ref.document(zgloszenie['id'])
        
        # Store the document
        doc_ref.set(zgloszenie)
        
        logging.info(f"Zapisano przyjazd dla zgłoszenia {zgloszenie['id']}")
        return True
    except Exception as e:
        logging.exception(f"Błąd podczas zapisywania przyjazdu: {e}")
        return False

def get_przyjazdy(data_przyjazdu, user_role, user_magazyny, magazyny_param=None):
    """
    Get arrivals for a specific date, filtered by user role and warehouses.
    
    Args:
        data_przyjazdu: The arrival date to filter by
        user_role: The role of the user making the request
        user_magazyny: List of warehouses the user has access to
        magazyny_param: Optional comma-separated string of warehouses to filter by
    
    Returns:
        list: A list of arrivals for the specified date
    """
    try:
        # Create a query to filter by arrival date
        query = firestore_db.collection('przyjazdy').where('data_przyjazdu', '==', data_przyjazdu)
        
        # Execute the query
        docs = query.stream()
        
        # Convert to list of dictionaries
        przyjazdy = []
        for doc in docs:
            przyjazd = doc.to_dict()
            przyjazd['id'] = doc.id
            przyjazdy.append(przyjazd)
        
        # Apply additional filtering based on user role
        if user_role == 'dyspozytor':
            # Parse the magazyny_param string if provided
            if magazyny_param:
                selected = [m.strip() for m in magazyny_param.split(',')]
                # Ensure the warehouses are ones the user has access to
                selected = [m for m in selected if m in user_magazyny]
            else:
                selected = user_magazyny
                
            # Filter przyjazdy by selected warehouses
            przyjazdy = [p for p in przyjazdy if 
                        (p.get('magazyn_wyjazdowy') in selected or 
                         p.get('magazyn_koncowy') in selected)]
        
        logging.info(f"Znaleziono {len(przyjazdy)} przyjazdów na {data_przyjazdu}")
        return przyjazdy
    except Exception as e:
        logging.exception(f"Błąd podczas pobierania przyjazdów: {e}")
        return []

def update_przyjazd_hidden(zgloszenie_id, hidden=True):
    """
    Update the hidden status of an arrival in Firestore.
    
    Args:
        zgloszenie_id: The ID of the zgloszenie/przyjazd to update
        hidden: Boolean indicating whether the entry should be hidden
    
    Returns:
        bool: True if the operation succeeded, False otherwise
    """
    try:
        # Get a reference to the document
        doc_ref = firestore_db.collection('przyjazdy').document(zgloszenie_id)
        
        # Check if the document exists
        if not doc_ref.get().exists:
            logging.warning(f"Przyjazd {zgloszenie_id} nie istnieje w Firestore")
            return False
        
        # Update the hidden field
        doc_ref.update({'hidden': hidden})
        
        logging.info(f"Zaktualizowano status ukrycia dla przyjazdu {zgloszenie_id}: {hidden}")
        return True
    except Exception as e:
        logging.exception(f"Błąd podczas aktualizacji statusu ukrycia: {e}")
        return False

def synchronize_przyjazdy():
    """
    Synchronize the arrivals in Firestore with the zgloszenia in Realtime DB.
    This function is useful for initial setup or data recovery.
    """
    try:
        # Get all zgloszenia from Realtime DB
        zgloszenia = get_all_zgloszenia()
        
        # Filter for zgloszenia that have arrival data
        with_arrival = [z for z in zgloszenia.values() if 
                      'data_przyjazdu' in z and z['data_przyjazdu'] and 
                      'godzina_przyjazdu' in z and z['godzina_przyjazdu']]
        
        # Store each one in Firestore
        count = 0
        for zgloszenie in with_arrival:
            if store_przyjazd(zgloszenie):
                count += 1
        
        logging.info(f"Zsynchronizowano {count} przyjazdów z {len(with_arrival)} znalezionych")
        return count
    except Exception as e:
        logging.exception(f"Błąd podczas synchronizacji przyjazdów: {e}")
        return 0