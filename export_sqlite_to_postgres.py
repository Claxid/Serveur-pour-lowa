#!/usr/bin/env python3
"""
Script pour exporter les données SQLite vers PostgreSQL
Usage: python export_sqlite_to_postgres.py
"""

import sqlite3
import json
from pathlib import Path

# Chemin vers votre base SQLite
SQLITE_DB = Path(__file__).parent / "lowa.db"
OUTPUT_SQL = Path(__file__).parent / "data_export.sql"

def export_data():
    conn = sqlite3.connect(SQLITE_DB)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    with open(OUTPUT_SQL, 'w', encoding='utf-8') as f:
        # Exporter les users
        f.write("-- Export des utilisateurs\n")
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        for user in users:
            f.write(f"INSERT INTO users (id, email, password_hash, nom, prenom, sexe, date_creation) VALUES ({user['id']}, '{user['email']}', '{user['password_hash']}', '{user['nom']}', '{user['prenom']}', '{user['sexe'] or 'NULL'}', '{user['date_creation']}');\n")
        
        # Exporter les carts
        f.write("\n-- Export des paniers\n")
        cursor.execute("SELECT * FROM carts")
        carts = cursor.fetchall()
        for cart in carts:
            items = cart['items'].replace("'", "''")
            f.write(f"INSERT INTO carts (user_id, items, updated_at) VALUES ({cart['user_id']}, '{items}', '{cart['updated_at']}');\n")
        
        # Exporter purchase_history
        f.write("\n-- Export de l'historique d'achats\n")
        cursor.execute("SELECT * FROM purchase_history")
        purchases = cursor.fetchall()
        for purchase in purchases:
            items = purchase['items'].replace("'", "''")
            f.write(f"INSERT INTO purchase_history (id, user_id, purchase_date, total, items) VALUES ({purchase['id']}, {purchase['user_id']}, '{purchase['purchase_date']}', {purchase['total']}, '{items}');\n")
        
        # Exporter sessions (optionnel, elles expireront de toute façon)
        f.write("\n-- Export des sessions (optionnel)\n")
        cursor.execute("SELECT * FROM sessions WHERE expires_at > datetime('now')")
        sessions = cursor.fetchall()
        for session in sessions:
            f.write(f"INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES ('{session['token']}', {session['user_id']}, '{session['created_at']}', '{session['expires_at']}');\n")
        
        # Reset sequences
        f.write("\n-- Réinitialiser les séquences\n")
        if users:
            max_user_id = max(u['id'] for u in users)
            f.write(f"SELECT setval('users_id_seq', {max_user_id}, true);\n")
        if purchases:
            max_purchase_id = max(p['id'] for p in purchases)
            f.write(f"SELECT setval('purchase_history_id_seq', {max_purchase_id}, true);\n")
    
    conn.close()
    print(f"✅ Export réussi ! Fichier créé : {OUTPUT_SQL}")
    print(f"\n📋 Statistiques :")
    print(f"   - {len(users)} utilisateurs")
    print(f"   - {len(carts)} paniers")
    print(f"   - {len(purchases)} achats")
    print(f"   - {len(sessions)} sessions actives")
    print(f"\n🚀 Prochaine étape :")
    print(f"   1. Copiez le contenu de '{OUTPUT_SQL.name}'")
    print(f"   2. Sur Render, allez dans votre PostgreSQL database")
    print(f"   3. Cliquez sur 'Connect' → 'PSQL Command'")
    print(f"   4. Collez et exécutez le SQL")

if __name__ == "__main__":
    export_data()
