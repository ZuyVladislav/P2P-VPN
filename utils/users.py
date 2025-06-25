# utils/users.py

from typing import List, Dict, Optional

# Определяем структуру данных: словарь USERS, где ключом служит имя/логин,
# а значением - словарь с логином, паролем и IP-адресом пользователя.
USERS: Dict[str, Dict[str, str]] = {
    "User1": {
        "login": "User1",
        "password": "1111",
        "ip": "192.168.25.47"
    },
    "User2": {
        "login": "User2",
        "password": "2222",
        "ip": "192.168.25.50"
    },
    "User3": {
        "login": "User3",
        "password": "3333",
        "ip": "192.168.25.49"
    },
     "User4": {
        "login": "User4",
        "password": "4444",
        "ip": "192.168.25.48"
    },
    },
    # ... другие пользователи ...
}

def get_user(name: str) -> Optional[Dict[str, str]]:
    """Возвращает словарь с данными пользователя по его имени (логину)."""
    return USERS.get(name)

def get_all_users() -> List[Dict[str, str]]:
    """Возвращает список словарей с данными по всем пользователям."""
    return list(USERS.values())