from typing import List, Dict, Optional, Union

# Определяем структуру данных: словарь USERS, где ключом служит имя/логин,
# а значением — словарь с логином, паролем, IP-адресом и списком соседних узлов пользователя.
USERS: Dict[str, Dict[str, Union[str, List[str]]]] = {
    "User1": {
        "login": "User1",
        "password": "1111",
        "ip": "192.168.25.47",
        "neighbors": ["User2", "User3", "User4"]
    },
    "User2": {
        "login": "User2",
        "password": "2222",
        "ip": "192.168.25.50",
        "neighbors": ["User1", "User3", "User4"]
    },
    "User3": {
        "login": "User3",
        "password": "3333",
        "ip": "192.168.25.49",
        "neighbors": ["User1", "User2", "User4"]
    },
    "User4": {
        "login": "User4",
        "password": "4444",
        "ip": "192.168.25.48",
        "neighbors": ["User1", "User2", "User3"]
    },
}

def get_user(name: str) -> Optional[Dict[str, Union[str, List[str]]]]:
    """Возвращает словарь с данными пользователя по его имени (логину)."""
    return USERS.get(name)

def get_all_users() -> List[Dict[str, Union[str, List[str]]]]:
    """Возвращает список словарей с данными по всем пользователям."""
    return list(USERS.values())