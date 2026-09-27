import re
import time
import functools
from typing import Callable, Any, Optional


def audit_logger(func: Callable[..., Any]) -> Callable[..., Any]:
    """
    Декоратор для аудита функций ИБ-анализа.
    Замеряет время выполнения, логирует обнаружение угроз и перехватывает ошибки.
    """
    @functools.wraps(func)  # сохраняет имя и docstring исходной функции
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        # Запоминаем время до вызова
        start = time.time()
        
        try:
            # Вызываем исходную функцию с её аргументами
            result = func(*args, **kwargs)
            
            # Считаем, сколько времени заняла работа
            elapsed = time.time() - start
            
            # Логируем результат в консоль
            print(f"[AUDIT] {func.__name__} выполнена за {elapsed:.4f} сек. Результат: {result}")
            
            # Если функция вернула True - значит нашла угрозу, пишем отдельно
            if result is True:
                print(f"[AUDIT]  {func.__name__} обнаружила угрозу!")
            
            return result
        
        except Exception as e:
            # Если внутри функции произошла ошибка - ловим её
            # Пишем сообщение и возвращаем False (тест!)
            print(f"[AUDIT] Ошибка в {func.__name__}: {e}")
            return False
    
    return wrapper  # возвращаем обёртку


class SecurityEvent:
    """
    Класс события безопасности.
    Хранит информацию о том, что произошло: время, IP, тип, важность.
    """
    
    def __init__(self, timestamp: str, source_ip: str, event_type: str, severity: int = 1) -> None:
        # Сохраняем простые атрибуты
        self.timestamp = timestamp
        self.source_ip = source_ip
        self.event_type = event_type
        # severity идёт через сеттер - там будет проверка диапазона
        self.severity = severity

    @property
    def severity(self) -> int:
        # Геттер: возвращает внутренний атрибут _severity
        return self._severity

    @severity.setter
    def severity(self, value: int) -> None:
        # Сеттер: проверяем, что значение - целое число от 1 до 5
        if not isinstance(value, int) or value < 1 or value > 5:
            raise ValueError("severity должно быть целым числом от 1 до 5")
        # Если всё ок - сохраняем во внутренний атрибут
        self._severity = value

    @property
    def is_critical(self) -> bool:
        # Геттер: True, если severity >= 4
        return self._severity >= 4

    @classmethod
    def from_syslog(cls, raw_line: str) -> "SecurityEvent":
        """
        Фабричный метод: создаёт объект из строки лога.
        Пример: '2026-09-13 12:00:00 [SSH] Failed login from 192.168.1.50'
        """
        # Первые 19 символов - это timestamp ('2026-09-13 12:00:00')
        timestamp = raw_line[:19].strip()
        
        # Ищем IP после слова 'from'
        ip_match = re.search(r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', raw_line)
        source_ip = ip_match.group(1) if ip_match else "0.0.0.0"
        
        # Ищем тег в квадратных скобках: [SSH] или [WEB]
        tag_match = re.search(r'\[(\w+)\]', raw_line)
        event_type = tag_match.group(1) if tag_match else "UNKNOWN"
        
        # Определяем важность по ключевым словам
        line_lower = raw_line.lower()
        if "sqli" in line_lower or "attack payload" in line_lower:
            severity = 5  # SQL-инъекция - самое опасное
        elif "failed" in line_lower or "brute" in line_lower:
            severity = 3  # Неудачный вход - средний уровень
        else:
            severity = 1  # Всё остальное - низкий уровень
        
        # Создаём объект через cls (это и есть фабричный метод)
        return cls(timestamp, source_ip, event_type, severity)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecurityEvent":
        """
        Фабричный метод: создаёт объект из словаря.
        """
        # Берём значения из словаря, если ключа нет - подставляем значение по умолчанию
        return cls(
            timestamp=data.get("timestamp", ""),
            source_ip=data.get("source_ip", "0.0.0.0"),
            event_type=data.get("event_type", "UNKNOWN"),
            severity=data.get("severity", 1),
        )

    def __repr__(self) -> str:
        # Строковое представление объекта для отладки
        return f"SecurityEvent(ip='{self.source_ip}', type='{self.event_type}', severity={self.severity})"


class IPUtils:
    """
    Класс-утилита для работы с IP-адресами.
    Все методы статические - объект создавать не нужно.
    """
    
    @staticmethod
    def is_private(ip: str) -> bool:
        """
        Проверяет, приватный ли IP:
        - 10.x.x.x
        - 172.16.x.x – 172.31.x.x
        - 192.168.x.x
        - 127.x.x.x
        """
        # Разбиваем IP на 4 части
        parts = ip.split(".")
        if len(parts) != 4:
            return False  # не похоже на IP
        
        try:
            first = int(parts[0])
            second = int(parts[1])
        except ValueError:
            return False  # в IP не числа
        
        # Проверяем каждый диапазон
        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        if first == 127:
            return True
        
        return False  # ни один диапазон не подошёл

    @staticmethod
    def mask_ip(ip: str) -> str:
        """
        Маскирует последний октет IP.
        '192.168.1.50' -> '192.168.1.***'
        """
        parts = ip.split(".")
        if len(parts) != 4:
            return ip  # не IP - возвращаем как есть
        
        # Заменяем последний октет на ***
        parts[3] = "***"
        # Склеиваем обратно через точку
        return ".".join(parts)


class BlacklistManager:
    """
    Менеджер чёрного списка IP-адресов.
    Работает как множество с удобными методами.
    """
    
    def __init__(self, initial_ips: Optional[list[str]] = None) -> None:
        # Если передали список - делаем из него множество
        # Если нет - пустое множество
        self._blocked_ips: set[str] = set(initial_ips) if initial_ips else set()

    def add_ip(self, ip: str) -> None:
        # Добавляем IP в чёрный список
        self._blocked_ips.add(ip)

    def remove_ip(self, ip: str) -> None:
        # Удаляем IP (discard - безопасно, если его нет)
        self._blocked_ips.discard(ip)

    def __contains__(self, ip: str) -> bool:
        # Магический метод: работает оператор `in`
        # Пример: if "192.168.1.1" in manager:
        return ip in self._blocked_ips

    def __len__(self) -> int:
        # Магический метод: работает функция len()
        return len(self._blocked_ips)

    def __repr__(self) -> str:
        # Строковое представление для отладки
        return f"BlacklistManager(blocked_count={len(self._blocked_ips)})"
