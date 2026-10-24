"""FlashLock backend — вся логика шифрования, без интерфейса.

Фронтенд (frontend.py) запрашивает и проверяет пароль, а затем вызывает
backend.encrypt() или backend.decrypt(). Всё остальное находится здесь.
"""

import base64
import hashlib
import hmac
import os
import sys

from cryptography.fernet import Fernet, InvalidToken

SALT_FILE = ".flashlock_salt"      # файл с солью (16 случайных байт)
MARKER_FILE = ".flashlock_marker"  # файл-маркер для проверки пароля
MARKER_MSG = b"flashlock-v1"       # фиксированная строка, из которой считается маркер
ITERATIONS = 200_000               # сколько раз PBKDF2 повторяет хеш (защита от перебора пароля)

# Файлы, которые программа никогда не должна шифровать:
# собственную соль, свой маркер и свой исходный код.
PROTECTED_NAMES = {
    SALT_FILE,
    MARKER_FILE,
    "flashlock", "flashlock.py", "flashlock.exe",
    "frontend.py", "backend.py", "flashlock_frontend.py", "flashlock_backend.py",
}


def app_dir():
    """Возвращает папку, в которой лежит программа (корень флешки)."""
    if getattr(sys, "frozen", False):
        # Программа собрана PyInstaller'ом и запущена как .app/.exe,
        # поэтому sys.executable указывает на исполняемый файл, а не на .py.
        if sys.platform == "darwin":
            # На macOS исполняемый файл лежит внутри пакета .app:
            #   .../FlashLock.app/Contents/MacOS/FlashLock
            # Поднимаемся на 3 уровня вверх до самого .app, затем ещё на один —
            # получаем папку, в которой лежит .app (это и есть корень флешки).
            bundle = os.path.abspath(os.path.join(sys.executable, "..", "..", ".."))
            return os.path.dirname(bundle)
        # Windows: папка рядом с .exe.
        return os.path.dirname(sys.executable)
    # Запуск из исходника (python backend.py): папка рядом с этим файлом.
    return os.path.dirname(os.path.abspath(__file__))


def get_salt(folder):
    """Читает файл соли, либо создаёт новую 16-байтную соль при первом запуске.

    Соль — случайное число, которое лежит на флешке открыто. Оно нужно, чтобы
    один и тот же пароль давал РАЗНЫЙ ключ на разных флешках.
    """
    salt_path = os.path.join(folder, SALT_FILE)
    if os.path.exists(salt_path):
        # Соль уже создана раньше — просто читаем её (она никогда не меняется).
        with open(salt_path, "rb") as file:
            existing_salt = file.read()
        return existing_salt
    # Первый запуск: генерируем 16 случайных байт и сохраняем их в файл.
    new_salt = os.urandom(16)
    with open(salt_path, "wb") as file:
        file.write(new_salt)
    return new_salt


def derive_key(password, salt):
    """Превращает пароль + соль в 32 сырых байта ключа через PBKDF2."""
    password_bytes = password.encode("utf-8")
    derived_key = hashlib.pbkdf2_hmac(
        "sha256", password_bytes, salt, ITERATIONS, dklen=32
    )
    return derived_key


def fernet_key(raw_key):
    """Оборачивает сырые байты ключа в ключ Fernet (base64).

    Fernet ожидает ключ в виде base64-строки, а не сырых байтов,
    поэтому кодируем 32 байта в base64.
    """
    encoded_key = base64.urlsafe_b64encode(raw_key)
    return encoded_key


def make_marker(raw_key):
    """Считает 32-байтный HMAC-тег по фиксированной строке с помощью ключа.

    Это «маркер» — значение, по которому программа проверяет правильность
    пароля, НЕ храня сам пароль.
    """
    marker_tag = hmac.new(raw_key, MARKER_MSG, hashlib.sha256).digest()
    return marker_tag


def write_marker(folder, raw_key):
    """Записывает маркер в файл .flashlock_marker.

    Вызывается при ПЕРВОМ шифровании, чтобы «запомнить» правильный пароль.
    """
    marker_tag = make_marker(raw_key)
    with open(os.path.join(folder, MARKER_FILE), "wb") as file:
        file.write(marker_tag)


def check_marker(folder, raw_key):
    """Проверяет, совпадает ли сохранённый маркер с текущим ключом.

    Возвращает True, если пароль правильный, и False — если неправильный
    или маркера ещё нет.
    """
    marker_path = os.path.join(folder, MARKER_FILE)
    if not os.path.exists(marker_path):
        return False  # маркера ещё нет — проверять нечего
    with open(marker_path, "rb") as file:
        stored_marker = file.read()
    # Считаем маркер заново из текущего ключа и сравниваем.
    expected_marker = make_marker(raw_key)
    # hmac.compare_digest сравнивает за постоянное время (защита от атаки по времени).
    return hmac.compare_digest(stored_marker, expected_marker)


def has_marker():
    """Возвращает True, если маркер уже существует (пароль уже установлен).

    Фронтенд использует это, чтобы после перезапуска программы понять,
    что пароль уже задан, и спрашивать его повторно, а не предлагать
    задать заново.
    """
    return os.path.exists(os.path.join(app_dir(), MARKER_FILE))


def encrypt_folder(folder, key):
    """Шифрует каждый файл в папке: и содержимое, и имя файла.

    Рекурсивно обходит все файлы. Каждый файл превращается в .enc со
    «случайным» именем (это зашифрованное настоящее имя).
    """
    cipher = Fernet(key)
    count = 0  # сколько файлов зашифровано
    for root, dirs, files in os.walk(folder):
        # Не заходим в скрытые папки (.venv, .git, .Trashes...) и в .app.
        dirs[:] = [d for d in dirs if not d.startswith(".") and not d.endswith(".app")]
        for name in files:
            # Пропускаем скрытые файлы, уже зашифрованные (.enc) и защищённые.
            if name.startswith(".") or name.endswith(".enc") or name in PROTECTED_NAMES:
                continue
            path = os.path.join(root, name)
            with open(path, "rb") as file:
                data = file.read()  # содержимое файла
            name_bytes = name.encode("utf-8")
            # Шифруем имя файла → получаем случайно выглядящий токен.
            encrypted_name = cipher.encrypt(name_bytes).decode("ascii")
            # Шифруем содержимое файла.
            encrypted_data = cipher.encrypt(data)
            # Пишем новый файл полностью, затем удаляем оригинал
            # (правило «сначала записать — потом удалить», чтобы не потерять данные).
            with open(os.path.join(root, encrypted_name + ".enc"), "wb") as file:
                file.write(encrypted_data)
            os.remove(path)
            count += 1
    return count


def decrypt_folder(folder, key):
    """Расшифровывает каждый .enc-файл: и имя, и содержимое.

    Это обратная операция к encrypt_folder.
    """
    cipher = Fernet(key)
    count = 0  # сколько файлов расшифровано
    for root, _, files in os.walk(folder):
        for name in files:
            if not name.endswith(".enc"):
                continue
            # Имя файла (без .enc) — это зашифрованное настоящее имя.
            token = name[:-4]
            try:
                token_bytes = token.encode("ascii")
                # Расшифровываем имя → получаем настоящее имя файла.
                original_name = cipher.decrypt(token_bytes).decode("utf-8")
            except (InvalidToken, UnicodeError):
                # Имя не расшифровалось — это «чужой» .enc-файл (например,
                # ascii.enc от Tcl), а не наш. Пропускаем его, а не падаем.
                continue
            path = os.path.join(root, name)
            with open(path, "rb") as file:
                data = file.read()
            try:
                decrypted_data = cipher.decrypt(data)
            except InvalidToken:
                # Содержимое не расшифровалось — файл повреждён или пароль неверный.
                raise ValueError(f"Wrong password or corrupted file: {name}")
            # Пишем расшифрованный файл под настоящим именем, затем удаляем .enc.
            with open(os.path.join(root, original_name), "wb") as file:
                file.write(decrypted_data)
            os.remove(path)
            count += 1
    return count


def encrypt(password):
    """Шифрует папку программы за паролем.

    Возвращает пару (успех, сообщение), где успех — True или False.
    Это точка входа, которую вызывает frontend.py.
    """
    folder = app_dir()
    try:
        salt = get_salt(folder)
        raw_key = derive_key(password, salt)
        marker_path = os.path.join(folder, MARKER_FILE)
        if os.path.exists(marker_path):
            # Маркер уже есть → сначала проверяем пароль, потом шифруем.
            if not check_marker(folder, raw_key):
                return False, "Wrong password."
        else:
            # Маркера нет → это первое шифрование: создаём маркер.
            write_marker(folder, raw_key)
        key = fernet_key(raw_key)
        count = encrypt_folder(folder, key)
        return True, f"Encrypted files: {count}"
    except Exception as e:
        return False, f"Error: {e}"


def decrypt(password):
    """Расшифровывает папку программы за паролем.

    Возвращает пару (успех, сообщение), где успех — True или False.
    """
    folder = app_dir()
    try:
        salt_path = os.path.join(folder, SALT_FILE)
        if not os.path.exists(salt_path):
            return False, "Salt file not found."
        marker_path = os.path.join(folder, MARKER_FILE)
        if not os.path.exists(marker_path):
            return False, "Marker file not found. Cannot verify password."
        salt = get_salt(folder)
        raw_key = derive_key(password, salt)
        if not check_marker(folder, raw_key):
            return False, "Wrong password."
        key = fernet_key(raw_key)
        count = decrypt_folder(folder, key)
        return True, f"Decrypted files: {count}"
    except Exception as e:
        return False, f"Error: {e}"


def has_encrypted_files():
    """Возвращает True, если в папке ещё есть зашифрованные .enc-файлы."""
    folder = app_dir()
    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if not d.startswith(".") and not d.endswith(".app")]
        for name in files:
            if name.endswith(".enc"):
                return True
    return False


def reset_password():
    """Сбрасывает пароль: удаляет маркер и соль (пароль становится «нулевым»).

    Отказывает, если в папке ещё есть зашифрованные файлы — сначала их
    нужно расшифровать, иначе они станут нечитаемыми навсегда.
    Возвращает пару (успех, сообщение).
    """
    folder = app_dir()
    try:
        if has_encrypted_files():
            return False, "Decrypt your files first — some files are still encrypted."
        marker_path = os.path.join(folder, MARKER_FILE)
        if os.path.exists(marker_path):
            os.remove(marker_path)
        salt_path = os.path.join(folder, SALT_FILE)
        if os.path.exists(salt_path):
            os.remove(salt_path)
        return True, "Password reset."
    except Exception as e:
        return False, f"Error: {e}"
