"""Create the first local administrator without exposing the password in arguments."""

import argparse
from getpass import getpass

from monitoring.db import SessionLocal
from monitoring.models import UserRole
from monitoring.services.auth import create_user


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a Monitoring Maxval administrator")
    parser.add_argument("--username", default="admin")
    args = parser.parse_args()

    password = getpass("Новый пароль: ")
    confirmation = getpass("Повторите пароль: ")
    if password != confirmation:
        raise SystemExit("Пароли не совпадают")

    with SessionLocal() as session:
        try:
            user = create_user(session, args.username, password, UserRole.ADMIN)
            session.commit()
        except ValueError as exc:
            session.rollback()
            raise SystemExit(str(exc)) from exc
    print(f"Администратор '{user.username}' создан.")


if __name__ == "__main__":
    main()
