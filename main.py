# main.py
import argparse

from keychain import zsetup_vault, zvault_add, zvault_get, zvault_list


def main():
    parser = argparse.ArgumentParser(prog="zvault")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("init")

    p_add = sub.add_parser("add")
    p_add.add_argument("name")

    p_get = sub.add_parser("get")
    p_get.add_argument("name")

    sub.add_parser("list")
    args = parser.parse_args()

    if args.command == "init":
        zsetup_vault()
    elif args.command == "add":
        zvault_add(args.name)
    elif args.command == "get":
        zvault_get(args.name)
    elif args.command == "list":
        zvault_list()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
