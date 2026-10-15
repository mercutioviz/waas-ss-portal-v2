#!/usr/bin/env python3
"""
Resolve a WaasAccount's decrypted API key for use in ad-hoc shell commands,
without ever echoing it into chat history or a log.

Usage:
    python3 scripts/resolve_api_key.py "Barracuda-CSA"
    python3 scripts/resolve_api_key.py "Barracuda-CSA" --user-id 3

Prints only the raw key to stdout (nothing else), so it's safe to capture
with command substitution:

    export WAAS_API_KEY=$(python3 scripts/resolve_api_key.py "Barracuda-CSA")
    curl -H "Authorization: Bearer $WAAS_API_KEY" ...

Exits non-zero with a message on stderr if the account isn't found, is
ambiguous (same name under multiple users), or has no API key configured.
"""
import argparse
import sys

sys.path.insert(0, __file__.rsplit('/scripts/', 1)[0])

from app import create_app
from app.models import WaasAccount


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('account_name', help='WaasAccount.account_name to look up')
    parser.add_argument('--user-id', type=int, default=None,
                         help='Disambiguate when multiple users have an account with this name')
    args = parser.parse_args()

    app = create_app()
    with app.app_context():
        query = WaasAccount.query.filter_by(account_name=args.account_name)
        if args.user_id is not None:
            query = query.filter_by(user_id=args.user_id)
        matches = query.all()

        if not matches:
            print(f'No WaasAccount named {args.account_name!r} found.', file=sys.stderr)
            sys.exit(1)

        if len(matches) > 1:
            print(f'Ambiguous: {len(matches)} accounts named {args.account_name!r}. '
                  'Re-run with --user-id to disambiguate:', file=sys.stderr)
            for acct in matches:
                print(f'  id={acct.id} user_id={acct.user_id}', file=sys.stderr)
            sys.exit(1)

        account = matches[0]
        key = account.api_key
        if not key:
            print(f'Account {args.account_name!r} (id={account.id}) has no API key configured '
                  '(it may be using v2 email/password credentials instead).', file=sys.stderr)
            sys.exit(1)

        print(key)


if __name__ == '__main__':
    main()
