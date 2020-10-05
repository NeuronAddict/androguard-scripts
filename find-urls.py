import os
import sys

from androguard import misc
from androguard.core.analysis.analysis import Analysis, StringAnalysis
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.misc import AnalyzeAPK
from androguard import session
import argparse

parser = argparse.ArgumentParser('find string in a apk')
parser.add_argument('apk')
parser.add_argument('--only-login', help='display only logins', action='store_true')
parser.add_argument('--show-file', help='Add filename before url', action='store_true')
parser.add_argument('--session', help='session file')
args = parser.parse_args()

sess = misc.get_default_session()

if args.session and os.path.exists(args.session):
    print('load session from {} ...'.format(args.session), file=sys.stderr)
    sess = session.Load(args.session)

a: APK
d: DalvikVMFormat
dx: Analysis

print('[*] Analyse {} ...'.format(args.apk), file=sys.stderr)
a, d, dx = AnalyzeAPK(args.apk, session=sess)

find_http = []


login_hints = ['login', 'auth', 'token', 'cred']

exclude_domains = ['googleapis.com', 'crashlytics.com']


def display(value, prefix=None):
    if prefix:
        print('[+] ' + prefix + ':' + value)
    else:
        print('[+] ' + value)


for s in list(dx.get_strings()):

    s: StringAnalysis = s

    if 'http' in s.get_value() and all(t not in s.get_value() for t in exclude_domains):
        find_http.append(s.get_value())

        if not args.only_login:
            display(s.get_value(), os.path.basename(args.apk if args.show_file else None))
        else:
            for t in login_hints:
                if t in s.get_value():
                    display(s.get_value(), os.path.basename(args.apk if args.show_file else None))
                    break

if args.session:
    print('[*] save session in {} ...'.format(args.session))
    session.Save(sess, args.session)
