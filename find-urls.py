import os

from androguard.core.analysis.analysis import Analysis, StringAnalysis
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.misc import AnalyzeAPK
import argparse

parser = argparse.ArgumentParser('find string in a apk')
parser.add_argument('apk')
parser.add_argument('--only-login', help='display only logins', action='store_true')
parser.add_argument('--show-file', help='Add filename before url', action='store_true')
args = parser.parse_args()

a: APK
d: DalvikVMFormat
dx: Analysis
a, d, dx = AnalyzeAPK(args.apk)

find_http = []


login_hints = ['login', 'auth', 'token', 'cred']

exclude_domains = ['googleapis.com', 'crashlytics.com']


def display(value, prefix=None):
    if prefix:
        print(prefix + ':' + value)
    else:
        print(value)


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
