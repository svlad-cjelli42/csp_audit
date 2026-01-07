
from csp_audit import *
import sys

url = sys.argv[1]

with open('csp.json', 'r') as f:
    all_policy = json.load(f)
    all_policy[url] = format_csp(get_csp(url))
    print(all_policy)
