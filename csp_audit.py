import requests
import json
import re

# Setting the directives to audit. Additional directives can be defined here to expand checks.
directive_list = ['default-src', 'script-src', 'frame-src']

# Web request to get the live policy. Returns csp_full list, split for each directive.
def get_csp(url):
    print(f'Getting csp for: {url} ...')
    try:
        r = requests.get(url)
        csp_full = r.headers['content-security-policy'].split(';')
        return csp_full
    except requests.exceptions.RequestException as e:
        print(e)

# Formatting to json. Returns csp list containing each directive defined in directive_list.
def format_csp(policy):
    csp = {}
    for directive in directive_list:
        csp[directive] = []
    for i in policy:
        csp_split = i.strip().split(' ')
        if csp_split[0].strip() in directive_list:
            for p in csp_split[1:]:
                p = p.replace('\'', '').replace('"', '').strip()
                if is_not_nonce_or_hash(p):
                    csp[csp_split[0].strip()].append(p)

    return csp

# Checks if the current value is a nonce or hash.
def is_not_nonce_or_hash(string):
    nonce_re = re.compile(r'^nonce-([a-zA-Z0-9+/_-]+={0,2})$')
    hash_re = re.compile(r'^(sha256|sha384|sha512)-([a-zA-Z0-9+/_-]+={0,2})$')
    string = string.strip()
    if string is None:
        return False
    if nonce_re.match(string) or hash_re.match(string):
        return False
    else:
        return True

# Initial auditing function to see if the lists match.
def is_matching(rec_policy, live_policy):
    if sorted(live_policy) == sorted(rec_policy):
        return True
    else:
        return False

# More in depth auditing function to return the discrepancies.
def compare_policies(rec_policy, live_policy):
    rec_policy = sorted(rec_policy)
    live_policy = sorted(live_policy)
    for i in rec_policy:
        if i not in live_policy:
            print(f'\t\tMismatch found: {i} is in rec_policy but not in live_policy\n')
    for i in live_policy:
        if i not in rec_policy:
            print(f'\t\tMismatch found: {i} is in live_policy but not in rec_policy\n')
    print('Recorded Policy: \n' + json.dumps(rec_policy, indent=4))
    print('Live Policy: \n' + json.dumps(live_policy, indent=4))

def main():
    # File read for the recorded policy
    with open('csp.json', 'r') as f:
        all_policy = json.load(f)
        # Checking policy for each URL defined in csp.json
        for key in all_policy.keys():
            print('--------------------------------------------------------------------')
            live_policy = format_csp(get_csp(key))
            for p in directive_list:
                if not is_matching(all_policy[key][p], live_policy[p]):
                    print(f'\n\t- {p} policy mismatch for: {key}')
                    # If-Else checks just for easier traceability on the discrepancy.
                    if len(all_policy[key][p]) > len(live_policy[p]):
                        print(f'\n\t- The recorded policy for the directive {p} has an extra entry:\n')
                        compare_policies(all_policy[key][p], live_policy[p])
                    elif len(all_policy[key][p]) < len(live_policy[p]):
                        print(f'\n\t- The recorded policy for the directive {p} is missing an entry:\n')
                        compare_policies(all_policy[key][p], live_policy[p])
                    else:
                        print(f'\n\t- The {p} policy does not match:\n')
                        compare_policies(all_policy[key][p], live_policy[p])
                else:
                    print(f'\n\t- {p} policy is matching for: {key}')

if __name__ == "__main__":
    main()