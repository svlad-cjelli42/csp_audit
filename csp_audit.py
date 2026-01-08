import requests
import json
import re

default_str = 'default-src'
script_str = 'script-src'
frame_str = 'frame-src'
directive_list = ['default-src','script-src','frame-src']

def get_csp(url):
    print(f'Getting csp from: {url} ...')
    try:
        r = requests.get(url)
        csp_full = r.headers['content-security-policy'].split(';')
        return csp_full
    except requests.exceptions.RequestException as e:
        print(e)

def format_csp(policy):
    csp = {
        "default-src": [],
        "script-src": [],
        "frame-src": []
    }
    for i in policy:
        csp_split = i.strip().split(' ')
        if csp_split[0].strip() in directive_list:
            for p in csp_split[1:]:
                p = p.replace('\'', '').replace('"', '').strip()
                if is_not_nonce_or_hash(p):
                    csp[csp_split[0].strip()].append(p)

    return csp

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

def is_matching(rec_policy, live_policy):
    if sorted(live_policy) == sorted(rec_policy):
        return True
    else:
        return False

def main():
    with open('csp.json', 'r') as f:
        all_policy = json.load(f)
        for key in all_policy.keys():
            live_policy = format_csp(get_csp(key))
            def_rec_policy = all_policy[key][default_str]
            scr_rec_policy = all_policy[key][script_str]
            frm_rec_policy = all_policy[key][frame_str]

            if is_matching(live_policy[default_str], def_rec_policy):
                print(f'Default source matching for {key}')
            else:
                print(f'Default source not matching for {key}')
            if is_matching(live_policy[script_str], scr_rec_policy):
                print(f'Script source matching for {key}')
            else:
                print(f'Script source not matching for {key}')
            if is_matching(live_policy[frame_str], frm_rec_policy):
                print(f'Frame source matching for {key}')
            else:
                print(f'Frame source not matching for {key}')

if __name__ == "__main__":
    main()