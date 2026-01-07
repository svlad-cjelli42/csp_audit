import requests
import json
import re

default_str = 'default-src'
script_str = 'script-src'
frame_str = 'frame-src'

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
        if i.lstrip().startswith(default_str):
            default_src = i
            for p in default_src.split(' '):
                p = remove_quotes(p)
                if not p == '' and not p.strip() == default_str and is_not_nonce_or_hash(p):
                    csp[default_str].append(p)
        if i.lstrip().startswith(script_str):
            script_src = i
            for p in script_src.split(' '):
                p = remove_quotes(p)
                if not p == '' and not p.strip() == script_str and is_not_nonce_or_hash(p):
                    csp[script_str].append(p)
        if i.lstrip().startswith(frame_str):
            frame_src = i
            for p in frame_src.split(' '):
                p = remove_quotes(p)
                if not p == '' and not p.strip() == frame_str and is_not_nonce_or_hash(p):
                    csp[frame_str].append(p)
    return csp

def remove_quotes(string):
    if string.startswith("'") and string.endswith("'") or string.startswith("'") and string.endswith("'"):
        string = string[1:-1].strip()
    return string

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