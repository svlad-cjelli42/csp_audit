# Content Security Policy Auditing Script

### Used to compare a predefined json file containing the CSP of multiple URLs with that seen from on the live site.

This is currently only set up to check for the directives:
+ default-src
+ script-src
+ frame-src

Additional directives can be added by:
1. Adding a new string definition variable (i.e. image_str = 'image-src')
2. Adding the new directive to the directive_list list
3. Adding the new directive to the csp list within format_csp()

## Use

The csp.json file is a sample of how the predefined list should be formatted. 
csp_onboard.py can be used to create the file, appending a new CSP to the list.
```
csp_onboard.py {URL}
```

Once you have an audit file, csp_audit.py can be run periodically to check that the policy hasn't changed.
