# Content Security Policy Auditing Script

### Used to compare a predefined json file containing the CSP of multiple URLs with that seen from on the live site.

This is currently only set up to check for the directives:
+ default-src
+ script-src
+ frame-src

Additional directives can be added by modifying directive_list.

## Use

The csp.json file is a sample of how the predefined list should be formatted. 
csp_onboard.py can be used to create the file, appending a new CSP to the list.
```
csp_onboard.py {URL}
```

Once you have an audit file, csp_audit.py can be run periodically to audit for policy changes.
