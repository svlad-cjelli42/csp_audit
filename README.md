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

Example - Audit Passed
```
Getting csp for: https://example.com/ ...

	- default-src policy is matching for: https://example.com/

	- script-src policy is matching for: https://example.com/

	- frame-src policy is matching for: https://example.com/
```
Example - Audit Failed
```
Getting csp for: https://example.com/ ...

	- default-src policy mismatch for: https://example.com/

	- The recorded policy for the directive default-src has an extra entry:

		Mismatch found: vendor.com is in rec_policy but not in live_policy

Recorded Policy: 
[
    "vendor.com",
    "self"
]
Live Policy: 
[
    "self"
]

	- script-src policy is matching for: https://example.com/

	- frame-src policy is matching for: https://example.com/
```
