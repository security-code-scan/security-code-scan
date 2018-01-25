# Release Notes
## 2.5.0
Different improvements were made to taint analysis. The analysis was extended from local variables into member variables.
False positives fixes in:
* XSS analyzer
* Weak hash analyzer. Added more patterns.
* Path traversal. Also added more patterns.

New feature:
* Open redirect detection.