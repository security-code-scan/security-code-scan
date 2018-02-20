# Release Notes
## 2.6.0
XXE analysis expanded.
More patterns to detect Open Redirect and Path Traversal.
Weak hash analyzer fixes.
Added request validation aspx analyzer.
False positives reduced in hardcoded password manager.

Web.config analysis:
* The feature was broken. [See how to enable.](#AnalyzingConfigFiles)
* Added detection of request validation mode.
* Diagnostic messages improved.

Taint improvements:
* Area expanded.
* Taint diagnostic messages include which passed parameter is untrusted.

## 2.5.0
Various improvements were made to taint analysis. The analysis was extended from local variables into member variables.
False positive fixes in:
* XSS analyzer.
* Weak hash analyzer. Added more patterns.
* Path traversal. Also added more patterns.

New features:
* Open redirect detection.