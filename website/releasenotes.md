# Release Notes
## 2.7
[Insecure deserialization analyzers]((#SCS0028)) for multiple libraries and formatters:
* [Json.NET](https://www.newtonsoft.com/json)
* [BinaryFormatter](https://msdn.microsoft.com/en-us/library/system.runtime.serialization.formatters.binary.binaryformatter(v=vs.110).aspx)
* [FastJSON](https://github.com/mgholam/fastJSON)
* [JavaScriptSerializer](https://msdn.microsoft.com/en-us/library/system.web.script.serialization.javascriptserializer(v=vs.110).aspx)
* [DataContractJsonSerializer](https://msdn.microsoft.com/en-us/library/system.runtime.serialization.json.datacontractjsonserializer(v=vs.110).aspx)
* [NetDataContractSerializer](https://msdn.microsoft.com/en-us/library/system.runtime.serialization.netdatacontractserializer(v=vs.110).aspx)
* [XmlSerializer](https://msdn.microsoft.com/en-us/library/system.xml.serialization.xmlserializer(v=vs.110).aspx)
* and many more...

Added warning for the usage of AllowHtml attribute.  
Different input validation analyzer and CSRF analyzer improvements.

## 2.6.1
Exceptions analyzing VB.NET projects fixed.

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
