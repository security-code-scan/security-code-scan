# Release Notes

## 5.6.2
* Blue-yellow edition in support of Ukraine.

## 5.6.1
* Fixed #239 "Adding custom sanitizers to a config file in stand-alone runner".

## 5.6.0
* Added support for .NET 6.0 and VS2022

## 5.2.1
* New parameter `--ignore-msbuild-errors` for standalone runner to ignore errors from incompatible projects.
* Bug fixes and improvements.

## 5.1.0
* Standalone runner improved. My favorite way to run SCS!
* Bug fixes and improvements.
* A [script](https://github.com/SPoint42/SecurityTools/tree/main/SCDotNet2DefectDojo) was made by [Sebastien gioria](https://github.com/SPoint42) for importing the analysis results into [DefectDojo](https://github.com/DefectDojo/django-DefectDojo).

## 5.0.0
* New inter-procedural taint analysis engine.
* New sinks and sources.
* Bug fixes.
* Standalone tool.

## 3.5.3
* Removed EntityFramework "Interpolated" sinks that caused false positives.
* Added configuration entry for Web Config analyzer to allow filtering file names.

## 3.5.2
Bugfix release.
* Fix MissingMethodException "Method not found: 'YamlDotNet.Serialization.IDeserializer YamlDotNet.Serialization.DeserializerBuilder.Build()'" if incompatible version of YamlDotNet is loaded by the process.

## 3.5.0
* Better taint analysis in implicit string conversions case.
* Out of range exception fix.
* New SQL injection and Path Traversal sinks.

Thanks [@watfordgnf](https://github.com/watfordgnf) and [@indy-singh](https://github.com/indy-singh) for the contributions!

## 3.4.0
* XSS analyzer was rewritten. Additional sanitizers were added.
* Added [ReportAnalysisCompletion](https://github.com/security-code-scan/security-code-scan/commit/792c265cd218ea7abb8433d52ca159eb90ab91ae#diff-34b8f54577569f3aae468b7f58cc5d02) option to output a message that the analysis did run.
* Bugfixes and improvements.

## 3.3.0
* Better C# 7 handling
* CSRF analyzer configuration made more flexible.  
  Configuration file schema version has changed to 2.0, so if you had custom config settings, you’ll need to adjust to the schema and bump your file name from config-2.0.yml to config-2.1.yml or change from Version: 2.0 to Version: 2.1 if it was added to a project.
* Bug fixes.

Thanks [@kevin-montrose](https://github.com/kevin-montrose) for the contributions!

## 3.2.0
Bugfix release.
* Fixes using SCS as nuget. [#117](https://github.com/security-code-scan/security-code-scan/issues/117)
* One click code fixes were removed until a separate assembly is created. [#71](https://github.com/security-code-scan/security-code-scan/issues/71)

## 3.1.0
The release adds support for VS2019 and bug fixes. Also:
* Adds multiple XSS sinks for WebForms (thanks [Andrei!](https://github.com/zaichenko))
* Changes in SCS configuration file doesn't require to restart Visual Studio anymore.
* Warnings are suppressed for generated code.
* Adds .NET Core cookie analyzer.

## 3.0.0
This is a major release that introduces configurable taint sources, sanitizers and validators. Configuration file schema version has changed to 2.0, so if you had custom config settings, you'll need to adjust to the schema and bump your file name from `config-1.0.yml` to `config-2.0.yml` or change from `Version: 1.0` to `Version: 2.0` if it was added to a project.  
With the introduction of taint sources and taint entry points warning are shown only for the tainted data. Unknowns are reported only in the Audit Mode.  
Multiple improvements and fixes were done to Taint, Anti-CSRF token, XSS, SQL injection, Path traversal, XPath injection, Certificate validation analyzers.  
New LDAP injection detection was added.  
An issue was fixed that could surface as `Session Terminated unexpectedly. Disabling 'Security Code Scan' might help prevent...`.

I would like to thank all [contributors](https://github.com/security-code-scan/security-code-scan/graphs/contributors) to this and previous releases. Also to everyone who has reported [issues or feature requests](https://github.com/security-code-scan/security-code-scan/issues?utf8=%E2%9C%93&q=is%3Aissue).  

## 2.8.0
**Important:** This release targets full .NET framework and **may** not run on Unix machines. Although as tested it runs fine in [microsoft/dotnet 2.1 docker container](https://hub.docker.com/r/microsoft/dotnet/) on Linux, still for Unix based Continuous Integration builds it is better to use [SecurityCodeScan.VS2017 NuGet package](https://www.nuget.org/packages/SecurityCodeScan.VS2017), that targets netstandard.

Added external configuration files: per user account and per project. It allows you to customize settings from [built-in configuration](https://github.com/security-code-scan/security-code-scan/blob/master/SecurityCodeScan/Config/Main.yml) or add your specific Sinks and Behaviors.  
> ⚠️Note: Configuration schema has changed in version 3.0.0 please refer to the documentation above for examples.

Audit Mode setting (Off by default) was introduced for those interested in warnings with more false positives.

## 2.7.1
Couple of issues related to VB.NET fixed:
* VB.NET projects were not analyzed when using the analyzer from NuGet.
* 'Could not load file or assembly 'Microsoft.CodeAnalysis.VisualBasic, Version=1.0.0.0...' when building C# .NET Core projects from command line with dotnet.exe

## 2.7.0
[Insecure deserialization analyzers](#SCS0028) for multiple libraries and formatters:
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
