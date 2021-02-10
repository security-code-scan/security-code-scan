# Security static code analyzer for .NET
[Website](https://security-code-scan.github.io)

* Detects various [security vulnerability patterns](https://security-code-scan.github.io/#rules): SQL Injection, Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), XML eXternal Entity Injection (XXE), etc.

* Basic intraprocedural taint analysis for input data.

* Analyzes .NET and [.NET Core](https://en.wikipedia.org/wiki/.NET_Framework#.NET_Core) projects in a background (IntelliSense) or during a build.

* Continuous Integration (CI) with [GitHub action](https://github.com/marketplace/actions/securitycodescan) or through [MSBuild](https://msdn.microsoft.com/en-us/library/dd393574.aspx).

* Works with Visual Studio 2019 or higher. Visual Studio [Community](https://www.visualstudio.com/en-us/products/visual-studio-community-vs.aspx), Professional and Enterprise editions are supported. Other editors that support Roslyn based analyzers like Rider or OmniSharp should work too.

* [Open Source](https://github.com/security-code-scan/security-code-scan)