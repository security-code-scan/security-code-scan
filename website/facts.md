# Quick Facts

<span class="octicon octicon-organization"/> Two modes: for Developers and Auditors.

<span class="octicon octicon-bug"/> Detects various [security vulnerability patterns](#rules): SQL Injection, Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), XML eXternal Entity Injection (XXE), etc.

<span class="octicon octicon-git-branch"/> Basic intraprocedural taint analysis for input data.

<span class="octicon octicon-code"/> Analyzes .NET and [.NET Core](https://en.wikipedia.org/wiki/.NET_Framework#.NET_Core) projects in a background (IntelliSense) or during a build.

<span class="octicon octicon-pulse"/> Continuous Integration (CI) through [MSBuild](https://msdn.microsoft.com/en-us/library/dd393574.aspx). For Unix CI runners please use [VS2017 NuGet package](https://www.nuget.org/packages/SecurityCodeScan.VS2017). See [Continuous Integration Builds section](#continuous-integration-builds) for instructions.

<span class="octicon octicon-plug"/> Works with Visual Studio 2015 or higher. Visual Studio [Community](https://www.visualstudio.com/en-us/products/visual-studio-community-vs.aspx), Professional and Enterprise editions are supported. Other editors that support Roslyn based analyzers like Rider or OmniSharp should work too.

<span class="octicon octicon-mark-github"/> [Open Source](https://github.com/security-code-scan/security-code-scan)
