[![Security Code Scan](website/images/logo.png)](https://security-code-scan.github.io)  
*Vulnerability Patterns Detector for C# and VB.NET* - [Website](https://security-code-scan.github.io)  

[![Build](https://github.com/security-code-scan/security-code-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/security-code-scan/security-code-scan/actions/workflows/ci.yml)

### Downloading
Official releases are available as [nuget package](https://www.nuget.org/packages/SecurityCodeScan.VS2019/), [Visual Studio extension](https://marketplace.visualstudio.com/items?itemName=JaroslavLobacevski.SecurityCodeScanVS2019) and [stand-alone runner](https://www.nuget.org/packages/security-scan/).  

### Building
```
git clone https://github.com/security-code-scan/security-code-scan.git
cd security-code-scan
```
Open `SecurityCodeScan.sln` in Visual Studio or build from command line:
```
nuget restore SecurityCodeScan.sln
msbuild SecurityCodeScan.sln
```

### Contributing
* All documentation from the [official site](https://security-code-scan.github.io) is open-source and located in the [website](https://github.com/security-code-scan/security-code-scan/tree/vs2019/website) folder. Feel free to modify the markdown files and contribute to it.
* You may customize the behavior of Security Code Scan by creating a local configuration file as described in [ExternalConfigurationFiles section](https://security-code-scan.github.io/#ExternalConfigurationFiles). It is easy to add new vulnerable functions (sinks) that should trigger a warning, define untrusted sources, etc. Once you think you have working configuration file you are welcome to contribute your changes to the main built-in configuration file. Ideally your Pull Request comes with tests that cover the changes.
* Review the list of available [issues.](https://github.com/security-code-scan/security-code-scan/issues) The general understanding of Roslyn might be handy:
  - [Use Roslyn to Write a Live Code Analyzer for Your API](https://docs.microsoft.com/en-us/archive/msdn-magazine/2014/special-issue/csharp-and-visual-basic-use-roslyn-to-write-a-live-code-analyzer-for-your-api)
  - [Getting Started with Roslyn Analyzers](https://docs.microsoft.com/en-us/visualstudio/extensibility/getting-started-with-roslyn-analyzers?view=vs-2015&redirectedfrom=MSDN)
  - ["Learn Roslyn Now" by Josh Varty](https://joshvarty.com/learn-roslyn-now/)
  - [Online syntax tree visualizer](https://sharplab.io/)

### Tests
Most of the tests are written in two languages: C# and VB.NET. If you aren't an expert in VB.NET (me neither) use [any online converter](https://converter.telerik.com/) to create the VB.NET counterpart from tested C# code example.  
Tests are ideal for developing features and fixing bugs as it is easy to debug.

### Debugging
In case you are not sure what is wrong or you see AD0001 error with an exception, it is possible to debug the analysis of problematic Visual Studio solution.  
> Visual Studio offloads some static analysis work to a separate process. It is a good idea to uncomment [the lines](https://github.com/security-code-scan/security-code-scan/blob/b246418f5d17ba8634ffd70295da636ee3596fc5/SecurityCodeScan/Analyzers/Analyzers.cs#L134-L135) to have a chance to debug the child process.

First, make sure there are no Security Code Scan Visual Studio extensions installed to avoid interference.  
Right click `SecurityCodeScan.Vsix` project in the solution and choose `Set as StartUp project`.  
Start debugging in Visual Studio. It will open another instance of Visual Studio with debugger attached.  
Open the solution with the problematic source.  

