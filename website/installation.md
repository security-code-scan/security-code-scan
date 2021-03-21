# Installation
Security Code Scan (SCS) [can be installed as](https://docs.microsoft.com/en-us/visualstudio/code-quality/install-roslyn-analyzers):
* [Visual Studio extension](https://marketplace.visualstudio.com/items?itemName=JaroslavLobacevski.SecurityCodeScanVS2019). Use the link or open "Tools > Extensions and Updates..." Select "Online" in the tree on the left and search for SecurityCodeScan in the right upper field. Click "Download" and install.
* [NuGet package](https://www.nuget.org/packages/SecurityCodeScan.VS2019/).
  * Right-click on the root item in your solution. Select "Manage NuGet Packages for Solution...". Select "Browse" on the top and search for Security Code Scan. Select project you want to install into and click "Install".
  * Another option is to install the package into all projects in a solution: use "Tools > NuGet Package Manager > Package Manager Console". Run the command `Get-Project -All | Install-Package SecurityCodeScan`.
* [Stand-alone runner](https://www.nuget.org/packages/security-scan/). Install with `dotnet tool install --global security-scan` and run `security-scan /your/solution.sln`. For older .NET 4.x please use `security-scan4x.zip` from [GitHub Releases](https://github.com/security-code-scan/security-code-scan/releases).

All three options or running SCS have their own advantages.

Installing it as NuGet package allows to choose projects in a solution that should be analyzed. It is a good idea to exclude test projects, because they do not make it into a final product.  
> ⚠️Note:
> In previous versions of .NET Core, if you added a reference to a project that had a Roslyn analyzer as NuGet package, it was automatically added to the dependent project too. To disable this behavior, for example if the dependent project is a unit test project, make sure the NuGet package is added as private in the *.csproj* or *.vbproj* file of the referenced project:
>
> ```xml
> <PackageReference Include="SecurityCodeScan" Version="5.0.0" PrivateAssets="all" />
> ```

However it requires discipline to install SCS into every solution a developer works with. Installing it as a Visual Studio extension is a single install action.

The NuGet version runs during a build and in background as IntelliSense (VS extension provides IntelliSense only) and can be integrated to any Continuous Integration (CI) server that supports [MSBuild](https://msdn.microsoft.com/en-us/library/dd393574.aspx).

However as SCS become more powerful and requires more computation done in a background when installed as Visual Studio extension or added to a project as NuGet package, running SCS as stand-alone tool allows controlling when static analysis starts and finishes. Running the stand-alone tool allows customizing different parameters and exclude unit test projects:

![Stand-alone tool options](images/security-scan-tool.png)

## Continuous Integration Builds
Continuous Integration (CI) support for [GitHub](https://github.com/marketplace/actions/securitycodescan) and [GitLab](https://docs.gitlab.com/ee/user/application_security/sast/analyzers.html) pipelines. [Stand-alone runner](https://www.nuget.org/packages/security-scan/) or through [MSBuild](https://msdn.microsoft.com/en-us/library/dd393574.aspx) for custom integrations.
For custom integrations SCS is capable of producing results in SARIF format and displaying warnings with other build messages in the build output. SCS warnings are in the form of  
`[source file](line,column): warning SCS[rule id]: [warning description] [project_file]`  
