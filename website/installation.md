# Installation
Security Code Scan (SCS) can be installed as:
* [Visual Studio extension](https://marketplace.visualstudio.com/items?itemName=PhilippeArteau.RoslynSecurityGuard). Use the link or open "Tools > Extensions and Updates..." Select "Online" in the tree on the left and search for RoslynSecurityGuard in the right upper field. Click "Download" and install.
* [NuGet package](https://www.nuget.org/packages/RoslynSecurityGuard/).
  * Right-click on the root item in your solution. Select "Manage NuGet Packages for Solution...". Select "Browse" on the top and search for RoslynSecurityGuard. Select project you want to install into and click "Install".
  * Another option is to install the package into all projects in a solution: use "Tools > NuGet Package Manager > Package Manager Console". Run the command `Get-Project -All | Install-Package Roslyn.Security.Guard`.

Installing it as NuGet package gives an advantage to choose projects in a solution that should be analyzed. It is a good idea to exclude test projects, because they do not make it into a final product. However it requires discipline to install SCS into every solution a developer works with. Installing it as a Visual Studio extension is a single install action.

Because of the [Roslyn](https://github.com/dotnet/roslyn) technology SCS is based on only the NuGet version runs during a build (VS extension provides intellisense only) and can be integrated to any Continuous Integration (CI) server that supports [MSBuild](https://msdn.microsoft.com/en-us/library/dd393574.aspx).