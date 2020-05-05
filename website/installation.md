# Installation
Security Code Scan (SCS) [can be installed as](https://docs.microsoft.com/en-us/visualstudio/code-quality/install-roslyn-analyzers):
* [Visual Studio extension](https://marketplace.visualstudio.com/items?itemName=JaroslavLobacevski.SecurityCodeScan). Use the link or open "Tools > Extensions and Updates..." Select "Online" in the tree on the left and search for SecurityCodeScan in the right upper field. Click "Download" and install.
* [NuGet package](https://www.nuget.org/packages/SecurityCodeScan/).
  * Right-click on the root item in your solution. Select "Manage NuGet Packages for Solution...". Select "Browse" on the top and search for Security Code Scan. Select project you want to install into and click "Install".
  * Another option is to install the package into all projects in a solution: use "Tools > NuGet Package Manager > Package Manager Console". Run the command `Get-Project -All | Install-Package SecurityCodeScan`.

Installing it as NuGet package gives an advantage to choose projects in a solution that should be analyzed. It is a good idea to exclude test projects, because they do not make it into a final product.  
> ⚠️Note:
> In a .NET Core project, if you add a reference to a project that has SCS as a NuGet package, it is automatically added to the dependent project too. To disable this behavior, for example if the dependent project is a unit test project, mark the NuGet package as private in the *.csproj* or *.vbproj* file of the referenced project:
>
> ```xml
> <PackageReference Include="SecurityCodeScan" Version="3.0.0" PrivateAssets="all" />
> ```

However it requires discipline to install SCS into every solution a developer works with. Installing it as a Visual Studio extension is a single install action.

The NuGet version runs during a build and in background as IntelliSense (VS extension provides IntelliSense only) and can be integrated to any Continuous Integration (CI) server that supports [MSBuild](https://msdn.microsoft.com/en-us/library/dd393574.aspx).

## Continuous Integration Builds
If the CI server of your choice is using MSBuild, then integration of SCS is just a matter of adding NuGet packages and collecting the output from the build. SCS warnings are in the form of  
`[source file](line,column): warning SCS[rule id]: [warning description] [project_file]`  
If your CI server doesn't support MSBuild, here is an example how it can be scripted to use Docker container for building:  
* `git clone` or copy by other means the sources of your project to a local directory.
* `docker run -ti --rm --volume $PWD/SourcesFolderName:/tmp/app -w /tmp/app microsoft/dotnet:2.0-sdk`
* `dotnet add src/SourcesFolderName/ProjectName.csproj package SecurityCodeScan.VS2017` to reference SCS NuGet package in specific project file. Repeat for every project you want to analyze. Strictly speaking the step is not necessary if the SCS NuGet package is already referenced in project during development.
> ⚠️If there is an error `Package 'SecurityCodeScan.VS2017' is incompatible with 'all' frameworks in project` try:  
a. `dotnet nuget locals all -c` as suggested in [this NuGet issue](https://github.com/NuGet/Home/issues/5127#issuecomment-360645795).  
b. or using `dotnet add src/SourcesFolderName/ProjectName.csproj package SecurityCodeScan` instead.  
* `dotnet build --no-incremental`
* Grep the output.
