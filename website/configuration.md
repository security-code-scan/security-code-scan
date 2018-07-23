# Configuration
## Full Solution Analysis
*Full solution analysis* is a Visual Studio (2015 Update 3 RC and later) feature that enables you to choose whether you see code analysis issues only in open Visual C# or Visual Basic files in your solution, or in both open and closed Visual C# or Visual Basic files in your solution. For performance reasons it is disabled by default. It is not needed if SCS is installed as NuGet package. In VS extension case open Tools > Options in Visual Studio. Select Text Editor > C# (or Basic) > Advanced. Make sure the "Enable full solution analysis" is checked:

![Full Solution Analysis](images/fullsolution.png)  
Since *Full solution analysis* for IntelliSense has performance impact this is another reason to use Security Code Scan during a build only as a nuget instead of Visual Studio extension.
## Analyzing .aspx and web.config Files
To enable analysis of these files you need to modify all C#(.csproj) and VB.NET(.vbproj) projects in a solution and add "AdditionalFileItemNames" element as shown below:
```xml
<Project DefaultTargets="Build" ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <PropertyGroup>
    [..]
    <TargetFrameworkProfile />
    <!-- Add the line below -->
    <AdditionalFileItemNames>$(AdditionalFileItemNames);Content</AdditionalFileItemNames>
  </PropertyGroup>
```
The helper PowerShell script can be used to do it automatically for all projects in a subfolder:
```powershell
Get-ChildItem *.csproj -Recurse | ForEach-Object {
$content = [xml] (Get-Content $_)
     
if (-not $content.Project.PropertyGroup[0].AdditionalFileItemNames)
    {
    Write-Host "AdditionalFileItemNames missing in $_"
    $additionalFileItemNamesElt = $content.CreateElement("AdditionalFileItemNames",
    "http://schemas.microsoft.com/developer/msbuild/2003")
    $additionalFileItemNamesElt.set_InnerText('$(AdditionalFileItemNames);Content')
    $content.Project.PropertyGroup[0].AppendChild($additionalFileItemNamesElt)
    }

Set-ItemProperty $_ -name IsReadOnly -value $false
$content.Save($_)
# Normalize line endings
(Get-Content $_ -Encoding UTF8) | Set-Content $_ -Encoding UTF8
}
```
## External Configuration Files
There are two types of external configuration files that can be used together: per user account and per project. It allows you to customize built-in settings from https://github.com/security-code-scan/security-code-scan/blob/master/SecurityCodeScan/Config/Main.yml or add your specific Sinks and Behaviors. Global settings file location is %LocalAppData%\SecurityCodeScan\config-1.0.yml
An example of config-1.0.yml:
```
CsrfProtectionAttributes:
  -  HttpMethodsNameSpace: MyCompany.AspNetCore.Mvc
     AntiCsrfAttribute: MyNamespace.MyAntiCsrfAttribute
```

For project specific settings add SecurityCodeScan.config.yml into a project. Go to file properties and set the Build Action to AdditionalFiles:

![image](https://user-images.githubusercontent.com/26652396/43063175-d28dc288-8e63-11e8-90eb-a7cb31900aff.png)

An example of SecurityCodeScan.config.yml:
```
Version: 1.0
Sinks:
  MyKey:
    Namespace: MyNamespace
    ClassName: Test
    Member: method
    Name: VulnerableFunctionName
    InjectableArguments: [0]
    Locale: SCS0001
```
## Audit Mode
Audit mode is off by default. It can be turned on in an external configuration file to get warnings with more false positives.
## Testing on WebGoat.NET
Download an intentionally vulnerable project [WebGoat.NET](https://github.com/OWASP/WebGoat.NET/zipball/master) for testing. Open the solution. If you have installed SCS as a VS extension you should see warning after few seconds in the "Errors" tab. Make sure IntelliSense results are not filtered in the window:

![Intellisense](images/intellisense.png)

If SCS is installed as NuGet package you'll need to build the solution. Then you should see the warning in the "Errors" and "Output" tabs:

![Intellisense](images/output.png)
## Severity
Each warning severity is configurable: expand References > Analyzers > SecurityCodeScan under the project in a Solution window, right click on a warning ID and modify the severity. WebGoat.NET.ruleset will be automatically saved in the project's directory:

![Intellisense](images/severity.png)
## Troubleshooting
If no SCS warnings are displayed, temporarily disable other installed analyzers. A buggy analyzer may [affect results from other analyzers](https://github.com/dotnet/roslyn/issues/23879).
