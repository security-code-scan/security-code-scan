using System.Collections.Generic;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Config;
using SecurityCodeScan.Test.Helpers;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test.Taint
{
    [TestClass]
    public class SystemWebApiControllerEntryPointsTaintAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string _)
        {
            return new[] { new SqlInjectionTaintAnalyzer() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(System.Data.SqlClient.SqlCommand).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Web.Http.ApiController).Assembly.Location),
        };

        private DiagnosticResult Expected = new DiagnosticResult
        {
            Id       = "SCS0002",
            Severity = DiagnosticSeverity.Warning,
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [DataTestMethod]
        [DataRow("System.Web.Http", "public ", "MyController", "ApiController", true)]
        [DataRow("System.Web.Http", "internal ", "MyController", "ApiController", false)]
        [DataRow("System.Web.Http", "public ", "My",           "ApiController", false)]
        [DataRow("System.Web.Http", "public ", "MyController", "System.Object", false)]
        [DataRow("System.Web.Http", "public ", "MyController", "ApiController", false, "", "NonAction")]
        public async Task TaintSourceControllerRules(string @namespace,
                                                     string classsAccessibility,
                                                     string @class,
                                                     string baseClass,
                                                     bool warn,
                                                     string classAttr = "",
                                                     string methodAttr = "",
                                                     string paramAttr = "")
        {
            string csClassAttribute = "", vbClassAttribute = "", csParamAttribute = "", vbParamAttribute = "", csMethodAttr = "", vbMethodAttr = "";

            if (classAttr != "")
            {
                csClassAttribute = $"[{classAttr}]";
                vbClassAttribute = $"<{classAttr}>";
            }

            if (methodAttr != "")
            {
                csMethodAttr = $"[{methodAttr}]";
                vbMethodAttr = $"<{methodAttr}>";
            }

            if (paramAttr != "")
            {
                csParamAttribute = $"[{paramAttr}]";
                vbParamAttribute = $"<{paramAttr}>";
            }

            var cSharpTest = $@"
#pragma warning disable 8019
using {@namespace};
#pragma warning restore 8019

{classsAccessibility}class JustController {{}}

{csClassAttribute}
{classsAccessibility}class {@class} : {baseClass}
{{
    {csMethodAttr}
    public void Run({csParamAttribute}string input)
    {{
        Sink(input);
    }}

    private void Sink(string input) {{}}
}}
";

            var visualBasicTest = $@"
#Disable Warning BC50001
Imports {@namespace}
#Enable Warning BC50001

{classsAccessibility.CSharpReplaceToVBasic()}Class JustController
End Class

{vbClassAttribute}
{classsAccessibility.CSharpReplaceToVBasic()}Class {@class}
    Inherits {baseClass}

    {vbMethodAttr}
    Public Sub Run({vbParamAttribute}ByVal input As String)
        Sink(input)
    End Sub

    Private Sub Sink(ByVal input As String)
    End Sub
End Class

";

            var testConfig = $@"
Sinks:
  - Type: {@class}
    TaintTypes:
      - SCS0002
    Methods:
    - Name: Sink
      Arguments:
        - input
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            if (warn)
            {
                await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            }
        }
    }

    [TestClass]
    public class SystemWebMvcControllerEntryPointsTaintAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string _)
        {
            return new[] { new SqlInjectionTaintAnalyzer() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(System.Data.SqlClient.SqlCommand).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Web.Mvc.Controller).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Web.HttpRequestBase).Assembly.Location),
        };

        private DiagnosticResult Expected = new DiagnosticResult
        {
            Id       = "SCS0002",
            Severity = DiagnosticSeverity.Warning,
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [DataTestMethod]
        [DataRow("input", true)]
        [DataRow("Request.ToString()", false)]
        [DataRow("Request.AcceptTypes[0]", true)]
        [DataRow("Request.AnonymousID", true)]
        [DataRow("Request.ApplicationPath", false)]
        [DataRow("Request.AppRelativeCurrentExecutionFilePath", false)]
        [DataRow("Request.Browser.ToString()", true)]
        [DataRow("Request.ClientCertificate.Issuer", true)]
        [DataRow("Request.ContentEncoding.ToString()", false)]
        [DataRow("Request.ContentLength.ToString()", false)]
        [DataRow("Request.ContentType.ToString()", true)]
        [DataRow("Request.Cookies[\"auth\"].Value", true)]
        [DataRow("Request.CurrentExecutionFilePath", false)]
        [DataRow("Request.CurrentExecutionFilePathExtension", false)]
        [DataRow("Request.FilePath", false)]
        [DataRow("Request.Files[0].FileName", true)]
        [DataRow("Request.Filter.ToString()", false)]
        [DataRow("Request.Form[\"id\"]", true)]
        [DataRow("Request.Headers[0]", true)]
        [DataRow("Request.HttpChannelBinding.ToString()", false)]
        [DataRow("Request.HttpMethod", true)]
        [DataRow("Request.InputStream.ToString()", true)]
        [DataRow("Request.IsAuthenticated.ToString()", false)]
        [DataRow("Request.IsLocal.ToString()", false)]
        [DataRow("Request.IsSecureConnection.ToString()", false)]
        [DataRow("Request[\"id\"]", true)]
        [DataRow("Request.LogonUserIdentity.ToString()", false)]
        [DataRow("Request.Params[\"id\"]", true)]
        [DataRow("Request.Path", true)]
        [DataRow("Request.PathInfo", true)]
        [DataRow("Request.PhysicalApplicationPath", false)]
        [DataRow("Request.PhysicalPath", false)]
        [DataRow("Request.QueryString[\"id\"]", true)]
        [DataRow("Request.RawUrl", true)]
        [DataRow("Request.ReadEntityBodyMode.ToString()", false)]
        [DataRow("Request.RequestContext.HttpContext.ToString()", true)]
        [DataRow("Request.RequestType", true)]
        [DataRow("Request.ServerVariables[\"ALL_HTTP\"]", true)]
        [DataRow("Request.TimedOutToken.ToString()", false)]
        [DataRow("Request.TlsTokenBindingInfo.ToString()", false)]
        [DataRow("Request.TotalBytes.ToString()", false)]
        [DataRow("Request.Unvalidated.ToString()", true)]
        [DataRow("Request.Url.ToString()", true)]
        [DataRow("Request.UrlReferrer.ToString()", true)]
        [DataRow("Request.UserAgent", true)]
        [DataRow("Request.UserHostAddress", true)]
        [DataRow("Request.UserHostName", true)]
        [DataRow("Request.UserLanguages[0]", true)]
        [DataRow("Request.BinaryRead(100).ToString()", true)]
        [DataRow("Request.GetBufferedInputStream().ToString()", true)]
        [DataRow("Request.GetBufferlessInputStream(true).ToString()", true)]
        [DataRow("Request.GetBufferlessInputStream().ToString()", true)]
        [DataRow("ControllerContext.RouteData.Values[\"test\"].ToString()", true)]
        public async Task TaintSourceController(string payload, bool warn)
        {
            var cSharpTest = $@"
using System.Web.Mvc;

public class MyController : Controller
{{
    public void Run(string input)
    {{
        Sink({payload});
    }}

    private void Sink(string input) {{}}
}}
";

            payload = payload.CSharpReplaceToVBasic();
            var visualBasicTest = $@"
Imports System.Web.Mvc

Public Class MyController
    Inherits Controller

    Public Sub Run(ByVal input As String)
        Sink({payload})
    End Sub

    Private Sub Sink(ByVal input As String)
    End Sub
End Class

";

            var testConfig = @"
Sinks:
  - Type: MyController
    TaintTypes:
      - SCS0002
    Methods:
    - Name: Sink
      Arguments:
        - input
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            if (warn)
            {
                await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            }
        }

        [DataTestMethod]
        [DataRow("System.Web.Mvc", "public ", "MyController", "Controller", true)]
        [DataRow("System.Web.Mvc", "public ", "MyController", "System.Object", false)]
        [DataRow("System.Web.Mvc", "public ", "My", "Controller", false)]
        [DataRow("System.Web.Mvc", "public ", "MyController", "Controller", false, "", "NonAction")]
        public async Task TaintSourceControllerRules(string @namespace,
                                                     string classsAccessibility,
                                                     string @class,
                                                     string baseClass,
                                                     bool warn,
                                                     string classAttr = "",
                                                     string methodAttr = "",
                                                     string paramAttr = "")
        {
            string csClassAttribute = "", vbClassAttribute = "", csParamAttribute = "", vbParamAttribute = "", csMethodAttr = "", vbMethodAttr = "";

            if (classAttr != "")
            {
                csClassAttribute = $"[{classAttr}]";
                vbClassAttribute = $"<{classAttr}>";
            }

            if (methodAttr != "")
            {
                csMethodAttr = $"[{methodAttr}]";
                vbMethodAttr = $"<{methodAttr}>";
            }

            if (paramAttr != "")
            {
                csParamAttribute = $"[{paramAttr}]";
                vbParamAttribute = $"<{paramAttr}>";
            }

            var cSharpTest = $@"
#pragma warning disable 8019
using {@namespace};
#pragma warning restore 8019

{classsAccessibility}class JustController {{}}

{csClassAttribute}
{classsAccessibility}class {@class} : {baseClass}
{{
    {csMethodAttr}
    public void Run({csParamAttribute}string input)
    {{
        Sink(input);
    }}

    private void Sink(string input) {{}}
}}
";

            var visualBasicTest = $@"
#Disable Warning BC50001
Imports {@namespace}
#Enable Warning BC50001

{classsAccessibility.CSharpReplaceToVBasic()}Class JustController
End Class

{vbClassAttribute}
{classsAccessibility.CSharpReplaceToVBasic()}Class {@class}
    Inherits {baseClass}

    {vbMethodAttr}
    Public Sub Run({vbParamAttribute}ByVal input As String)
        Sink(input)
    End Sub

    Private Sub Sink(ByVal input As String)
    End Sub
End Class

";

            var testConfig = $@"
Sinks:
  - Type: {@class}
    TaintTypes:
      - SCS0002
    Methods:
    - Name: Sink
      Arguments:
        - input
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            if (warn)
            {
                await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            }
        }
    }

    [TestClass]
    public class AspNetCoreMvcEntryPointsTaintAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string _)
        {
            return new[] { new SqlInjectionTaintAnalyzer() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(System.Data.SqlClient.SqlCommand).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.Controller).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.ControllerBase).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Http.HttpRequest).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Http.IRequestCookieCollection).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.ActionContext).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Routing.RouteValueDictionary).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.Extensions.Primitives.StringValues).Assembly.Location),
            MetadataReference.CreateFromFile(Assembly.Load("netstandard, Version=2.0.0.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51")
                                                     .Location),
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        private DiagnosticResult Expected = new DiagnosticResult
        {
            Id       = "SCS0002",
            Severity = DiagnosticSeverity.Warning,
        };

        [DataTestMethod]
        [DataRow("input", true)]
        [DataRow("Request.ToString()", false)]
        [DataRow("Request.Body.ToString()", true)]
        [DataRow("Request.ContentLength.ToString()", false)]
        [DataRow("Request.ContentType.ToString()", true)]
        [DataRow("Request.Cookies[\"auth\"]", true)]
        [DataRow("Request.Form[\"id\"]", true)]
        [DataRow("Request.HasFormContentType.ToString()", false)]
        [DataRow("Request.Headers[\"x\"]", true)]
        [DataRow("Request.Host.Host", true)]
        [DataRow("Request.HttpContext.Items[0].ToString()", true)]
        [DataRow("Request.IsHttps.ToString()", false)]
        [DataRow("Request.Method", true)]
        [DataRow("Request.Path", true)]
        [DataRow("Request.PathBase", true)]
        [DataRow("Request.Protocol", true)]
        [DataRow("Request.Query[\"id\"]", true)]
        [DataRow("Request.QueryString.Value", true)]
        [DataRow("Request.Scheme", true)]
        [DataRow("Request.ReadFormAsync(System.Threading.CancellationToken.None).ToString()", true)]
        [DataRow("ControllerContext.RouteData.Values[\"test\"].ToString()", true)]
        public async Task TaintSourceControllerCore(string payload, bool warn)
        {
            var cSharpTest = $@"
using Microsoft.AspNetCore.Mvc;

public class MyController : Controller
{{
    public void Run(string input)
    {{
        Sink({payload});
    }}

    private void Sink(string input) {{}}
}}
";

            payload = payload.CSharpReplaceToVBasic();
            var visualBasicTest = $@"
Imports Microsoft.AspNetCore.Mvc

Public Class MyController
    Inherits Controller

    Public Sub Run(ByVal input As String)
        Sink({payload})
    End Sub

    Private Sub Sink(ByVal input As String)
    End Sub
End Class

";

            var testConfig = @"
Sinks:
  - Type: MyController
    TaintTypes:
      - SCS0002
    Methods:
    - Name: Sink
      Arguments:
        - input
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            if (warn)
            {
                await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            }
        }

        [DataTestMethod]
        [DataRow("Microsoft.AspNetCore.Mvc", "public ",   "MyController", "Controller", true)]
        [DataRow("Microsoft.AspNetCore.Mvc", "internal ", "MyController", "Controller", false)]
        [DataRow("Microsoft.AspNetCore.Mvc", "public ", "MyController", "System.Object", true)]
        [DataRow("Microsoft.AspNetCore.Mvc", "public ", "My", "Controller", true)]
        [DataRow("Microsoft.AspNetCore.Mvc", "public ", "My", "JustController", true)]
        [DataRow("Microsoft.AspNetCore.Mvc", "public ", "My", "System.Object", false)]
        [DataRow("Microsoft.AspNetCore.Mvc", "public ", "My", "System.Object", true, "Controller")]
        [DataRow("Microsoft.AspNetCore.Mvc", "public ", "My", "Controller", false, "NonController")]
        [DataRow("Microsoft.AspNetCore.Mvc", "public ", "My", "Controller", false, "", "NonAction")]
        [DataRow("Microsoft.AspNetCore.Mvc", "public ", "My", "Controller", false, "", "", "FromServices")]
        public async Task TaintSourceControllerRules(string @namespace, string classsAccessibility, string @class, string baseClass, bool warn, string classAttr = "", string methodAttr = "", string paramAttr = "")
        {
            string csClassAttribute = "", vbClassAttribute = "", csParamAttribute = "", vbParamAttribute = "", csMethodAttr = "", vbMethodAttr = "";

            if (classAttr != "")
            {
                csClassAttribute = $"[{classAttr}]";
                vbClassAttribute = $"<{classAttr}>";
            }

            if (methodAttr != "")
            {
                csMethodAttr = $"[{methodAttr}]";
                vbMethodAttr = $"<{methodAttr}>";
            }

            if (paramAttr != "")
            {
                csParamAttribute = $"[{paramAttr}]";
                vbParamAttribute = $"<{paramAttr}>";
            }

            var cSharpTest = $@"
#pragma warning disable 8019
using {@namespace};
#pragma warning restore 8019

{classsAccessibility}class JustController {{}}

{csClassAttribute}
{classsAccessibility}class {@class} : {baseClass}
{{
    {csMethodAttr}
    public void Run({csParamAttribute}string input)
    {{
        Sink(input);
    }}

    private void Sink(string input) {{}}
}}
";

            var visualBasicTest = $@"
#Disable Warning BC50001
Imports {@namespace}
#Enable Warning BC50001

{classsAccessibility.CSharpReplaceToVBasic()}Class JustController
End Class

{vbClassAttribute}
{classsAccessibility.CSharpReplaceToVBasic()}Class {@class}
    Inherits {baseClass}

    {vbMethodAttr}
    Public Sub Run({vbParamAttribute}ByVal input As String)
        Sink(input)
    End Sub

    Private Sub Sink(ByVal input As String)
    End Sub
End Class

";

            var testConfig = $@"
Sinks:
  - Type: {@class}
    TaintTypes:
      - SCS0002
    Methods:
    - Name: Sink
      Arguments:
        - input
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            if (warn)
            {
                await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            }
        }
    }

    [TestClass]
    public class AspNetCoreMvcApiControllerEntryPointsTaintAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string _)
        {
            return new[] { new SqlInjectionTaintAnalyzer() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(System.Data.SqlClient.SqlCommand).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.ControllerBase).Assembly.Location),
            MetadataReference.CreateFromFile(Assembly.Load("netstandard, Version=2.0.0.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51")
                                                     .Location),
        };

        private DiagnosticResult Expected = new DiagnosticResult
        {
            Id       = "SCS0002",
            Severity = DiagnosticSeverity.Warning,
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [DataTestMethod]
        [DataRow("Microsoft.AspNetCore.Mvc", "public ",   "MyController", "ControllerBase", true, "ApiController")]
        [DataRow("Microsoft.AspNetCore.Mvc", "internal ", "MyController", "ControllerBase", false, "ApiController")]

        [DataRow("Microsoft.AspNetCore.Mvc", "public ", "MyController", "System.Object", true)]
        [DataRow("Microsoft.AspNetCore.Mvc", "public ", "My",           "System.Object", false)]
        [DataRow("Microsoft.AspNetCore.Mvc", "public ", "My",           "System.Object", true, "ApiController")]
        [DataRow("Microsoft.AspNetCore.Mvc", "public ", "My",           "System.Object", true, "Controller")]

        [DataRow("Microsoft.AspNetCore.Mvc", "public ", "My",           "ControllerBase", true, "")]
        // todo:? same rule is used for aspNetCoreController because we can't have two rules for System.Object
        // however the difference is ApiController doesn't check if parent name suffix is 'Controller'
        //[DataRow("Microsoft.AspNetCore.Mvc", "public ", "My",           "JustController", false, "")]
        [DataRow("Microsoft.AspNetCore.Mvc", "public ", "My",           "JustController", true, "", "ApiController")]
        [DataRow("Microsoft.AspNetCore.Mvc", "public ", "My",           "JustController", true, "", "Controller")]

        [DataRow("Microsoft.AspNetCore.Mvc", "public ", "MyController", "ControllerBase", false, "ApiController", "", "NonAction")]
        [DataRow("Microsoft.AspNetCore.Mvc", "public ", "MyController", "ControllerBase", false, "ApiController", "", "",       "FromServices")]
        [DataRow("Microsoft.AspNetCore.Mvc", "public ", "MyController", "ControllerBase", false, "NonController")]
        public async Task TaintSourceControllerRules(string @namespace,
                                                     string classsAccessibility,
                                                     string @class,
                                                     string baseClass,
                                                     bool warn,
                                                     string classAttr = "",
                                                     string baseClassAttr = "",
                                                     string methodAttr = "",
                                                     string paramAttr = "")
        {
            string csClassAttribute = "", vbClassAttribute = "", csParamAttribute = "", vbParamAttribute = "", csMethodAttr = "", vbMethodAttr = "";

            if (classAttr != "")
            {
                csClassAttribute = $"[{classAttr}]";
                vbClassAttribute = $"<{classAttr}>";
            }

            if (methodAttr != "")
            {
                csMethodAttr = $"[{methodAttr}]";
                vbMethodAttr = $"<{methodAttr}>";
            }

            if (paramAttr != "")
            {
                csParamAttribute = $"[{paramAttr}]";
                vbParamAttribute = $"<{paramAttr}>";
            }

            var cSharpTest = $@"
#pragma warning disable 8019
using {@namespace};
#pragma warning restore 8019

{classsAccessibility} class JustController {{}}

{csClassAttribute}
{classsAccessibility} class {@class} : {baseClass}
{{
    {csMethodAttr}
    public void Run({csParamAttribute}string input)
    {{
        Sink(input);
    }}

    private void Sink(string input) {{}}
}}
";

            var visualBasicTest = $@"
#Disable Warning BC50001
Imports {@namespace}
#Enable Warning BC50001

{classsAccessibility.CSharpReplaceToVBasic()}Class JustController
End Class

{vbClassAttribute}
{classsAccessibility.CSharpReplaceToVBasic()}Class {@class}
    Inherits {baseClass}

    {vbMethodAttr}
    Public Sub Run({vbParamAttribute}ByVal input As String)
        Sink(input)
    End Sub

    Private Sub Sink(ByVal input As String)
    End Sub
End Class

";

            var testConfig = $@"
Sinks:
  - Type: {@class}
    TaintTypes:
      - SCS0002
    Methods:
    - Name: Sink
      Arguments:
        - input
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            if (warn)
            {
                await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            }
        }
    }
}
