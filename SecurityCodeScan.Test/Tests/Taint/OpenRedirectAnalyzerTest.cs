using System.Collections.Generic;
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
    public class OpenRedirectAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            return new DiagnosticAnalyzer[] { new TaintAnalyzerCSharp(), new TaintAnalyzerVisualBasic(), };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(System.Web.HttpResponse).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Web.Mvc.ActionResult).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Http.HttpResponse).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.Controller).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.ControllerBase).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.IUrlHelper).Assembly.Location),
        };

        private DiagnosticResult Expected = new DiagnosticResult
        {
            Id       = "SCS0027",
            Severity = DiagnosticSeverity.Warning,
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestCategory("Detect")]
        [DataRow("System.Web",                "Response.Redirect(input)")]
        [DataRow("System.Web",                "Response.Redirect(input, true)")]
        [DataRow("System.Web",                "Response.RedirectPermanent(input)")]
        [DataRow("System.Web",                "Response.RedirectPermanent(input, true)")]
        [DataRow("Microsoft.AspNetCore.Http", "Response.Redirect(input)")]
        [DataRow("Microsoft.AspNetCore.Http", "Response.Redirect(input, true)")]
        [DataTestMethod]
        public async Task OpenRedirect(string @namespace, string sink)
        {
            var cSharpTest = $@"
using {@namespace};

class OpenRedirect
{{
    public static HttpResponse Response = null;

    public void Run(string input)
    {{
        {sink};
    }}
}}
";

            var visualBasicTest = $@"
Imports {@namespace}

Class OpenRedirect
    Public Shared Response As HttpResponse

    Public Sub Run(input As String)
        {sink}
    End Sub
End Class
";

            var testConfig = @"
TaintEntryPoints:
  AAA:
    ClassName: OpenRedirect
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [DataRow("System.Web",                "Response.Redirect(\"\")")]
        [DataRow("System.Web",                "Response.Redirect(\"\", flag)")]
        [DataRow("System.Web",                "Response.RedirectPermanent(\"\")")]
        [DataRow("System.Web",                "Response.RedirectPermanent(\"\", flag)")]
        [DataRow("Microsoft.AspNetCore.Http", "Response.Redirect(\"\")")]
        [DataRow("Microsoft.AspNetCore.Http", "Response.Redirect(\"\", flag)")]
        [DataTestMethod]
        public async Task OpenRedirectConst(string @namespace, string sink)
        {
            var cSharpTest = $@"
using {@namespace};

class OpenRedirect
{{
    public static HttpResponse Response = null;

    public void Run(bool flag)
    {{
        {sink};
    }}
}}
";

            var visualBasicTest = $@"
Imports {@namespace}

Class OpenRedirect
    Public Shared Response As HttpResponse

    Public Sub Run(flag As Boolean)
        {sink}
    End Sub
End Class
";

            var testConfig = @"
TaintEntryPoints:
  AAA:
    ClassName: OpenRedirect
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataRow("System.Web.Mvc",           "Redirect(input)")]
        [DataRow("System.Web.Mvc",           "RedirectPermanent(input)")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Redirect(input)")]
        [DataRow("Microsoft.AspNetCore.Mvc", "RedirectPermanent(input)")]
        [DataRow("System.Web.Mvc",           "new RedirectResult(input)")]
        [DataRow("System.Web.Mvc",           "new RedirectResult(input, true)")]
        [DataRow("Microsoft.AspNetCore.Mvc", "new RedirectResult(input)")]
        [DataRow("Microsoft.AspNetCore.Mvc", "new RedirectResult(input, true)")]
        // todo: AspNetCore 2.0
        //[DataRow("Microsoft.AspNetCore.Mvc", "new RedirectResult(input, true, true)")]
        //[DataRow("Microsoft.AspNetCore.Mvc", "RedirectPreserveMethod(input)")]
        //[DataRow("Microsoft.AspNetCore.Mvc", "RedirectPermanentPreserveMethod(input)")]
        [DataTestMethod]
        public async Task OpenRedirectController(string @namespace, string sink)
        {
            var cSharpTest = $@"
using {@namespace};

class OpenRedirect : Controller
{{
    public ActionResult Run(string input)
    {{
        return {sink};
    }}
}}
";

            var visualBasicTest = $@"
Imports {@namespace}

Public Class OpenRedirect
    Inherits Controller

    Public Function Run(input As String) as ActionResult
        Return {sink}
    End Function
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [DataRow("System.Web.Mvc",           "Redirect(\"\")")]
        [DataRow("System.Web.Mvc",           "RedirectPermanent(\"\")")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Redirect(\"\")")]
        [DataRow("Microsoft.AspNetCore.Mvc", "RedirectPermanent(\"\")")]
        [DataRow("System.Web.Mvc",           "new RedirectResult(\"\")")]
        [DataRow("System.Web.Mvc",           "new RedirectResult(\"\", flag)")]
        [DataRow("Microsoft.AspNetCore.Mvc", "new RedirectResult(\"\")")]
        [DataRow("Microsoft.AspNetCore.Mvc", "new RedirectResult(\"\", flag)")]
        // todo: AspNetCore 2.0
        //[DataRow("Microsoft.AspNetCore.Mvc", "new RedirectResult(\"\", flag, flag)")]
        //[DataRow("Microsoft.AspNetCore.Mvc", "RedirectPreserveMethod(\"\")")]
        //[DataRow("Microsoft.AspNetCore.Mvc", "RedirectPermanentPreserveMethod(\"\")")]
        [DataRow("System.Web.Mvc",           "Redirect(Url.RouteUrl(new {controller = input}) + \"#Id\")")]
        [DataTestMethod]
        public async Task OpenRedirectControllerConst(string @namespace, string sink)
        {
            var cSharpTest = $@"
using {@namespace};

class OpenRedirect : Controller
{{
    public ActionResult Run(bool flag, string input)
    {{
        return {sink};
    }}
}}
";

            sink = sink.CSharpReplaceToVBasic();
            var visualBasicTest = $@"
Imports {@namespace}

Public Class OpenRedirect
    Inherits Controller

    Public Function Run(flag As Boolean, input As System.String) as ActionResult
        Return {sink}
    End Function
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataRow("Microsoft.AspNetCore.Mvc")]
        [DataTestMethod]
        public async Task OpenRedirectController2(string @namespace)
        {
            var cSharpTest1 = $@"
using {@namespace};

class OpenRedirect : Controller
{{
    public ActionResult Run(string input)
    {{
        var a = new RedirectResult("""");
        a.Url = input;
        return a;
    }}
}}
";

            var cSharpTest2 = $@"
using {@namespace};

class OpenRedirect : Controller
{{
    public ActionResult Run(string input)
    {{
        return new RedirectResult("""") {{Url = input}};
    }}
}}
";

            var visualBasicTest = $@"
Imports {@namespace}

Public Class OpenRedirect
    Inherits Controller

    Public Function Run(input As String) as ActionResult
        Dim a As New RedirectResult("""")
        a.Url = input
        Return a
    End Function
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest1, Expected).ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest2, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Url = \"\"")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Url = Url.RouteUrl(input)")]
        [DataTestMethod]
        public async Task OpenRedirectController2Const(string @namespace, string sink)
        {
            var cSharpTest1 = $@"
using {@namespace};

class OpenRedirect : Controller
{{
    public ActionResult Run(string input)
    {{
        var a = new RedirectResult("""");
        a.{sink};
        return a;
    }}
}}
";

            var cSharpTest2 = $@"
using {@namespace};

class OpenRedirect : Controller
{{
    public ActionResult Run(string input)
    {{
        return new RedirectResult("""") {{{sink}}};
    }}
}}
";

            var visualBasicTest = $@"
Imports {@namespace}

Public Class OpenRedirect
    Inherits Controller

    Public Function Run(input As String) as ActionResult
        Dim a As New RedirectResult("""")
        a.{sink}
        Return a
    End Function
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest1).ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest2).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }
    }
}
