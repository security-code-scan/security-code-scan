using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Helpers;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test.Taint
{
    [TestClass]
    public class OpenRedirectAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new[] { new TaintAnalyzer() };
        }

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[]
            {
                MetadataReference.CreateFromFile(typeof(System.Web.HttpResponse).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Http.HttpResponse).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.Controller).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.ControllerBase).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Web.Mvc.ActionResult).Assembly.Location),
            };
        }

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

    public static void Run(string input)
    {{
        {sink};
    }}
}}
";

            var visualBasicTest = $@"
Imports {@namespace}

Class OpenRedirect
    Public Shared Response As HttpResponse

    Public Shared Sub Run(input As String)
        {sink}
    End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0027",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

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

    public static void Run(bool flag)
    {{
        {sink};
    }}
}}
";

            var visualBasicTest = $@"
Imports {@namespace}

Class OpenRedirect
    Public Shared Response As HttpResponse

    Public Shared Sub Run(flag As Boolean)
        {sink}
    End Sub
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [DataRow("System.Web.Mvc",           "Redirect(input)")]
        [DataRow("System.Web.Mvc",           "RedirectPermanent(input)")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Redirect(input)")]
        [DataRow("Microsoft.AspNetCore.Mvc", "RedirectPermanent(input)")]
        // todo: AspNetCore 2.0
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

            var expected = new DiagnosticResult
            {
                Id       = "SCS0027",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        [DataRow("System.Web.Mvc",           "Redirect(\"\")")]
        [DataRow("System.Web.Mvc",           "RedirectPermanent(\"\")")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Redirect(\"\")")]
        [DataRow("Microsoft.AspNetCore.Mvc", "RedirectPermanent(\"\")")]
        // todo: AspNetCore 2.0
        //[DataRow("Microsoft.AspNetCore.Mvc", "RedirectPreserveMethod(\"\")")]
        //[DataRow("Microsoft.AspNetCore.Mvc", "RedirectPermanentPreserveMethod(\"\")")]
        [DataTestMethod]
        public async Task OpenRedirectControllerConst(string @namespace, string sink)
        {
            var cSharpTest = $@"
using {@namespace};

class OpenRedirect : Controller
{{
    public ActionResult Run()
    {{
        return {sink};
    }}
}}
";

            var visualBasicTest = $@"
Imports {@namespace}

Public Class OpenRedirect
    Inherits Controller

    Public Function Run() as ActionResult
        Return {sink}
    End Function
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }
    }
}
