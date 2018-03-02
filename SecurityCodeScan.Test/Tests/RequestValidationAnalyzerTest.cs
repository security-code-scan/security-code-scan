using System.Collections.Generic;
using System.Threading.Tasks;
using System.Web.Mvc;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Test.Helpers;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test
{
    [TestClass]
    public class RequestValidationAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new[] { new RequestValidationAnalyzer() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(ValidateInputAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Web.HttpRequestBase).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Web.Helpers.Validation).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestMethod]
        public async Task DetectAnnotationValidateInput()
        {
            var cSharpTest = @"
using System.Web.Mvc;

namespace VulnerableApp
{
    public class TestController
    {
        [HttpPost]
        [ValidateInput(false)]
        public ActionResult ControllerMethod(string input) {
            return null;
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Web.Mvc

Namespace VulnerableApp
    Public Class TestController
        <HttpPost> _
        <ValidateInput(False)> _
        Public Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0017",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectUnvalidatedProperty()
        {
            var cSharpTest = @"
using System.Web.Mvc;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [HttpPost]
        public ActionResult ControllerMethod(string input) {
            var test = Request.Unvalidated;
            return null;
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Web.Mvc

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller
        <HttpPost> _
        Public Function ControllerMethod(input As String) As ActionResult
            Dim test = Request.Unvalidated
            Return Nothing
        End Function
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id = "SCS0017",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 10, 32)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 9, 32)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectUnvalidatedMethod()
        {
            var cSharpTest = @"
using System.Web.Mvc;
using System.Web.Helpers;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [HttpPost]
        public ActionResult ControllerMethod(string input) {
            var test = Request.Unvalidated();
            return null;
        }
    }
}
";

            var expected = new DiagnosticResult
            {
                Id = "SCS0017",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 11, 32)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task IgnoreUnrelatedUnvalidatedMethod()
        {

            var cSharpTest = @"
using System.Web.Mvc;
using System.Web;

namespace VulnerableApp
{
    public static class Extension
    {
        public static void Unvalidated(this HttpRequestBase request){
        }
    }
    public class TestController : Controller
    {
        [HttpPost]
        public ActionResult ControllerMethod(string input) {
            Request.Unvalidated();
            return null;
        }
    }
}
";

            var expected = new DiagnosticResult
            {
                Id = "SCS0017",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
        }
    }
}
