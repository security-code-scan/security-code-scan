using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Web.Mvc;
using TestHelper;

namespace SecurityCodeScan.Test.Tests
{
    [TestClass]
    public class RequestValidationAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new[] { new RequestValidationAnalyzer() };
        }

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[] { MetadataReference.CreateFromFile(typeof(ValidateInputAttribute).Assembly.Location) };
        }

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
                Id = "SCS0017",
                Severity = DiagnosticSeverity.Warning
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        [ValidateInput(false)]
        public ActionResult ControllerMethod(string input)
        {
            return null;
        }
    }
}
