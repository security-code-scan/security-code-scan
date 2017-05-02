using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Web.Mvc;
using TestHelper;

namespace RoslynSecurityGuard.Test.Tests
{
    [TestClass]
    public class CsrfTokenAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
        {
            return new [] { new CsrfTokenAnalyzer() };
        }
        
        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[] { MetadataReference.CreateFromFile(typeof(ValidateAntiForgeryTokenAttribute).Assembly.Location) };
        }
        
        [TestMethod]
        public async Task CsrfDetectMissingToken()
        {
            var test = @"
                using System.Web.Mvc;

                namespace VulnerableApp
                {
                    public class TestController
                    {
                        [HttpPost]
                        //[ValidateAntiForgeryToken]
                        public ActionResult ControllerMethod(string input) {

                            return null;
                        }
                    }
                }
                ";
            var expected = new DiagnosticResult
            {
                Id = "SG0016",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(test, expected);
        }


        [TestMethod]
        public async Task CsrfValidateAntiForgeryTokenPresent()
        {
            var test = @"
                using System.Web.Mvc;

                namespace VulnerableApp
                {
                    public class TestController
                    {
                        [HttpPost]
                        [ValidateAntiForgeryToken]
                        public ActionResult ControllerMethod(string input) {

                            return null;
                        }
                    }
                }
                ";

            await VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public async Task CsrfValidateAntiForgeryTokenPresentWithInlinedAttributes()
        {
            var test = @"
                using System.Web.Mvc;

                namespace VulnerableApp
                {
                    public class TestController
                    {
                        [HttpPost, ValidateAntiForgeryToken]
                        public ActionResult ControllerMethod(string input) {
                            return null;
                        }
                    }
                }
                ";

            await VerifyCSharpDiagnostic(test);
        }
    }
}
