using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers;
using System.Collections.Generic;
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
        public void CsrfDetectMissingToken()
        {
            var test = @"
using System;
using System.Diagnostics;
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

            VerifyCSharpDiagnostic(test, expected);
        }


        [TestMethod]
        public void CsrfValidateAntiForgeryTokenPresent()
        {
            var test = @"
using System;
using System.Diagnostics;
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

            VerifyCSharpDiagnostic(test);
        }

        
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult ControllerMethod(string input) {

            return null;
        }
        
    }
}
