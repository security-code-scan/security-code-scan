using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers;
using RoslynSecurityGuard.CodeFixes;

using System.Collections.Generic;
using System.Threading.Tasks;
using System.Web.Mvc;
using TestHelper;

namespace RoslynSecurityGuard.Test.Tests
{
    [TestClass]
    public class CsrfTokenCodeFixProviderTest : CodeFixVerifier
    {

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[] { MetadataReference.CreateFromFile(typeof(ValidateAntiForgeryTokenAttribute).Assembly.Location) };
        }

        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
        {
            return new[] { new CsrfTokenAnalyzer() };
        }

        protected override CodeFixProvider GetCSharpCodeFixProvider()
        {
            return new CsrfTokenCodeFixProvider();
        }

        [TestMethod]
        public async Task CsrfVerifyTokenAdded()
        {
            var before = @"
using System;
using System.Diagnostics;
using System.Web.Mvc;

public class TestController
{

    //Test comment
    [HttpPost]
    public ActionResult ControllerMethod(string input) {
        return null;
    }
}
";
            var after = @"
using System;
using System.Diagnostics;
using System.Web.Mvc;

public class TestController
{

    //Test comment
    [HttpPost]
    [ValidateAntiForgeryToken]
    public ActionResult ControllerMethod(string input) {
        return null;
    }
}
";
            await VerifyCSharpFix(before, after);
        }
    }
}
