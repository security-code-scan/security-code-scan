using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers;
using RoslynSecurityGuard.CodeFixes;

using System.Collections.Generic;

using System.Web.Mvc;
using TestHelper;

namespace RoslynSecurityGuard.Test.Tests
{
    //FIXME: The test is working locally but not on AppVeyor..
    //[TestClass]
    public class CsrfTokenCodeFixProviderTest : CodeFixVerifier
    {

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[] { MetadataReference.CreateFromFile(typeof(ValidateAntiForgeryTokenAttribute).Assembly.Location) };
        }

        protected override DiagnosticAnalyzer GetCSharpDiagnosticAnalyzers()
        {
            return new CsrfTokenAnalyzer();
        }

        protected override CodeFixProvider GetCSharpCodeFixProvider()
        {
            return new CsrfTokenCodeFixProvider();
        }

        [TestMethod]
        public void VerifyCsrfTokenAdded()
        {
            var before = @"
using System;
using System.Diagnostics;
using System.Web.Mvc;

public class TestController
{
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
    [HttpPost]
    [ValidateAntiForgeryToken]
    public ActionResult ControllerMethod(string input) {
        return null;
    }
}
";
            VerifyCSharpFix(before, after);
        }
    }
}
