using Microsoft.VisualStudio.TestTools.UnitTesting;

using System.Collections.Generic;
using System.Web;

using TestHelper;
using Microsoft.CodeAnalysis.Diagnostics;
using RoslynSecurityGuard.Analyzers;
using Microsoft.CodeAnalysis;

namespace RoslynSecurityGuard.Test.Tests
{
    [TestClass]
    public class InsecureCookieAnalyzerTest : DiagnosticVerifier
    {

        protected override DiagnosticAnalyzer GetCSharpDiagnosticAnalyzers()
        {
            return new InsecureCookieAnalyzer();
        }

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[] { MetadataReference.CreateFromFile(typeof(HttpCookie).Assembly.Location)};
        }

        [TestMethod]
        public void CookieWithoutFlags()
        {

            var test = @"
using System;
using System.Web;

namespace VulnerableApp
{
    class CookieCreation
    {
        static void TestCookie()
        {
            var cookie = new HttpCookie(""test"");
        }
    }
}
";

            var expected08 = new DiagnosticResult {
                Id = "SG0008",
                Severity = DiagnosticSeverity.Warning
            };
            var expected09 = new DiagnosticResult
            {
                Id = "SG0009",
                Severity = DiagnosticSeverity.Warning
            };
            VerifyCSharpDiagnostic(test, new DiagnosticResult[] { expected08, expected09 });
        }

        [TestMethod]
        public void CookieWithFlags()
        {
            var test = @"
using System;
using System.Web;

namespace VulnerableApp
{
    class CookieCreation
    {
        static void TestCookie()
        {
            var cookie = new HttpCookie(""test"");
            cookie.Secure = true;
            cookie.HttpOnly = true;
        }
    }
}
";
            VerifyCSharpDiagnostic(test);
        }
    }
}
