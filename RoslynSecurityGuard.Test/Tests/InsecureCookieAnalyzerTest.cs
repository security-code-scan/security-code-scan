using Microsoft.VisualStudio.TestTools.UnitTesting;

using System.Collections.Generic;
using System.Threading.Tasks;
using System.Web;

using TestHelper;
using Microsoft.CodeAnalysis.Diagnostics;
using RoslynSecurityGuard.Analyzers;
using Microsoft.CodeAnalysis;
using RoslynSecurityGuard.Analyzers.Taint;

namespace RoslynSecurityGuard.Test.Tests
{
    [TestClass]
    public class InsecureCookieAnalyzerTest : DiagnosticVerifier
    {

        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
        {
            return new DiagnosticAnalyzer[] { new TaintAnalyzer(), new InsecureCookieAnalyzer() };
        }

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[] { MetadataReference.CreateFromFile(typeof(HttpCookie).Assembly.Location) };
        }

        [TestMethod]
        public async Task CookieWithoutFlags()
        {

            var test = @"
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

            var expected08 = new DiagnosticResult
            {
                Id = "SG0008",
                Severity = DiagnosticSeverity.Warning
            };
            var expected09 = new DiagnosticResult
            {
                Id = "SG0009",
                Severity = DiagnosticSeverity.Warning
            };
            await VerifyCSharpDiagnostic(test, new DiagnosticResult[] { expected08, expected09 });
        }

        [TestMethod]
        public async Task CookieWithFlags()
        {
            var test = @"
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
            await VerifyCSharpDiagnostic(test);
        }

/*
        static void TestCookie()
        {
            var cookie = new HttpCookie("test");
            cookie.Secure = true;
            cookie.HttpOnly = true;
        }
*/
    }
}
