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

        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
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

            var cSharpTest = @"
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
            var visualBasicTest1 = @"
Imports System.Web

Namespace VulnerableApp
	Class CookieCreation
		Private Shared Sub TestCookie()
			Dim cookie = New HttpCookie(""test"")
        End Sub
    End Class
End Namespace
";

            var visualBasicTest2 = @"
Imports System.Web

Namespace VulnerableApp
	Class CookieCreation
		Private Shared Sub TestCookie()
			Dim cookie As New HttpCookie(""test"")
        End Sub
    End Class
End Namespace
";
            var visualBasicTest3 = @"
Imports System.Web

Namespace VulnerableApp
	Class CookieCreation
		Private Shared Sub TestCookie()
			Dim cookie As HttpCookie = New HttpCookie(""test"")
        End Sub
    End Class
End Namespace
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

            DiagnosticResult[] expected = new DiagnosticResult[] { expected08, expected09 };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest1, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest2, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest3, expected);
        }

        [TestMethod]
        public async Task CookieWithFlags()
        {
            var cSharpTest = @"
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
            var visualBasicTest = @"
Imports System.Web

Namespace VulnerableApp
	Class CookieCreation
		Private Shared Sub TestCookie()
			Dim cookie = New HttpCookie(""test"")
            cookie.Secure = True
            cookie.HttpOnly = True
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }


        [TestMethod]
        public async Task CookieWithFlagsInLine()
        {
            var cSharpTest = @"
using System.Web;

namespace VulnerableApp
{
    class CookieCreation
    {
        static void TestCookie()
        {
            var a = new HttpCookie(""test"")
            {
                Secure = true,
                HttpOnly = true
            };
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Web

Namespace VulnerableApp
    Class CookieCreation
        Private Shared Sub TestCookie()
            Dim cookie As New HttpCookie(""test"") With {.Secure = True, .HttpOnly = True}
        End Sub
    End Class
End Namespace
";
            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
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
