using System.Collections.Generic;
using System.Threading.Tasks;
using System.Web;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Helpers;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test.InsecureCookie
{
    [TestClass]
    public class InsecureCookieAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            if (language == LanguageNames.CSharp)
                return new DiagnosticAnalyzer[] { new InsecureCookieAnalyzerCSharp(), new TaintAnalyzerCSharp() };
            else
                return new DiagnosticAnalyzer[] { new InsecureCookieAnalyzerVisualBasic(), new TaintAnalyzerVisualBasic() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(HttpCookie).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        private DiagnosticResult[] Expected =
        {
            new DiagnosticResult
            {
                Id = "SCS0008",
                Severity = DiagnosticSeverity.Warning
            },
            new DiagnosticResult
            {
                Id = "SCS0009",
                Severity = DiagnosticSeverity.Warning
            }
        };

        [TestCategory("Detect")]
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

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest1, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest2, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest3, Expected).ConfigureAwait(false);
        }

        [TestCategory("Ignore")]
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

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task CookieWithFalseFlags()
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
            cookie.Secure = false;
            cookie.HttpOnly = false;
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
            cookie.Secure = False
            cookie.HttpOnly = False
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Ignore")]
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

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task CookieWithFalseFlagsInLine()
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
                Secure = false,
                HttpOnly = false
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
            Dim cookie As New HttpCookie(""test"") With {.Secure = False, .HttpOnly = False}
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task CookieWithOverridenFlags()
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

            a.Secure = false;
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
            cookie.Secure = False
        End Sub
    End Class
End Namespace
";
            var expected08 = new DiagnosticResult
            {
                Id       = "SCS0008",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected08).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected08).ConfigureAwait(false);
        }

        [TestCategory("Ignore")]
        [TestMethod]
        public async Task CookieWithUnknownFlags()
        {
            var cSharpTest = @"
using System.Web;

namespace VulnerableApp
{
    class CookieCreation
    {
        static void TestCookie(bool isTrue)
        {
            var a = new HttpCookie(""test"")
            {
                Secure = isTrue,
                HttpOnly = isTrue
            };
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Web

Namespace VulnerableApp
    Class CookieCreation
        Private Shared Sub TestCookie(isTrue As Boolean)
            Dim cookie As New HttpCookie(""test"") With {.Secure = isTrue, .HttpOnly = isTrue}
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Ignore")]
        [TestMethod]
        public async Task IgnoreCookieFromOtherNamespace()
        {
            var cSharpTest = @"
namespace VulnerableApp
{
    class HttpCookie
    {
    }

    class CookieCreation
    {
        static void TestCookie()
        {
            var a = new HttpCookie();
        }
    }
}
";

            var visualBasicTest = @"
Namespace VulnerableApp
    Class HttpCookie
    End Class

    Class CookieCreation
        Private Shared Sub TestCookie()
            Dim a = New HttpCookie()
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task GivenAliasDirective_DetectDiagnostic()
        {
            var cSharpTest = @"
using Cookie = System.Web.HttpCookie;

namespace VulnerableApp
{
    class CookieCreation
    {
        static void TestCookie()
        {
            var cookie = new Cookie(""test"");
        }
    }
}
";
            var visualBasicTest = @"
Imports Cookie = System.Web.HttpCookie

Namespace VulnerableApp
    Class CookieCreation
        Private Shared Sub TestCookie()
            Dim cookie = New Cookie(""test"")
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }
    }
}
