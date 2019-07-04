using System.Collections.Generic;
using System.Reflection;
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
                return new DiagnosticAnalyzer[] { new CSharpAnalyzers(new TaintAnalyzerCSharp(new InsecureCookieAnalyzerCSharp())) };
            else
                return new DiagnosticAnalyzer[] { new VBasicAnalyzers(new TaintAnalyzerVisualBasic(new InsecureCookieAnalyzerVisualBasic())) };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(HttpCookie).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Http.CookieOptions).Assembly.Location),
            MetadataReference.CreateFromFile(Assembly.Load("netstandard, Version=2.0.0.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51")
                                                     .Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        private readonly DiagnosticResult[] Expected =
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
        [DataTestMethod]
        [DataRow("",        "var cookie = new HttpCookie(\"test\")",                      true)]
        [DataRow("static ", "Manager.Cookie = new HttpCookie(\"test\")",                  true)]
        [DataRow("",        "var m = new Manager(); m.Cookie = new HttpCookie(\"test\")", true)]
        [DataRow("",        "new Manager().Cookie = new HttpCookie(\"test\")",            false)]
        //[DataRow("",        "new Manager { Cookie = new HttpCookie(\"test\") }",          false)] todo: fix to work as in the previous line
        public async Task CookieAsMember(string modifier, string payload, bool vb)
        {
            var cSharpTest = $@"
using System.Web;

namespace VulnerableApp
{{
    public class Manager
    {{
        public {modifier}HttpCookie Cookie;
    }}

    class CookieCreation
    {{
        static void TestCookie()
        {{
            {payload};
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Web

Namespace VulnerableApp
    Public Class Manager
        Public {modifier.CSharpReplaceToVBasic()}Cookie As HttpCookie
    End Class

    Class CookieCreation
        Private Shared Sub TestCookie()
            {payload.CSharpReplaceToVBasic()}
        End Sub
    End Class
End Namespace

";
            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            if (vb)
                await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("Cookie = System.Web.HttpCookie",  "Cookie")]
        [DataRow("System.Web",                      "HttpCookie")]
        public async Task CookieWithoutFlags(string alias, string name)
        {
            var cSharpTest = $@"
using {alias};

namespace VulnerableApp
{{
    class CookieCreation
    {{
        static void TestCookie()
        {{
            var cookie = new {name}(""test"");
        }}
    }}
}}
";

            var visualBasicTest1 = $@"
Imports {alias}

Namespace VulnerableApp
    Class CookieCreation
        Private Shared Sub TestCookie()
            Dim cookie = New {name}(""test"")
        End Sub
    End Class
End Namespace
";

            var visualBasicTest2 = $@"
Imports {alias}

Namespace VulnerableApp
    Class CookieCreation
        Private Shared Sub TestCookie()
            Dim cookie As New {name}(""test"")
        End Sub
    End Class
End Namespace
";

            var visualBasicTest3 = $@"
Imports {alias}

Namespace VulnerableApp
    Class CookieCreation
        Private Shared Sub TestCookie()
            Dim cookie As {name} = New {name}(""test"")
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest1, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest2, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest3, Expected).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
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
        [DataTestMethod]
        [DataRow("System.Web", @"HttpCookie(""test"")")]
        [DataRow("Microsoft.AspNetCore.Http", @"CookieOptions()")]
        public async Task CookieWithFalseFlags(string @namespace, string constructor)
        {
            var cSharpTest = $@"
using {@namespace};

namespace VulnerableApp
{{
    class CookieCreation
    {{
        static void TestCookie()
        {{
            var cookie = new {constructor};
            cookie.Secure = false;
            cookie.HttpOnly = false;
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {@namespace}

Namespace VulnerableApp
    Class CookieCreation
        Private Shared Sub TestCookie()
            Dim cookie = New {constructor}
            cookie.Secure = False
            cookie.HttpOnly = False
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
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
                Id = "SCS0008",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected08).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected08).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
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

        [TestCategory("Safe")]
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
    }
}
