using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using System.Web;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Test.Helpers;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test.InsecureCookie
{
    [TestClass]
    public class InsecureCookieAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string _)
        {
            return new DiagnosticAnalyzer[] { new CookieAnalyzer() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(HttpCookie).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Web.Mvc.Controller).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Http.CookieOptions).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Http.HttpResponse).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.ControllerBase).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.Controller).Assembly.Location),
            MetadataReference.CreateFromFile(Assembly.Load("netstandard, Version=2.0.0.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51")
                                                     .Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        private static readonly DiagnosticResult ExpectedSCS0008 = new DiagnosticResult
        {
            Id = "SCS0008",
            Severity = DiagnosticSeverity.Warning
        };

        private static readonly DiagnosticResult ExpectedSCS0009 = new DiagnosticResult
        {
            Id = "SCS0009",
            Severity = DiagnosticSeverity.Warning
        };

        private static readonly DiagnosticResult[] Expected =
        {
            ExpectedSCS0008,
            ExpectedSCS0009
        };

        [DataTestMethod]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", @"Response.Cookies.Append(""aaa"", ""secret"", cookie)", "var cookie = new CookieOptions(); cookie.Secure = true; cookie.HttpOnly = true;")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", @"Response.Cookies.Append(""aaa"", ""secret"", cookie)", "var cookie = new CookieOptions(); cookie.Secure = true; cookie.HttpOnly = true; cookie.HttpOnly = false;", "SCS0009")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", @"Response.Cookies.Append(""aaa"", ""secret"", cookie)", "var cookie = new CookieOptions(); cookie.Secure = true; cookie.HttpOnly = true; cookie.HttpOnly = false; cookie.HttpOnly = true;")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", @"Response.Cookies.Append(""aaa"", ""secret"", cookie)", "var cookie = new CookieOptions(); cookie.Secure = true; cookie.HttpOnly = false;", "SCS0009")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", @"Response.Cookies.Append(""aaa"", ""secret"", cookie)", "var cookie = new CookieOptions(); cookie.Secure = false; cookie.HttpOnly = true;", "SCS0008")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", @"Response.Cookies.Append(""aaa"", ""secret"")", "var cookie = new CookieOptions();", "SCS0008", "SCS0009")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", @"Response.Cookies.Append(""aaa"", ""secret"")", "", "SCS0008", "SCS0009")]

        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "var cookie = new HttpCookie(\"\"); cookie.Secure = true; cookie.HttpOnly = true;")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "var cookie = new HttpCookie(\"\"); cookie.Secure = true; cookie.HttpOnly = true; cookie.HttpOnly = false;", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "var cookie = new HttpCookie(\"\"); cookie.Secure = true; cookie.HttpOnly = true; cookie.HttpOnly = false; cookie.HttpOnly = true;")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "var cookie = new HttpCookie(\"\"); cookie.Secure = true; cookie.HttpOnly = false;", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "var cookie = new HttpCookie(\"\"); cookie.Secure = true;", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "var cookie = new HttpCookie(\"\") { Secure = true };", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "var cookie = new HttpCookie(\"\"); cookie.Secure = false; cookie.HttpOnly = true;", "SCS0008")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "var cookie = new HttpCookie(\"\"); cookie.HttpOnly = true;", "SCS0008")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "var cookie = new HttpCookie(\"\") { HttpOnly = true };", "SCS0008")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "var cookie = new HttpCookie(\"\"); cookie.Secure = false; cookie.HttpOnly = false;", "SCS0008", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "var cookie = new HttpCookie(\"\");", "SCS0008", "SCS0009")]
        public async Task CookieSetAppend(string namespace1, string namespace2, string payload, string cookie, params string[] warnings)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using {namespace1};
    using {namespace2};
#pragma warning restore 8019

namespace VulnerableApp
{{
    public class TestController : Controller
    {{
        public void ControllerMethod()
        {{
            {cookie}
            {payload};
        }}
    }}
}}
";

            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports {namespace1}
    Imports {namespace2}
#Enable Warning BC50001

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller

        Public Sub ControllerMethod()
            {cookie.CSharpReplaceToVBasic()}
            {payload}
        End Sub
    End Class
End Namespace
";
            if (warnings.Any())
            {
                var expected = warnings.Select(x => new DiagnosticResult { Id = x, Severity = DiagnosticSeverity.Warning }).ToArray();
                await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
            }
        }

        [DataTestMethod]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", "CookieOptions", "return cookie", "var cookie = new CookieOptions(); cookie.Secure = true; cookie.HttpOnly = true;")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", "CookieOptions", "return cookie", "var cookie = new CookieOptions(); cookie.Secure = true; cookie.HttpOnly = false;", "SCS0009")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", "CookieOptions", "return cookie", "var cookie = new CookieOptions(); cookie.Secure = false; cookie.HttpOnly = true;", "SCS0008")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", "CookieOptions", "return cookie", "var cookie = new CookieOptions();", "SCS0008", "SCS0009")]

        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", "CookieOptions", "Test(cookie); return null", "var cookie = new CookieOptions(); cookie.Secure = true; cookie.HttpOnly = true;")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", "CookieOptions", "Test(cookie); return null", "var cookie = new CookieOptions(); cookie.Secure = true; cookie.HttpOnly = false;", "SCS0009")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", "CookieOptions", "Test(cookie); return null", "var cookie = new CookieOptions(); cookie.Secure = false; cookie.HttpOnly = true;", "SCS0008")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", "CookieOptions", "Test(cookie); return null", "var cookie = new CookieOptions();", "SCS0008", "SCS0009")]

        [DataRow("System.Web.Mvc", "System.Web", "HttpCookie", "return cookie", "var cookie = new HttpCookie(\"\"); cookie.Secure = true; cookie.HttpOnly = true;")]
        [DataRow("System.Web.Mvc", "System.Web", "HttpCookie", "return cookie", "var cookie = new HttpCookie(\"\"); cookie.Secure = true; cookie.HttpOnly = false;", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", "HttpCookie", "return cookie", "var cookie = new HttpCookie(\"\"); cookie.Secure = true;", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", "HttpCookie", "return cookie", "var cookie = new HttpCookie(\"\") { Secure = true };", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", "HttpCookie", "return cookie", "var cookie = new HttpCookie(\"\"); cookie.Secure = false; cookie.HttpOnly = true;", "SCS0008")]
        [DataRow("System.Web.Mvc", "System.Web", "HttpCookie", "return cookie", "var cookie = new HttpCookie(\"\"); cookie.HttpOnly = true;", "SCS0008")]
        [DataRow("System.Web.Mvc", "System.Web", "HttpCookie", "return cookie", "var cookie = new HttpCookie(\"\") { HttpOnly = true };", "SCS0008")]
        [DataRow("System.Web.Mvc", "System.Web", "HttpCookie", "return cookie", "var cookie = new HttpCookie(\"\"); cookie.Secure = false; cookie.HttpOnly = false;", "SCS0008", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", "HttpCookie", "return cookie", "var cookie = new HttpCookie(\"\");", "SCS0008", "SCS0009")]
        public async Task CookieReturn(string namespace1, string namespace2, string type, string payload, string cookie, params string[] warnings)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using {namespace1};
    using {namespace2};
#pragma warning restore 8019

namespace VulnerableApp
{{
    public class TestController : Controller
    {{
        public void Test({type} cookie)
        {{
        }}

        public {type} ControllerMethod()
        {{
            {cookie}
            {payload};
        }}
    }}
}}
";

            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports {namespace1}
    Imports {namespace2}
#Enable Warning BC50001

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller

        Public Sub Test(cookie As {type})
        End Sub

        Public Function ControllerMethod() As {type}
            {cookie.CSharpReplaceToVBasic()}
            {payload.CSharpReplaceToVBasic()}
        End Function
    End Class
End Namespace
";
            if (warnings.Any())
            {
                var expected = warnings.Select(x => new DiagnosticResult { Id = x, Severity = DiagnosticSeverity.Warning }).ToArray();
                await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
            }
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("System.Web", "HttpCookie", "static ", "Manager.Cookie = new HttpCookie(\"test\")",                  true)]
        [DataRow("System.Web", "HttpCookie", "",        "var m = new Manager(); m.Cookie = new HttpCookie(\"test\")", true)]
        [DataRow("System.Web", "HttpCookie", "",        "new Manager().Cookie = new HttpCookie(\"test\")",            false)]
        [DataRow("System.Web", "HttpCookie", "",        "new Manager { Cookie = new HttpCookie(\"test\") }",          false)]
        [DataRow("Microsoft.AspNetCore.Http", "CookieOptions", "static ", "Manager.Cookie = new CookieOptions()",                  true)]
        [DataRow("Microsoft.AspNetCore.Http", "CookieOptions", "",        "var m = new Manager(); m.Cookie = new CookieOptions()", true)]
        [DataRow("Microsoft.AspNetCore.Http", "CookieOptions", "",        "new Manager().Cookie = new CookieOptions()",            false)]
        [DataRow("Microsoft.AspNetCore.Http", "CookieOptions", "",        "new Manager { Cookie = new CookieOptions() }",          false)]
        public async Task CookieAsMember(string @namespace, string type, string modifier, string payload, bool vb)
        {
            var cSharpTest = $@"
using {@namespace};

namespace VulnerableApp
{{
    public class Manager
    {{
        public {modifier}{type} Cookie;
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
Imports {@namespace}

Namespace VulnerableApp
    Public Class Manager
        Public {modifier.CSharpReplaceToVBasic()}Cookie As {type}
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

        [TestCategory("Safe")]
        [DataTestMethod]
        [DataRow("System.Web",           @"System.Web.HttpCookie(""test"")",           "Response.Cookies.Set(cookie)")]
        [DataRow("Microsoft.AspNetCore", @"Microsoft.AspNetCore.Http.CookieOptions()", "Response.Cookies.Append(\"\", \"\", cookie)")]
        public async Task CookieWithUnknownFlags(string @namespace, string constructor, string payload)
        {
            var cSharpTest = $@"
using {@namespace}.Mvc;

namespace VulnerableApp
{{
    class CookieCreation : Controller
    {{
        public void TestCookie(bool isTrue)
        {{
            var cookie = new {constructor}
            {{
                Secure = isTrue,
                HttpOnly = isTrue
            }};
            {payload};
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {@namespace}.Mvc

Namespace VulnerableApp
    Class CookieCreation
        Inherits Controller
        Public Sub TestCookie(isTrue As Boolean)
            Dim cookie As New {constructor} With {{.Secure = isTrue, .HttpOnly = isTrue}}
            {payload}
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
        static HttpCookie TestCookie()
        {
            var a = new HttpCookie();
            return a;
        }
    }
}
";

            var visualBasicTest = @"
Namespace VulnerableApp
    Class HttpCookie
    End Class

    Class CookieCreation
        Private Shared Function TestCookie() As HttpCookie
            Dim a = New HttpCookie()
            Return a
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }
    }
}
