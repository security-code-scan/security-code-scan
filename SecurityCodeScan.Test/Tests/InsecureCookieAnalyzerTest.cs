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
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", @"Response.Cookies.Append(""aaa"", ""secret"", cookie)", "var cookie = new CookieOptions(); cookie.Secure = true; cookie.HttpOnly = true;", "CookieOptions")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", @"Response.Cookies.Append(""aaa"", ""secret"", cookie)", "var cookie = new CookieOptions(); cookie.Secure = true; cookie.HttpOnly = true; cookie.HttpOnly = false;", "CookieOptions", "SCS0009")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", @"Response.Cookies.Append(""aaa"", ""secret"", cookie)", "var cookie = new CookieOptions(); cookie.Secure = true; cookie.HttpOnly = true; cookie.HttpOnly = false; cookie.HttpOnly = true;", "CookieOptions")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", @"Response.Cookies.Append(""aaa"", ""secret"", cookie)", "var cookie = new CookieOptions(); cookie.Secure = true; cookie.HttpOnly = false;", "CookieOptions", "SCS0009")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", @"Response.Cookies.Append(""aaa"", ""secret"", cookie)", "var cookie = new CookieOptions(); cookie.Secure = false; cookie.HttpOnly = true;", "CookieOptions", "SCS0008")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", @"Response.Cookies.Append(""aaa"", ""secret"")", "var cookie = new CookieOptions();", "CookieOptions", "SCS0008", "SCS0009")]

        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "var cookie = new HttpCookie(\"\"); cookie.Secure = true; cookie.HttpOnly = true;", "HttpCookie")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "var cookie = new HttpCookie(\"\"); cookie.Secure = true; cookie.HttpOnly = true; cookie.HttpOnly = false;", "HttpCookie", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "var cookie = new HttpCookie(\"\"); cookie.Secure = true; cookie.HttpOnly = true; cookie.HttpOnly = false; cookie.HttpOnly = true;", "HttpCookie")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "var cookie = new HttpCookie(\"\"); cookie.Secure = true; cookie.HttpOnly = false;", "HttpCookie", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "var cookie = new HttpCookie(\"\"); cookie.Secure = true;", "HttpCookie", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "var cookie = new HttpCookie(\"\") { Secure = true };", "HttpCookie", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "var cookie = new HttpCookie(\"\"); cookie.Secure = false; cookie.HttpOnly = true;", "HttpCookie", "SCS0008")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "var cookie = new HttpCookie(\"\"); cookie.HttpOnly = true;", "HttpCookie", "SCS0008")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "var cookie = new HttpCookie(\"\") { HttpOnly = true };", "HttpCookie", "SCS0008")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "var cookie = new HttpCookie(\"\"); cookie.Secure = false; cookie.HttpOnly = false;", "HttpCookie", "SCS0008", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "var cookie = new HttpCookie(\"\");", "HttpCookie", "SCS0008", "SCS0009")]

        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Add(cookie)", "var cookie = new HttpCookie(\"\"); cookie.Secure = true; cookie.HttpOnly = true;", "HttpCookie")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Add(cookie)", "var cookie = new HttpCookie(\"\"); cookie.Secure = true; cookie.HttpOnly = true; cookie.HttpOnly = false;", "HttpCookie", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Add(cookie)", "var cookie = new HttpCookie(\"\"); cookie.Secure = true; cookie.HttpOnly = true; cookie.HttpOnly = false; cookie.HttpOnly = true;", "HttpCookie")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Add(cookie)", "var cookie = new HttpCookie(\"\"); cookie.Secure = true; cookie.HttpOnly = false;", "HttpCookie", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Add(cookie)", "var cookie = new HttpCookie(\"\"); cookie.Secure = true;", "HttpCookie", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Add(cookie)", "var cookie = new HttpCookie(\"\") { Secure = true };", "HttpCookie", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Add(cookie)", "var cookie = new HttpCookie(\"\"); cookie.Secure = false; cookie.HttpOnly = true;", "HttpCookie", "SCS0008")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Add(cookie)", "var cookie = new HttpCookie(\"\"); cookie.HttpOnly = true;", "HttpCookie", "SCS0008")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Add(cookie)", "var cookie = new HttpCookie(\"\") { HttpOnly = true };", "HttpCookie", "SCS0008")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Add(cookie)", "var cookie = new HttpCookie(\"\"); cookie.Secure = false; cookie.HttpOnly = false;", "HttpCookie", "SCS0008", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Add(cookie)", "var cookie = new HttpCookie(\"\");", "HttpCookie", "SCS0008", "SCS0009")]
        public async Task CookieInterprocedural(string namespace1, string namespace2, string payload, string cookie, string type, params string[] warnings)
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
        public void Use({type} cookie)
        {{
            {payload};
        }}

        public void ControllerMethod()
        {{
            {cookie}
            Use(cookie);
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

        Public Sub Use(cookie As {type})
            {payload}
        End Sub

        Public Sub ControllerMethod()
            {cookie.CSharpReplaceToVBasic()}
            Use(cookie)
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
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", @"Response.Cookies.Append(""aaa"", ""secret"", cookie)", "var cookie = new CookieOptions(); cookie.Secure = true; cookie.HttpOnly = true;")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", @"Response.Cookies.Append(""aaa"", ""secret"", cookie)", "var cookie = new CookieOptions(); cookie.Secure = true; cookie.HttpOnly = true; cookie.HttpOnly = false;", "SCS0009")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", @"Response.Cookies.Append(""aaa"", ""secret"", cookie)", "var cookie = new CookieOptions(); cookie.Secure = true; cookie.HttpOnly = true; cookie.HttpOnly = false; cookie.HttpOnly = true;")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", @"Response.Cookies.Append(""aaa"", ""secret"", cookie)", "var cookie = new CookieOptions(); cookie.Secure = true; cookie.HttpOnly = false;", "SCS0009")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", @"Response.Cookies.Append(""aaa"", ""secret"", cookie)", "var cookie = new CookieOptions(); cookie.Secure = false; cookie.HttpOnly = true;", "SCS0008")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", @"Response.Cookies.Append(""aaa"", ""secret"")", "var cookie = new CookieOptions();", "SCS0008", "SCS0009")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", @"Response.Cookies.Append(""aaa"", ""secret"")", "", "SCS0008", "SCS0009")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", @"Response.Cookies.Delete(""aaa"", cookie)", "var cookie = new CookieOptions(); cookie.Secure = false; cookie.HttpOnly = false;")]

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
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Remove("""")", "var cookie = new HttpCookie(\"\"); cookie.Secure = false; cookie.HttpOnly = false; cookie.HttpOnly = false;")]
        public async Task CookieIntraProcedural(string namespace1, string namespace2, string payload, string cookie, params string[] warnings)
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
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", @"Response.Cookies.Append(""aaa"", ""secret"", cookie)", "cookie = new CookieOptions(); cookie.Secure = true; cookie.HttpOnly = true;", "CookieOptions")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", @"Response.Cookies.Append(""aaa"", ""secret"", cookie)", "cookie = new CookieOptions(); cookie.Secure = true; cookie.HttpOnly = true; cookie.HttpOnly = false;", "CookieOptions", "SCS0009")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", @"Response.Cookies.Append(""aaa"", ""secret"", cookie)", "cookie = new CookieOptions(); cookie.Secure = true; cookie.HttpOnly = true; cookie.HttpOnly = false; cookie.HttpOnly = true;", "CookieOptions")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", @"Response.Cookies.Append(""aaa"", ""secret"", cookie)", "cookie = new CookieOptions(); cookie.Secure = true; cookie.HttpOnly = false;", "CookieOptions", "SCS0009")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", @"Response.Cookies.Append(""aaa"", ""secret"", cookie)", "cookie = new CookieOptions(); cookie.Secure = false; cookie.HttpOnly = true;", "CookieOptions", "SCS0008")]
        [DataRow("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", @"Response.Cookies.Append(""aaa"", ""secret"")", "cookie = new CookieOptions();", "CookieOptions", "SCS0008", "SCS0009")]

        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "cookie = new HttpCookie(\"\"); cookie.Secure = true; cookie.HttpOnly = true;", "HttpCookie")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "cookie = new HttpCookie(\"\"); cookie.Secure = true; cookie.HttpOnly = true; cookie.HttpOnly = false;", "HttpCookie", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "cookie = new HttpCookie(\"\"); cookie.Secure = true; cookie.HttpOnly = true; cookie.HttpOnly = false; cookie.HttpOnly = true;", "HttpCookie")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "cookie = new HttpCookie(\"\"); cookie.Secure = true; cookie.HttpOnly = false;", "HttpCookie", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "cookie = new HttpCookie(\"\"); cookie.Secure = true;", "HttpCookie", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "cookie = new HttpCookie(\"\") { Secure = true };", "HttpCookie", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "cookie = new HttpCookie(\"\"); cookie.Secure = false; cookie.HttpOnly = true;", "HttpCookie", "SCS0008")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "cookie = new HttpCookie(\"\"); cookie.HttpOnly = true;", "HttpCookie", "SCS0008")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "cookie = new HttpCookie(\"\") { HttpOnly = true };", "HttpCookie", "SCS0008")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "cookie = new HttpCookie(\"\"); cookie.Secure = false; cookie.HttpOnly = false;", "HttpCookie", "SCS0008", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Set(cookie)", "cookie = new HttpCookie(\"\");", "HttpCookie", "SCS0008", "SCS0009")]

        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Add(cookie)", "cookie = new HttpCookie(\"\"); cookie.Secure = true; cookie.HttpOnly = true;", "HttpCookie")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Add(cookie)", "cookie = new HttpCookie(\"\"); cookie.Secure = true; cookie.HttpOnly = true; cookie.HttpOnly = false;", "HttpCookie", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Add(cookie)", "cookie = new HttpCookie(\"\"); cookie.Secure = true; cookie.HttpOnly = true; cookie.HttpOnly = false; cookie.HttpOnly = true;", "HttpCookie")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Add(cookie)", "cookie = new HttpCookie(\"\"); cookie.Secure = true; cookie.HttpOnly = false;", "HttpCookie", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Add(cookie)", "cookie = new HttpCookie(\"\"); cookie.Secure = true;", "HttpCookie", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Add(cookie)", "cookie = new HttpCookie(\"\") { Secure = true };", "HttpCookie", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Add(cookie)", "cookie = new HttpCookie(\"\"); cookie.Secure = false; cookie.HttpOnly = true;", "HttpCookie", "SCS0008")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Add(cookie)", "cookie = new HttpCookie(\"\"); cookie.HttpOnly = true;", "HttpCookie", "SCS0008")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Add(cookie)", "cookie = new HttpCookie(\"\") { HttpOnly = true };", "HttpCookie", "SCS0008")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Add(cookie)", "cookie = new HttpCookie(\"\"); cookie.Secure = false; cookie.HttpOnly = false;", "HttpCookie", "SCS0008", "SCS0009")]
        [DataRow("System.Web.Mvc", "System.Web", @"Response.Cookies.Add(cookie)", "cookie = new HttpCookie(\"\");", "HttpCookie", "SCS0008", "SCS0009")]
        public async Task CookieAsMember(string namespace1, string namespace2, string payload, string cookie, string type, params string[] warnings)
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
        private {type} cookie;

        public void Use()
        {{
            {payload};
        }}

        public void ControllerMethod()
        {{
            {cookie}
            Use();
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

        Private cookie As {type}

        Public Sub Use()
            {payload}
        End Sub

        Public Sub ControllerMethod()
            {cookie.CSharpReplaceToVBasic()}
            Use()
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
