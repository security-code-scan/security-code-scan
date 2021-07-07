using System.Collections.Generic;
using System.Reflection;
using System.Threading.Tasks;
using System.Web;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Test.Config;
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test.Audit
{
    [TestClass]
    public class InsecureCookieAuditTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string _)
        {
            return new DiagnosticAnalyzer[] { new CookieAnalyzer()};
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

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("Response.Cookies.Add(cookie)", "System.Web.Mvc", "System.Web", "HttpCookie", "(\"\")", "Secure",   "HttpOnly", "SCS0008", false)]
        [DataRow("Response.Cookies.Add(cookie)", "System.Web.Mvc", "System.Web", "HttpCookie", "(\"\")", "Secure",   "HttpOnly", "SCS0008", true)]
        [DataRow("Response.Cookies.Add(cookie)", "System.Web.Mvc", "System.Web", "HttpCookie", "(\"\")", "HttpOnly", "Secure",   "SCS0009", false)]
        [DataRow("Response.Cookies.Add(cookie)", "System.Web.Mvc", "System.Web", "HttpCookie", "(\"\")", "HttpOnly", "Secure",   "SCS0009", true)]
        [DataRow(@"Response.Cookies.Append(""aaa"", ""secret"", cookie)", "Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", "CookieOptions", "()", "Secure", "HttpOnly", "SCS0008", false)]
        [DataRow(@"Response.Cookies.Append(""aaa"", ""secret"", cookie)", "Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", "CookieOptions", "()", "Secure", "HttpOnly", "SCS0008", true)]
        [DataRow(@"Response.Cookies.Append(""aaa"", ""secret"", cookie)", "Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", "CookieOptions", "()", "HttpOnly", "Secure", "SCS0009", false)]
        [DataRow(@"Response.Cookies.Append(""aaa"", ""secret"", cookie)", "Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Http", "CookieOptions", "()", "HttpOnly", "Secure", "SCS0009", true)]
        public async Task CookiePropertyDynamicValue(string sink, string namespace1, string namespace2, string type, string constructor, string property, string constProperty, string code, bool auditMode)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using {namespace1};
    using {namespace2};
#pragma warning restore 8019

namespace VulnerableApp
{{
    class CookieCreation : Controller
    {{
        void TestCookie(bool x)
        {{
            var cookie = new {type}{constructor};
            cookie.{property} = x;
            cookie.{constProperty} = true;
            {sink};
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
    Class CookieCreation
        Inherits Controller

        Private Sub TestCookie(x As Boolean)
            Dim cookie = New {type}{constructor}
            cookie.{property} = x
            cookie.{constProperty} = True
            {sink}
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id = code,
                Severity = DiagnosticSeverity.Warning
            };

            var testConfig = $@"
AuditMode: {auditMode}
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            await VerifyCSharpDiagnostic(cSharpTest,
                                         auditMode ? new[] { expected } : null,
                                         optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest,
                                              auditMode ? new[] { expected } : null,
                                              optionsWithProjectConfig).ConfigureAwait(false);
        }
    }
}
