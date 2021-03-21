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
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Http.CookieOptions).Assembly.Location),
            MetadataReference.CreateFromFile(Assembly.Load("netstandard, Version=2.0.0.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51").Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("System.Web", "HttpCookie", "(\"\")", "Secure",   "HttpOnly", "SCS0008", false)]
        [DataRow("System.Web", "HttpCookie", "(\"\")", "Secure",   "HttpOnly", "SCS0008", true)]
        [DataRow("System.Web", "HttpCookie", "(\"\")", "HttpOnly", "Secure",   "SCS0009", false)]
        [DataRow("System.Web", "HttpCookie", "(\"\")", "HttpOnly", "Secure",   "SCS0009", true)]
        [DataRow("Microsoft.AspNetCore.Http", "CookieOptions", "()", "Secure", "HttpOnly", "SCS0008", false)]
        [DataRow("Microsoft.AspNetCore.Http", "CookieOptions", "()", "Secure", "HttpOnly", "SCS0008", true)]
        [DataRow("Microsoft.AspNetCore.Http", "CookieOptions", "()", "HttpOnly", "Secure", "SCS0009", false)]
        [DataRow("Microsoft.AspNetCore.Http", "CookieOptions", "()", "HttpOnly", "Secure", "SCS0009", true)]
        public async Task CookiePropertyDynamicValue(string @namespace, string type, string constructor, string property, string constProperty, string code, bool auditMode)
        {
            var cSharpTest = $@"
using {@namespace};

namespace VulnerableApp
{{
    class CookieCreation
    {{
        static {type} TestCookie(bool x)
        {{
            var cookie = new {type}{constructor};
            cookie.{property} = x;
            cookie.{constProperty} = true;
            return cookie;
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {@namespace}

Namespace VulnerableApp
    Class CookieCreation
        Private Shared Function TestCookie(x As Boolean) As {type}
            Dim cookie = New {type}{constructor}
            cookie.{property} = x
            cookie.{constProperty} = True
            Return cookie
        End Function
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
