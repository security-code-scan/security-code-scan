using System.Collections.Generic;
using System.Threading.Tasks;
using System.Web;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Config;
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test.Audit
{
    [TestClass]
    public class InsecureCookieAuditTest : DiagnosticVerifier
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
            MetadataReference.CreateFromFile(typeof(HttpCookie).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("Secure",   "HttpOnly", "SCS0008", false)]
        [DataRow("Secure",   "HttpOnly", "SCS0008", true)]
        [DataRow("HttpOnly", "Secure",   "SCS0009", false)]
        [DataRow("HttpOnly", "Secure",   "SCS0009", true)]
        public async Task CookiePropertyDynamicValue(string property, string constProperty, string code, bool auditMode)
        {
            var cSharpTest = $@"
using System.Web;

namespace VulnerableApp
{{
    class CookieCreation
    {{
        static void TestCookie(bool x)
        {{
            var cookie = new HttpCookie(""test"");
            cookie.{property} = x;
            cookie.{constProperty} = true;
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Web

Namespace VulnerableApp
    Class CookieCreation
        Private Shared Sub TestCookie(x As Boolean)
            Dim cookie = New HttpCookie(""test"")
            cookie.{property} = x
            cookie.{constProperty} = True
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
