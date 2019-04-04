using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
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
    public class WeakPasswordValidatorPropertyAuditTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            if (language == LanguageNames.CSharp)
                return new DiagnosticAnalyzer[] { new CSharpAnalyzers(new TaintAnalyzerCSharp(new WeakPasswordValidatorPropertyAnalyzerCSharp())) };
            else
                return new DiagnosticAnalyzer[] { new VBasicAnalyzers(new TaintAnalyzerVisualBasic(new WeakPasswordValidatorPropertyAnalyzerVisualBasic())) };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(PasswordValidator).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [DataTestMethod]
        [DataRow("RequiredLength", "System.Int32", "SCS0032", false)]
        [DataRow("RequiredLength", "System.Int32", "SCS0032", true)]
        public async Task PasswordValidatorRequiredLength(string property, string type, string code, bool auditMode)
        {
            var cSharpTest = $@"
using Microsoft.AspNet.Identity;

namespace WebApplicationSandbox.Controllers
{{
    public class TestApp
    {{
        public void TestMethod({type} x)
        {{
            var pwdv = new PasswordValidator
            {{
                {property} = x
            }};
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports Microsoft.AspNet.Identity

Namespace WebApplicationSandbox.Controllers
    Public Class TestApp
        Public Sub TestMethod(x As {type})
            Dim pwdv As New PasswordValidator() With {{ _
                .{property} = x
            }}
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = code,
                Severity = DiagnosticSeverity.Warning
            };

            var testConfig = $@"
AuditMode: {auditMode}
MinimumPasswordValidatorProperties: 1
PasswordValidatorRequiredProperties: [{property}]
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            await VerifyCSharpDiagnostic(cSharpTest,
                                         auditMode ? new[] { expected } : null,
                                         optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest,
                                              auditMode ? new[] { expected } : null,
                                              optionsWithProjectConfig).ConfigureAwait(false);
        }

        [DataTestMethod]
        [DataRow("RequireDigit",            "System.Boolean", "SCS0034", false)]
        [DataRow("RequireDigit",            "System.Boolean", "SCS0034", true)]
        [DataRow("RequireLowercase",        "System.Boolean", "SCS0034", false)]
        [DataRow("RequireLowercase",        "System.Boolean", "SCS0034", true)]
        [DataRow("RequireNonLetterOrDigit", "System.Boolean", "SCS0034", false)]
        [DataRow("RequireNonLetterOrDigit", "System.Boolean", "SCS0034", true)]
        [DataRow("RequireUppercase",        "System.Boolean", "SCS0034", false)]
        [DataRow("RequireUppercase",        "System.Boolean", "SCS0034", true)]
        public async Task PasswordValidatorRequiredProperty(string property, string type, string code, bool auditMode)
        {
            var cSharpTest = $@"
using Microsoft.AspNet.Identity;

namespace WebApplicationSandbox.Controllers
{{
    public class TestApp
    {{
        public void TestMethod({type} x)
        {{
            var pwdv = new PasswordValidator
            {{
                RequiredLength = 1,
                {property} = x
            }};
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports Microsoft.AspNet.Identity

Namespace WebApplicationSandbox.Controllers
    Public Class TestApp
        Public Sub TestMethod(x As {type})
            Dim pwdv As New PasswordValidator() With {{ _
                .{property} = x, .RequiredLength = 1
            }}
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
PasswordValidatorRequiredLength: 1
MinimumPasswordValidatorProperties: 1
PasswordValidatorRequiredProperties: [{property}]
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
