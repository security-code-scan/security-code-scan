using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Audit;
using SecurityCodeScan.Test.Helpers;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test.Password
{
    [TestClass]
    public class HardcodedPasswordFieldTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            if (language == LanguageNames.CSharp)
                return new DiagnosticAnalyzer[] { new CSharpAnalyzers(new UnknownPasswordApiAnalyzerCSharp()) };
            else
                return new DiagnosticAnalyzer[] { new VBasicAnalyzers(new UnknownPasswordApiAnalyzerVisualBasic()) };
        }

        [TestCategory("Safe")]
        [DataRow("null")]
        [DataRow("String.Empty")]
        [DataRow("\"\"")]
        [DataTestMethod]
        public async Task HardCodePasswordFalsePositive(string value)
        {
            var vbValue = value.CSharpReplaceToVBasic();

            var cSharpTest = $@"
using System;

namespace VulnerableApp
{{
    class HardCodedPassword
    {{
        static void TestCookie()
        {{
            var uri = new UriBuilder();
            uri.Password = {value};
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System

Namespace VulnerableApp
    Class HardCodedPassword
        Private Shared Sub TestCookie()
            Dim uri = New UriBuilder()
            uri.Password = {vbValue}
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);

            cSharpTest = $@"
using System;

namespace VulnerableApp
{{
    class HardCodedPassword
    {{
        static void TestCookie()
        {{
            var uri = new UriBuilder {{Password = {value}}};
        }}
    }}
}}
";

            visualBasicTest = $@"
Imports System

Namespace VulnerableApp
    Class HardCodedPassword
        Private Shared Sub TestCookie()
            Dim uri = New UriBuilder With {{.Password = {vbValue}}}
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task HardCodePasswordAssignment()
        {
            var cSharpTest = @"
using System;

namespace VulnerableApp
{
    class HardCodedPassword
    {
        static void TestCookie()
        {
            var uri = new UriBuilder();
            uri.Password = ""t0ps3cr3t"";
        }
    }
}
";

            var visualBasicTest = @"
Imports System

Namespace VulnerableApp
    Class HardCodedPassword
        Private Shared Sub TestCookie()
            Dim uri = New UriBuilder()
            uri.Password = ""t0ps3cr3t""
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0015",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected, await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false)).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task HardCodePasswordInitializer()
        {
            var cSharpTest = @"
using System;

namespace VulnerableApp
{
    class HardCodedPassword
    {
        static void TestCookie()
        {
            var uri = new UriBuilder {Password = ""t0ps3cr3t""};
        }
    }
}
";

            var visualBasicTest = @"
Imports System

Namespace VulnerableApp
    Class HardCodedPassword
        Private Shared Sub TestCookie()
            Dim uri = New UriBuilder With {.Password = ""t0ps3cr3t""}
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0015",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected, await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false)).ConfigureAwait(false);
        }
    }
}
