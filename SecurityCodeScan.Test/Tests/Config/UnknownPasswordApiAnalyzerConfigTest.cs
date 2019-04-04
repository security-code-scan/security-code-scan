using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test.Config
{
    [TestClass]
    public class UnknownPasswordApiAnalyzerConfigTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            if (language == LanguageNames.CSharp)
                return new DiagnosticAnalyzer[] { new CSharpAnalyzers(new UnknownPasswordApiAnalyzerCSharp()) };
            else
                return new DiagnosticAnalyzer[] { new VBasicAnalyzers(new UnknownPasswordApiAnalyzerVisualBasic()) };
        }

        [DataTestMethod]
        [DataRow("",                 "SecretWord = \"t0ps3cr3t\"", "retwo", true)]
        [DataRow("",                 "SecretWord = \"t0ps3cr3t\"", "rEtwo", true)]
        [DataRow(" = \"t0ps3cr3t\"", "",                           "retwo", true)]
        [DataRow(" = \"t0ps3cr3t\"", "",                           "rEtwo", true)]

        [DataRow("",                 "SecretWord = \"t0ps3cr3t\"", "Word",   true)]
        [DataRow("",                 "SecretWord = \"t0ps3cr3t\"", "wOrD",   true)]
        [DataRow(" = \"t0ps3cr3t\"", "",                           "Word",   true)]
        [DataRow(" = \"t0ps3cr3t\"", "",                           "wOrD",   true)]

        [DataRow("",                 "SecretWord = \"t0ps3cr3t\"", "Secret", true)]
        [DataRow("",                 "SecretWord = \"t0ps3cr3t\"", "sEcret", true)]
        [DataRow(" = \"t0ps3cr3t\"", "",                           "Secret", true)]
        [DataRow(" = \"t0ps3cr3t\"", "",                           "sEcret", true)]

        [DataRow("",                 "SecretWord = \"t0ps3cr3t\"", "SecretWord", true)]
        [DataRow("",                 "SecretWord = \"t0ps3cr3t\"", "sEcretworD", true)]
        [DataRow(" = \"t0ps3cr3t\"", "",                           "SecretWord", true)]
        [DataRow(" = \"t0ps3cr3t\"", "",                           "sEcretworD", true)]

        [DataRow("",                 "SecretWord = \"\"",          "TestPassword", false)]
        [DataRow("",                 "SecretWord = \"\"",          "TeStPassWORD", false)]
        [DataRow(" = \"\"",          "",                           "SecretWord",   false)]
        [DataRow(" = \"\"",          "",                           "sEcretworD",   false)]
        [DataRow("",                 "SecretWord = String.Empty",  "TestPassword", false)]
        [DataRow("",                 "SecretWord = String.Empty",  "TeStPassWORD", false)]
        [DataRow(" = String.Empty",  "",                           "SecretWord",   false)]
        [DataRow(" = String.Empty",  "",                           "sEcretworD",   false)]
        public async Task HardcodedPassword(string classPayload, string payload, string pattern, bool warn)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System;
#pragma warning restore 8019

namespace VulnerableApp
{{
#pragma warning disable CS0414
    class HardCodedPassword
    {{
        private string SecretWord{classPayload};

        void Foo()
        {{
            {payload};
        }}
    }}
#pragma warning restore CS0414
}}
";

            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System
#Enable Warning BC50001

Namespace VulnerableApp
    Class HardCodedPassword
        Private SecretWord As String{classPayload}

        Private Sub Foo()
            {payload}
        End Sub
    End Class
End Namespace
";
            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);

            var testConfig = $@"
PasswordFields: [{pattern}]
";
            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            if (warn)
            {
                var expected = new DiagnosticResult
                {
                    Id       = "SCS0015",
                    Severity = DiagnosticSeverity.Warning
                };

                await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            }
        }
    }
}
