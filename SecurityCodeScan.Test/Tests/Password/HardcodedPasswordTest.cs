using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Helpers;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test.Password
{
    [TestClass]
    public class HardcodedPasswordTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            if (language == LanguageNames.CSharp)
                return new DiagnosticAnalyzer[] { new CSharpAnalyzers(new TaintAnalyzerCSharp()) };
            else
                return new DiagnosticAnalyzer[] { new VBasicAnalyzers(new TaintAnalyzerVisualBasic()) };
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task HardCodePasswordNetworkCredential()
        {
            var cSharpTest = @"
using System;
using System.Net;

namespace VulnerableApp
{
    class HardCodedPassword
    {
        static void TestHardcodedValue()
        {
            var test = new NetworkCredential(Guid.NewGuid().ToString(), ""pass"");
        }
    }
}
";

            var visualBasicTest = @"
Imports System
Imports System.Net

Namespace VulnerableApp
    Class HardCodedPassword
        Private Shared Sub TestHardcodedValue()
            Dim test = New NetworkCredential(Guid.NewGuid().ToString(), ""pass"")
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0015",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task HardCodePasswordDerivedBytes()
        {
            var cSharpTest = @"
using System.Security.Cryptography;

namespace VulnerableApp
{
    class HardCodedPassword
    {
        static void TestHardcodedValue()
        {
            var test = new PasswordDeriveBytes(""hardcode"", new byte[] { 0, 1, 2, 3 });
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Security.Cryptography

Namespace VulnerableApp
    Class HardCodedPassword
        Private Shared Sub TestHardcodedValue()
            Dim test = New PasswordDeriveBytes(""hardcode"", New Byte() {0, 1, 2, 3})
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0015",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task HardCodePasswordDerivedBytesFalsePositive()
        {
            var cSharpTest = @"
using System.Security.Cryptography;

namespace VulnerableApp
{
    class HardCodedPassword
    {
        static void TestHardcodedValue(string input)
        {
            var test = new PasswordDeriveBytes(input, new byte[] { 0, 1, 2, 3 });
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Security.Cryptography

Namespace VulnerableApp
    Class HardCodedPassword
        Private Shared Sub TestHardcodedValue(input As String)
            Dim test = New PasswordDeriveBytes(input, New Byte() {0, 1, 2, 3})
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }
    }
}
