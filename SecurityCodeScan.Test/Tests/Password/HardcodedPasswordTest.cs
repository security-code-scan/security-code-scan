using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Helpers;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test.Password
{
    [TestClass]
    public class HardcodedPasswordTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string _)
        {
            return new[] { new HardcodedPasswordAnalyzer() };
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
        public async Task HardCodePasswordDerivedBytesPassword()
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

        [TestCategory("Detect")]
        [DataTestMethod]
        //[DataRow("DESCryptoServiceProvider", "IV = System.Text.Encoding.Default.GetBytes(\"abc\")", true)] // todo:
        [DataRow("DESCryptoServiceProvider", "IV = new byte[] { 5, 17, 29, 41, 53, 65, 77, 89 }",   true)]
        //[DataRow("DESCryptoServiceProvider", "Key = System.Text.Encoding.Default.GetBytes(\"abc\")", true)] // todo:
        [DataRow("DESCryptoServiceProvider", "Key = new byte[] { 5, 17, 29, 41, 53, 65, 77, 89 }",   true)]
        [DataRow("DESCryptoServiceProvider", "Key = new byte[] { b, b, b, b, b, b, b, 89 }", false)]
        public async Task HardcodedIV(string type, string payload, bool warn)
        {
            var cSharpTest = $@"
using System.Security.Cryptography;

namespace VulnerableApp
{{
    class HardCodedPassword
    {{
        static string TestHardcodedValue(byte[] cipher, byte[] key, byte b)
        {{
            var desService = new {type}();

            desService.{payload};

            using (var transform = desService.CreateDecryptor())
            {{
                byte[] decryptedBytes = transform.TransformFinalBlock(cipher, 0, cipher.Length);
                return System.Text.Encoding.Default.GetString(decryptedBytes);
            }}
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Security.Cryptography

Namespace VulnerableApp
    Class HardCodedPassword
        Private Shared Function TestHardcodedValue(ByVal cipher As Byte(), ByVal key As Byte(), ByVal b As Byte) As String
            Dim desService = New {type}()
            desService.{payload.CSharpReplaceToVBasic()}

            Using transform = desService.CreateDecryptor()
                Dim decryptedBytes As Byte() = transform.TransformFinalBlock(cipher, 0, cipher.Length)
                Return System.Text.Encoding.[Default].GetString(decryptedBytes)
            End Using
        End Function
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0015",
                Severity = DiagnosticSeverity.Warning
            };

            if (warn)
            {
                await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest, null).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, null).ConfigureAwait(false);
            }
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task HardCodePasswordDerivedBytesSalt()
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

            var expected = new DiagnosticResult
            {
                Id       = "SCS0015",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }
    }
}
