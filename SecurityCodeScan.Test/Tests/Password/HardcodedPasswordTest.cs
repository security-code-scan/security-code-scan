using System.Collections.Generic;
using System.Security.Cryptography;
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
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new[] { new TaintAnalyzer() };
        }

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            //Making sure cryptography assembly is loaded
            return new[] { MetadataReference.CreateFromFile(typeof(PasswordDeriveBytes).Assembly.Location) };
        }

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

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

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

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }
    }
}
