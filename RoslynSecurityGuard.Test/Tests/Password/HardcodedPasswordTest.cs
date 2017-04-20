using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers.Taint;

using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;
using TestHelper;

namespace RoslynSecurityGuard.Tests
{
    [TestClass]
    public class HardcodedPasswordTest : DiagnosticVerifier
    {

        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
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

            var test = @"
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

            var expected = new DiagnosticResult
            {
                Id = "SG0015",
                Severity = DiagnosticSeverity.Warning
            };
            await VerifyCSharpDiagnostic(test, expected );
        }


        [TestMethod]
        public async Task HardCodePasswordDerivedBytesFalsePositive()
        {

            var test = @"
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
            await VerifyCSharpDiagnostic(test);
        }

        private void sandbox()
        {
            var test = new PasswordDeriveBytes("test", new byte[] { 0, 1, 2, 3 });
        }
    }
}
