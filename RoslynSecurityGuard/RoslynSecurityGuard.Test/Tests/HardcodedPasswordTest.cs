using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers.Taint;

using System.Collections.Generic;
using System.Security.Cryptography;
using TestHelper;

namespace RoslynSecurityGuard.Tests
{
    [TestClass]
    public class HardcodedPasswordTest : DiagnosticVerifier
    {

        protected override DiagnosticAnalyzer GetCSharpDiagnosticAnalyzers()
        {
            return new TaintAnalyzer();
        }

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            //Making sure cryptography assembly is loaded
            return new[] { MetadataReference.CreateFromFile(typeof(PasswordDeriveBytes).Assembly.Location) };
        }

        [TestMethod]
        public void HardCodePasswordDerivedBytes()
        {

            var test = @"
using System.Collections.Generic;
using System.Security.Cryptography;

namespace VulnerableApp
{
    class HardCodedPassword
    {
        static void TestCookie()
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
            VerifyCSharpDiagnostic(test, expected );
        }


        [TestMethod]
        public void HardCodePasswordDerivedBytesFalsePositive()
        {

            var test = @"
using System.Collections.Generic;
using System.Security.Cryptography;

namespace VulnerableApp
{
    class HardCodedPassword
    {
        static void TestCookie(string input)
        {
            var test = new PasswordDeriveBytes(input, new byte[] { 0, 1, 2, 3 });
        }
    }
}
";
            VerifyCSharpDiagnostic(test);
        }

        private void sandbox()
        {
            var test = new PasswordDeriveBytes("test", new byte[] { 0, 1, 2, 3 });
        }
    }
}
