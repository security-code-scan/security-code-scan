using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers;
using System;
using TestHelper;

namespace RoslynSecurityGuard.Tests
{
    [TestClass]
    public class WeakRandomAnalyzerTest : DiagnosticVerifier
    {
        protected override DiagnosticAnalyzer GetCSharpDiagnosticAnalyzers()
        {
            return new WeakRandomAnalyzer();
        }

        [TestMethod]
        public void RandomFalsePositive()
        {
            var code = @"using System;
using System.Security.Cryptography;

class WeakRandom
{
    static String generateSecureToken()
    {

        RandomNumberGenerator rnd = RandomNumberGenerator.Create();

        byte[] buffer = new byte[16];
        rnd.GetBytes(buffer);
        return BitConverter.ToString(buffer);
    }
}
";
            VerifyCSharpDiagnostic(code);
        }

        [TestMethod]
        public void RandomVulnerable1()
        {
            var code = @"
using System;
using System.Security.Cryptography;

class WeakRandom
{
    static String generateWeakToken()
    {
        Random rnd = new Random();
        return rnd.Next().ToString(); //Vulnerable
    }
}
";

            var expected = new DiagnosticResult
            {
                Id = "SG0005",
                Severity = DiagnosticSeverity.Warning,
            }.WithLocation(10, -1);

            VerifyCSharpDiagnostic(code, expected);
        }
    }
}
