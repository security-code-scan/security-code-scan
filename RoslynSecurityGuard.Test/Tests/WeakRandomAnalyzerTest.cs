using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using TestHelper;

namespace RoslynSecurityGuard.Tests
{
    [TestClass]
    public class WeakRandomAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
        {
            return new[] { new WeakRandomAnalyzer() };
        }

        [TestMethod]
        public async Task RandomFalsePositive()
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
            await VerifyCSharpDiagnostic(code);
        }

        [TestMethod]
        public async Task RandomVulnerable1()
        {
            var code = @"
using System;

class WeakRandom
{
    static string generateWeakToken()
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
            }.WithLocation(9, -1);

            await VerifyCSharpDiagnostic(code, expected);
        }
    }
}
