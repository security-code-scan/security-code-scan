using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers;
using RoslynSecurityGuard.Analyzers.Taint;
using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Security;
using System.Threading.Tasks;
using TestHelper;

namespace RoslynSecurityGuard.Test.Tests
{
    [TestClass]
    public class HardcodedPasswordFieldTest : DiagnosticVerifier
    {

        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
        {
            return new DiagnosticAnalyzer[] { new TaintAnalyzer(), new UnknownPasswordApiAnalyzer() };
        }

        [TestMethod]
        public async Task HardCodePasswordDerivedBytes()
        {

            var test = @"
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

            var expected = new DiagnosticResult
            {
                Id = "SG0015",
                Severity = DiagnosticSeverity.Warning
            };
            await VerifyCSharpDiagnostic(test, expected);
        }

        public void sandbox()
        {
            var uri = new UriBuilder();
            uri.Password = "t0ps3cr3t";
        }
    }
}
