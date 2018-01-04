using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Analyzers.Taint;
using TestHelper;

namespace SecurityCodeScan.Test.Tests
{
    [TestClass]
    public class HardcodedPasswordFieldTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new DiagnosticAnalyzer[] { new TaintAnalyzer(), new UnknownPasswordApiAnalyzer() };
        }

        [TestMethod]
        public async Task HardCodePasswordDerivedBytes()
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

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        //public void sandbox()
        //{
        //    var uri = new UriBuilder();
        //    uri.Password = "t0ps3cr3t";
        //}
    }
}
