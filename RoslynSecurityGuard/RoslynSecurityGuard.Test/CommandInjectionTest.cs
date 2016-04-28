using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TestHelper;

namespace RoslynSecurityGuard.Test
{

    [TestClass]
    public class CommandInjectionTest : DiagnosticVerifier
    {

        protected override DiagnosticAnalyzer GetCSharpDiagnosticAnalyzer()
        {
            return new CommandInjectionAnalyzer();
        }

        //No diagnostics expected to show up
        [TestMethod]
        public void CommandInjectionFalsePositive()
        {
            var test = @"
using System;
using System.Diagnostics;

namespace VulnerableApp
{
class ProcessExec
{
    static void TestCommandInject(string input)
    {
            Process.Start(""dir"");
    }
}
}
";
            VerifyCSharpDiagnostic(test);
        }

        //Diagnostic and CodeFix both triggered and checked for
        [TestMethod]
        public void CommandInjectionVulnerable1()
        {
            var test = @"
using System;
using System.Diagnostics;

namespace VulnerableApp
{
class ProcessExec
{
    static void TestCommandInject(string input)
    {
        Process.Start(input);
    }
}
}
        ";

            var expected = new DiagnosticResult
            {
                Id = "SG0001",
                Severity = DiagnosticSeverity.Warning,
                
            };

            VerifyCSharpDiagnostic(test, expected);
        }
    }
}