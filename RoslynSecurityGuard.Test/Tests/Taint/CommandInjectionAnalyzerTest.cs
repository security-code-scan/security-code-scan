using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers;
using RoslynSecurityGuard.Analyzers.Taint;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;
using TestHelper;

namespace RoslynSecurityGuard.Tests
{

    [TestClass]
    public class CommandInjectionAnalyzerTest : DiagnosticVerifier
    {

        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
        {
            return new[] { new TaintAnalyzer() };
        }

        //No diagnostics expected to show up
        [TestMethod]
        public async Task CommandInjectionFalsePositive()
        {
            var test = @"
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
            await VerifyCSharpDiagnostic(test);
        }



        [TestMethod]
        public async Task CommandInjectionFalsePositive_Filename()
        {
            var test = @"
using System.Diagnostics;

namespace VulnerableApp
{
    class ProcessExec
    {
        static void TestCommandInject(string input)
        {
            ProcessStartInfo p = new ProcessStartInfo();
            p.FileName = ""1234"";
        }
    }
}
";

            var expected = new DiagnosticResult
            {
                Id = "SG0001",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(test);
        }
        
        [TestMethod]
        public async Task CommandInjectionVulnerable1()
        {
            var test = @"
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
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(test, expected);
        }


        [TestMethod]
        public async Task CommandInjectionVulnerable2()
        {
            var test = @"
using System.Diagnostics;

namespace VulnerableApp
{
    class ProcessExec
    {
        static void TestCommandInject(string input)
        {
            ProcessStartInfo p = new ProcessStartInfo();
            p.FileName = input;
            //Process.Start(p);
        }
    }
}
";

            var expected = new DiagnosticResult
            {
                Id = "SG0001",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(test, expected);
        }


        private void sandbox(string input) {
            ProcessStartInfo p = new ProcessStartInfo();
            p.FileName = input;
            p.Arguments = input;
            Process.Start(p);
        }
    }
}