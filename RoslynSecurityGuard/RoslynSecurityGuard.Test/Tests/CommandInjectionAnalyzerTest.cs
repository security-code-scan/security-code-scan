using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers;
using RoslynSecurityGuard.Analyzers.Taint;
using System.Diagnostics;
using TestHelper;

namespace RoslynSecurityGuard.Tests
{

    [TestClass]
    public class CommandInjectionAnalyzerTest : DiagnosticVerifier
    {

        protected override DiagnosticAnalyzer GetCSharpDiagnosticAnalyzers()
        {
            return new TaintAnalyzer();
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



        [TestMethod]
        public void CommandInjectionFalsePositive_Filename()
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
                Severity = DiagnosticSeverity.Warning
            };

            VerifyCSharpDiagnostic(test, expected);
        }


        [TestMethod]
        public void CommandInjectionVulnerable2()
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

            VerifyCSharpDiagnostic(test, expected);
        }


        private void sandbox(string input) {
            ProcessStartInfo p = new ProcessStartInfo();
            p.FileName = input;
            p.Arguments = input;
            Process.Start(p);
        }
    }
}