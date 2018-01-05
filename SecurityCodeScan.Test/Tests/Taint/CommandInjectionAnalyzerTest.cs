using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Helpers;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test.Taint
{
    [TestClass]
    public class CommandInjectionAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new[] { new TaintAnalyzer() };
        }

        //No diagnostics expected to show up
        [TestMethod]
        public async Task CommandInjectionFalsePositive()
        {
            var cSharpTest = @"
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

            var visualBasicTest = @"
Imports System.Diagnostics

Namespace VulnerableApp
	Class ProcessExec
		Private Shared Sub TestCommandInject(input As String)
			Process.Start(""dir"")
        End Sub

    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [TestMethod]
        public async Task CommandInjectionFalsePositive_Filename()
        {
            var cSharpTest = @"
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

            var visualBasicTest = @"
Imports System.Diagnostics

Namespace VulnerableApp
	Class ProcessExec
		Private Shared Sub TestCommandInject(input As String)
			Dim p As New ProcessStartInfo()
			p.FileName = ""1234""
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [TestMethod]
        public async Task CommandInjectionVulnerable1()
        {
            var cSharpTest = @"
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

            var visualBasicTest = @"
Imports System.Diagnostics

Namespace VulnerableApp
	Class ProcessExec
		Private Shared Sub TestCommandInject(input As String)
			Process.Start(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0001",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        [TestMethod]
        public async Task CommandInjectionVulnerable2()
        {
            var cSharpTest = @"
using System.Diagnostics;

namespace VulnerableApp
{
    class ProcessExec
    {
        static void TestCommandInject(string input)
        {
            ProcessStartInfo p = new ProcessStartInfo();
            p.FileName = input;
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Diagnostics

Namespace VulnerableApp
	Class ProcessExec
		Private Shared Sub TestCommandInject(input As String)
			Dim p As New ProcessStartInfo()
			p.FileName = input
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0001",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }
    }
}
