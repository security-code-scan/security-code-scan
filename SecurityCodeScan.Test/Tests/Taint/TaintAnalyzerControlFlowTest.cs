using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers.Taint;
using TestHelper;

namespace SecurityCodeScan.Test.Tests
{
    /// <summary>
    /// This class regroup test cases covering condition, loop and other structural statements..
    /// </summary>
    [TestClass]
    public class TaintAnalyzerControlFlowTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new[] { new TaintAnalyzer() };
        }

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[] { MetadataReference.CreateFromFile(typeof(System.Data.SqlClient.SqlCommand).Assembly.Location) };
        }

        [TestMethod]
        public async Task Condition1()
        {
            var cSharpTest = @"
using System.Data.SqlClient;

namespace sample
{
    class SqlConstant
    {
        public static void Run(string input)
        {
            string username = input;
            var variable1 = username;
            var variable2 = variable1;

            if(variable2 != """") {
                new SqlCommand(variable2);
            }
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Data.SqlClient

Namespace sample
	Class SqlConstant
		Public Shared Sub Run(input As String)
			Dim username As String = input
			Dim variable1 = username
			Dim variable2 = variable1

			If variable2 <> """" Then
				Dim com As New SqlCommand(variable2)
			End If
		End Sub
	End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        [TestMethod]
        public async Task Condition2()
        {
            var cSharpTest = @"
using System.Data.SqlClient;

namespace sample
{
    class SqlConstant
    {
        public static void Run(string input)
        {
            string username = input;
            var variable1 = username;
            var variable2 = variable1;

            if(variable2 != """")
                new SqlCommand(variable2);

        }
    }
}
";

            var visualBasicTest = @"
Imports System.Data.SqlClient

Namespace sample
	Class SqlConstant
		Public Shared Sub Run(input As String)
			Dim username As String = input
			Dim variable1 = username
			Dim variable2 = variable1

            Dim com As SqlCommand
			If (variable2 <> """") Then com = New SqlCommand(variable2)
		End Sub
	End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        [TestMethod]
        public async Task Loop1()
        {
            var cSharpTest = @"
using System.Data.SqlClient;

namespace sample
{
    class SqlConstant
    {
        public static void Run(string input)
        {
            string username = input;
            var variable1 = username;
            var variable2 = variable1;

            for (int i=0;i<10;i++) {
                new SqlCommand(variable2);
            }

        }
    }
}
";

            var visualBasicTest = @"
Imports System.Data.SqlClient

Namespace sample
	Class SqlConstant
		Public Shared Sub Run(input As String)
			Dim username As String = input
			Dim variable1 = username
			Dim variable2 = variable1

			For i As Integer = 0 To 9
				Dim com As New SqlCommand(variable2)
			Next
		End Sub
	End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        [TestMethod]
        public async Task Loop2()
        {
            var cSharpTest = @"
using System.Data.SqlClient;

namespace sample
{
    class SqlConstant
    {
        public static void Run(string input)
        {
            string username = input;
            var variable1 = username;
            var variable2 = variable1;

            for (int i=0;i<10;i++)
                new SqlCommand(variable2);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Data.SqlClient

Namespace sample
	Class SqlConstant
		Public Shared Sub Run(input As String)
			Dim username As String = input
			Dim variable1 = username
			Dim variable2 = variable1

			For i As Integer = 0 To 9
				Dim com As New SqlCommand(variable2)
			Next
		End Sub
	End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }
    }
}
