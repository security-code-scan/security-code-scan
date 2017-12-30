using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers.Taint;
using System.Collections.Generic;
using System.Threading.Tasks;
using TestHelper;

namespace SecurityCodeScan.Test.Tests.Taint
{
    [TestClass]
    public class TaintTransferTest : DiagnosticVerifier
    {

        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new List<DiagnosticAnalyzer> { new TaintAnalyzer() };
        }

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[] { MetadataReference.CreateFromFile(typeof(System.Data.SqlClient.SqlCommand).Assembly.Location) };
        }

        [TestMethod]
        public async Task TransferStringFormatSafe()
        {
            var cSharpTest = @"
using System;
using System.Data.SqlClient;

class SqlTransferTesting
{
    public static void Run()
    {
        string tableName = ""table_name"";

        string safeQuery = String.Format(""SELECT * FROM {0}"",tableName);
        new SqlCommand(safeQuery);
    }
}
";
            var visualBasicTest = @"
Imports System.Data.SqlClient

Class SqlTransferTesting
    Public Shared Sub Run()
        Dim tableName As String = ""table_name""

        Dim safeQuery As String = String.Format(""Select * FROM {0}"", tableName)
		Dim com As New SqlCommand(safeQuery)
	End Sub
End Class
";
            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
            
        }

        [TestMethod]
        public async Task TransferStringFormatUnSafe1()
        {
            var cSharpTest = @"
using System;
using System.Data.SqlClient;

class SqlTransferTesting
{
    public static void Run(string input)
    {
        string tableName = input;

        string safeQuery = String.Format(""SELECT * FROM {0}"", tableName);
        new SqlCommand(safeQuery);
    }
}
";
            var visualBasicTest = @"
Imports System.Data.SqlClient

Class SqlTransferTesting
    Public Shared Sub Run(input As String)
        Dim tableName As String = input

        Dim safeQuery As String = String.Format(""Select * FROM {0}"", tableName)
		Dim com As New SqlCommand(safeQuery)
	End Sub
End Class
";
            var expected = new DiagnosticResult
            {
                Id = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
            await VerifyCSharpDiagnostic(cSharpTest, expected);
        }

        [TestMethod]
        public async Task TransferStringFormatUnSafe2()
        {
            var cSharpTest = @"
using System;
using System.Data.SqlClient;

class SqlTransferTesting
{
    public static void Run(string input)
    {
        string query = input;

        string safeQuery = String.Format(query, ""test"");
        new SqlCommand(safeQuery);
    }
}
";
            var visualBasicTest = @"
Imports System.Data.SqlClient

Class SqlTransferTesting
    Public Shared Sub Run(input As String)
        Dim query As String = input

        Dim safeQuery As String = String.Format(query, ""test"")
		Dim com As New SqlCommand(safeQuery)
	End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
            await VerifyCSharpDiagnostic(cSharpTest, expected);
        }


        [TestMethod]
        public async Task TransferStringInterpolatedSafe()
        {
            var cSharpTest = @"
using System.Data.SqlClient;

class SqlTransferTesting
{
    public static void Run(string input)
    {
        string query = input;

        string safeQuery = $""SELECT * FROM test"";
        new SqlCommand(safeQuery);
    }
}
";

            var visualBasicTest = @"
Imports System.Data.SqlClient

Class SqlTransferTesting
    Public Shared Sub Run(input As String)
        Dim query As String = input

        Dim safeQuery As String = ""SELECT* FROM test""
        Dim com As New SqlCommand(safeQuery)
	End Sub
End Class
";

            await VerifyVisualBasicDiagnostic(visualBasicTest);
            await VerifyCSharpDiagnostic(cSharpTest);
        }

        [TestMethod]
        public async Task TransferStringInterpolatedUnSafe()
        {
            var cSharpTest = @"
using System.Data.SqlClient;

class SqlTransferTesting
{
    public static void Run(string input)
    {
        string query = input;

        string safeQuery = $""{query}"";
        new SqlCommand(safeQuery);
    }
}
";

            var expected = new DiagnosticResult
            {
                Id = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
        }
    }
    
}
