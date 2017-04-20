using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers.Taint;
using System.Collections.Generic;
using System.Threading.Tasks;
using TestHelper;

namespace RoslynSecurityGuard.Test.Tests.Taint
{
    [TestClass]
    public class TaintTransferTest : DiagnosticVerifier
    {

        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
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
            var test = @"
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
            await VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public async Task TransferStringFormatUnSafe1()
        {
            var test = @"
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


            var expected = new DiagnosticResult
            {
                Id = "SG0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(test, expected);
        }

        [TestMethod]
        public async Task TransferStringFormatUnSafe2()
        {
            var test = @"
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

            var expected = new DiagnosticResult
            {
                Id = "SG0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(test, expected);
        }


        [TestMethod]
        public async Task TransferStringInterpolatedSafe()
        {
            var test = @"
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

            var yolo = $"123 {test.ToString()}";
            await VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public async Task TransferStringInterpolatedUnSafe()
        {
            var test = @"
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
                Id = "SG0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(test, expected);
        }
    }
    
}
