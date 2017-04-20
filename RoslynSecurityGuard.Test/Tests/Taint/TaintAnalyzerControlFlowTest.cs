using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers.Taint;
using System.Collections.Generic;
using System.Threading.Tasks;
using TestHelper;

namespace RoslynSecurityGuard.Test.Tests
{

    /// <summary>
    /// This class regroup test cases covering condition, loop and other structural statements..
    /// </summary>
    [TestClass]
    public class TaintAnalyzerControlFlowTest : DiagnosticVerifier
    {

        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
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
            var test = @"
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
            var expected = new DiagnosticResult
            {
                Id = "SG0026",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(test,expected);
        }

        [TestMethod]
        public async Task Condition2()
        {
            var test = @"
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

            var expected = new DiagnosticResult
            {
                Id = "SG0026",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(test, expected);
        }


        [TestMethod]
        public async Task Loop1()
        {
            var test = @"
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
            var expected = new DiagnosticResult
            {
                Id = "SG0026",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(test, expected);
        }


        [TestMethod]
        public async Task Loop2()
        {
            var test = @"
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
            var expected = new DiagnosticResult
            {
                Id = "SG0026",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(test, expected);
        }
    }
}
