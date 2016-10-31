using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers.Taint;
using System.Collections.Generic;
using TestHelper;

namespace RoslynSecurityGuard.Test.Tests
{

    /// <summary>
    /// This class regroup test cases covering condition, loop and other structural statements..
    /// </summary>
    [TestClass]
    public class TaintAnalyzerControlFlowTest : DiagnosticVerifier
    {

        protected override DiagnosticAnalyzer GetCSharpDiagnosticAnalyzers()
        {
            return new TaintAnalyzer();
        }


        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[] { MetadataReference.CreateFromFile(typeof(System.Data.SqlClient.SqlCommand).Assembly.Location) };
        }

        [TestMethod]
        public void Condition1()
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

            if(variable2 != '') {
                new SqlCommand(variable2);
            }
        }
    }
}
";
            var expected = new DiagnosticResult
            {
                Id = "SG0014",
                Severity = DiagnosticSeverity.Warning,
            };
            VerifyCSharpDiagnostic(test,expected);
        }

        [TestMethod]
        public void Condition2()
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

            if(variable2 != '')
                new SqlCommand(variable2);

        }
    }
}
";

            var expected = new DiagnosticResult
            {
                Id = "SG0014",
                Severity = DiagnosticSeverity.Warning,
            };
            VerifyCSharpDiagnostic(test, expected);
        }


        [TestMethod]
        public void Loop1()
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
                Id = "SG0014",
                Severity = DiagnosticSeverity.Warning,
            };
            VerifyCSharpDiagnostic(test, expected);
        }


        [TestMethod]
        public void Loop2()
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
                Id = "SG0014",
                Severity = DiagnosticSeverity.Warning,
            };
            VerifyCSharpDiagnostic(test, expected);
        }
    }
}
