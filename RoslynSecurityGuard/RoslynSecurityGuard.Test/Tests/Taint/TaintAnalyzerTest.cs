using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers.Taint;
using System.Collections.Generic;
using System.Data.SqlClient;
using TestHelper;

namespace RoslynSecurityGuard.Tests
{
    [TestClass]
    public class TaintAnalyzerTest : DiagnosticVerifier
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
        public void VariableTransferSimple()
        {
            var test = @"
using System.Data.SqlClient;

namespace sample
{
    class SqlConstant
    {
        public static void Run()
        {
            string username = ""Hello Friend.."";
            var variable1 = username;
            var variable2 = variable1;

            new SqlCommand(variable2);
        }
    }
}
";
            VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public void VariableConcatenation()
        {
            var test = @"
using System.Data.SqlClient;

namespace sample
{
    class SqlConstant
    {
        public static void Run()
        {
            string username = ""Shall we play a game?"";

            new SqlCommand(""SELECT* FROM users WHERE username = '"" + username + ""' LIMIT 1"");
        }
    }
}
";
            VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public void VariableTransferWithConcatenation()
        {
            var test = @"
using System.Data.SqlClient;

namespace sample
{
    class SqlConstant
    {
        public static void Run()
        {
            string username = ""This is all safe"";
            var variable1 = username;
            var variable2 = variable1;

            new SqlCommand(""SELECT* FROM users WHERE username = '"" + variable2 + ""' LIMIT 1"");
        }
    }
}
";

            VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public void VariableTransferUnsafe()
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
            VerifyCSharpDiagnostic(test, expected);
        }


        [TestMethod]
        public void VariableConcatenationUnsafe()
        {
            var test = @"
using System.Data.SqlClient;

namespace sample
{
    class SqlConstant
    {
        public static void Run(string input)
        {
            new SqlCommand(""SELECT* FROM users WHERE username = '"" + input + ""' LIMIT 1"");
        }
    }
}
";

            var expected = new DiagnosticResult
            {
                Id = "SG0026",
                Severity = DiagnosticSeverity.Warning,
            };
            VerifyCSharpDiagnostic(test, expected);
        }



        [TestMethod]
        public void VariableOverride() {
            var test = @"
using System.Data.SqlClient;

namespace sample
{
    class SqlConstant
    {
        public static void Run(string input)
        {
            {
                string username = ""ignore_me"";
            }
            {
                string username = input;
                new SqlCommand(""SELECT* FROM users WHERE username = '"" + username + ""' LIMIT 1"");
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
            VerifyCSharpDiagnostic(test, expected);
        }



        [TestMethod]
        public void VariableReuse()
        {
            var test = @"
using System.Data.SqlClient;

namespace sample
{
    class SqlConstant
    {
        public static void Run(string input)
        {
            string query = ""SELECT * FROM [User] WHERE user_id = 1"";
            SqlCommand cmd1 = new SqlCommand(query);

            query = input;
            SqlCommand cmd2 = new SqlCommand(query);
        }
    }
}
";

            var expected = new DiagnosticResult
            {
                Id = "SG0026",
                Severity = DiagnosticSeverity.Warning,
            };
            VerifyCSharpDiagnostic(test, expected);
        }

/*
        public static void Run(string input)
        {
            string query = "SELECT* FROM[User] WHERE user_id = 1";
            new SqlCommand(query);

            query = input;
            new SqlCommand(query);
        }
*/
    }
}
