using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers.Taint;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Threading.Tasks;
using TestHelper;

namespace RoslynSecurityGuard.Tests
{
    [TestClass]
    public class TaintAnalyzerTest : DiagnosticVerifier
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
        public async Task VariableTransferSimple()
        {
            var cSharpTest = @"
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
            var visualBasicTest = @"
Imports System.Data.SqlClient

Namespace sample
	Class SqlConstant
		Public Shared Sub Run()
			Dim username As String = ""Hello Friend..""
            Dim variable1 = username
            Dim variable2 = variable1

            Dim com As New SqlCommand(variable2)
        End Sub

    End Class
End Namespace
";
            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [TestMethod]
        public async Task VariableConcatenation()
        {
            var cSharpTest = @"
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
            var visualBasicTest = @"
Imports System.Data.SqlClient

Namespace sample
	Class SqlConstant
		Public Shared Sub Run()
			Dim username As String = ""Shall we play a game?""

			Dim com As New SqlCommand(""SELECT * FROM users WHERE username = '"" & username + ""' LIMIT 1"")
		End Sub
	End Class
End Namespace
";
            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [TestMethod]
        public async Task VariableTransferWithConcatenation()
        {
            var cSharpTest = @"
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
            var visualBasicTest = @"
Imports System.Data.SqlClient

Namespace sample
	Class SqlConstant
		Public Shared Sub Run()
			Dim username As String = ""Hello Friend..""
            Dim variable1 = username
            Dim variable2 = variable1

            Dim com As New SqlCommand(""SELECT* FROM users WHERE username = '"" + variable2 + ""' LIMIT 1"")
        End Sub

    End Class
End Namespace
";
            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [TestMethod]
        public async Task VariableTransferUnsafe()
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

            Dim com As New SqlCommand(variable2)
        End Sub

    End Class
End Namespace
";
            var expected = new DiagnosticResult
            {
                Id = "SG0026",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }
        
        [TestMethod]
        public async Task VariableConcatenationUnsafe()
        {
            var cSharpTest = @"
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
            var visualBasicTest = @"
Imports System.Data.SqlClient

Namespace sample
    Class SqlConstant
        Public Shared Sub Run(input As String)
            Dim com As New SqlCommand(""SELECT* FROM users WHERE username = '"" & input & ""' LIMIT 1"")
        End Sub
    End Class
End Namespace
";


            var expected = new DiagnosticResult
            {
                Id = "SG0026",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        [TestMethod]
        public async Task VariableOverride() {
            var cSharpTest = @"
using System.Data.SqlClient;

namespace sample
{
    class SqlConstant
    {
        public static void Run(string input)
        {
            {
#pragma warning disable 219
                string username = ""ignore_me"";
#pragma warning restore 219
            }
            {
                string username = input;
                new SqlCommand(""SELECT* FROM users WHERE username = '"" + username + ""' LIMIT 1"");
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
			If True Then
				Dim username As String = ""ignore_me""
			End If
			If True Then
				Dim username As String = input
				Dim com As New SqlCommand(""SELECT* FROM users WHERE username = '"" & username + ""' LIMIT 1"")
			End If
		End Sub
	End Class
End Namespace
";
            var expected = new DiagnosticResult
            {
                Id = "SG0026",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }



        [TestMethod]
        public async Task VariableReuse()
        {
            var cSharpTest = @"
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
            var visualBasicTest = @"
Imports System.Data.SqlClient

Namespace sample
	Class SqlConstant
		Public Shared Sub Run(input As String)
			Dim query As String = ""SELECT * FROM [User] WHERE user_id = 1""
			Dim cmd1 As New SqlCommand(query)

			query = input
			Dim cmd2 As SqlCommand = New SqlCommand(query)
		End Sub
	End Class
End Namespace
";
            var expected = new DiagnosticResult
            {
                Id = "SG0026",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
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
