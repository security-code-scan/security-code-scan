using System.Collections.Generic;
using System.Linq;
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
    public class TaintTransferTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            return new List<DiagnosticAnalyzer> { new TaintAnalyzerCSharp(), new TaintAnalyzerVisualBasic() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(System.Data.SqlClient.SqlCommand).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

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
        string column1 = ""1"";

        string safeQuery = String.Format(""SELECT * FROM {0}"", tableName);
        new SqlCommand(safeQuery);

        safeQuery = String.Format(""SELECT {1} FROM {0}"", tableName, column1);
        new SqlCommand(safeQuery);

        safeQuery = String.Format(""SELECT {1},{2} FROM {0}"", tableName, column1, column1);
        new SqlCommand(safeQuery);

        safeQuery = String.Format(""SELECT {1},{2},{3} FROM {0}"", tableName, column1, column1, column1);
        new SqlCommand(safeQuery);

        safeQuery = String.Format(null, ""SELECT * FROM {0}"", tableName);
        new SqlCommand(safeQuery);

        safeQuery = String.Format(null, ""SELECT {1} FROM {0}"", tableName, column1);
        new SqlCommand(safeQuery);

        safeQuery = String.Format(null, ""SELECT {1},{2} FROM {0}"", tableName, column1, column1);
        new SqlCommand(safeQuery);

        safeQuery = String.Format(null, ""SELECT {1},{2},{3} FROM {0}"", tableName, column1, column1, column1);
        new SqlCommand(safeQuery);
    }
}
";

            var visualBasicTest = @"
Imports System.Data.SqlClient

Class SqlTransferTesting
    Public Shared Sub Run()
        Dim tableName As String = ""table_name""
        Dim column1 As String = ""1""

        Dim safeQuery As String = String.Format(""Select * FROM {0}"", tableName)
        Dim com1 As New SqlCommand(safeQuery)

        safeQuery = String.Format(""SELECT {1} FROM {0}"", tableName, column1)
        Dim com2 As New SqlCommand(safeQuery)

        safeQuery = String.Format(""SELECT {1},{2} FROM {0}"", tableName, column1, column1)
        Dim com3 As New SqlCommand(safeQuery)

        safeQuery = String.Format(""SELECT {1},{2},{3} FROM {0}"", tableName, column1, column1, column1)
        Dim com4 As New SqlCommand(safeQuery)

        safeQuery = String.Format(Nothing, ""SELECT * FROM {0}"", tableName)
        Dim com5 As New SqlCommand(safeQuery)

        safeQuery = String.Format(Nothing, ""SELECT {1} FROM {0}"", tableName, column1)
        Dim com6 As New SqlCommand(safeQuery)

        safeQuery = String.Format(Nothing, ""SELECT {1},{2} FROM {0}"", tableName, column1, column1)
        Dim com7 As New SqlCommand(safeQuery)

        safeQuery = String.Format(Nothing, ""SELECT {1},{2},{3} FROM {0}"", tableName, column1, column1, column1)
        Dim com8 As New SqlCommand(safeQuery)
    End Sub
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [DataRow("static")]
        [DataRow("")]
        [DataTestMethod]
        public async Task MemberFunction(string modifier)
        {
            var cSharpTest = $@"
using System.IO;

class PathTraversal
{{
    private {modifier} byte[] GetBytes()
    {{
        return new byte[1];
    }}

    public {modifier} void Run()
    {{
        File.WriteAllBytes(""a.txt"", GetBytes());
    }}
}}
";

            modifier = modifier.Replace("static", "Shared");
            var visualBasicTest = $@"
Imports System.IO

Class PathTraversal
    Private {modifier} Function GetBytes() As System.Byte()
        return New System.Byte(1) {{}}
    End Function
    Public {modifier} Sub Run()
        File.WriteAllBytes(""a.txt"", GetBytes())
    End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0018",
                Severity = DiagnosticSeverity.Warning,
            };
            // Methods are not expanded and taint of 'this' doesn't affect a member call without arguments
            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        [Ignore] // todo: stream passed to Foo should be tainted
        public async Task TaintPassedArgument()
        {
            var cSharpTest = @"
using System.IO;

class Test
{
    private byte[] _bytes;

    public Test(byte[] bytes)
    {
        _bytes = bytes;
    }

    public void Foo(MemoryStream s)
    {
        s.Write(_bytes, 0, _bytes.Length);
    }
}

class PathTraversal
{
    public static void Run(byte[] bytes)
    {
        var stream = new MemoryStream();
        var t = new Test((byte[])(object)bytes);
        t.Foo((MemoryStream)(object)stream);
        File.WriteAllBytes(""a.txt"", stream.ToArray());
    }
}
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0018",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task TransferSqlInitializerSafe()
        {
            var cSharpTest = @"
using System.Data.SqlClient;

namespace sample
{
    class MyFoo
    {
        public static void Run()
        {
            var sqlCommand = new SqlCommand {CommandText = ""select * from Products""};
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Data.SqlClient

Namespace sample
    Class MyFoo
        Public Shared Sub Run()
            Dim com As New SqlCommand With {.CommandText = ""select * from Products""}
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [DataTestMethod]
        [DataRow("sql",       new[] { "SCS0026" },           new[] { "SCS0026" })]
        [DataRow("xyz",       new[] { "CS0103" },            new[] { "BC30451" })]
        [DataRow("foo()",     new[] { "CS0029" },            new[] { "BC30311" })]
        [DataRow("foo2(xyz)", new[] { "SCS0026", "CS0103" }, new[] { "SCS0026", "BC30451" })]
        public async Task TransferSqlInitializerUnSafe(string right, string[] csErrors, string[] vbErrors)
        {
            var cSharpTest = $@"
using System.Data.SqlClient;

namespace sample
{{
    class MyFoo
    {{
        public static void Run(string sql)
        {{
            var sqlCommand = new SqlCommand {{CommandText = {right}}};
        }}

        static MyFoo foo()
        {{
            return null;
        }}

        static string foo2(string a)
        {{
            return null;
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Data.SqlClient

Namespace sample
    Class MyFoo
        Public Shared Sub Run(sql As System.String)
            Dim com As New SqlCommand With {{.CommandText = {right}}}
        End Sub

        Private Shared Function foo() As MyFoo
            Return Nothing
        End Function

        Private Shared Function foo2(a As String) As String
            Return Nothing
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest,
                                         csErrors.Select(x => new DiagnosticResult { Id = x }.WithLocation("Test0.cs", 10)).ToArray())
                .ConfigureAwait(false);

            await VerifyVisualBasicDiagnostic(visualBasicTest,
                                              vbErrors.Select(x => new DiagnosticResult { Id = x }.WithLocation("Test0.vb", 7)).ToArray())
                .ConfigureAwait(false);
        }

        [TestMethod]
        public async Task TransferPathInitializerSafe()
        {
            var cSharpTest = @"
using System.IO;

class PathTraversal
{
    public static void Run()
    {
        File.WriteAllBytes(""a.txt"", new MemoryStream {Capacity = 10}.ToArray());
    }
}
";

            var visualBasicTest = @"
Imports System.IO

Class PathTraversal
    Public Shared Sub Run()
        File.WriteAllBytes(""a.txt"", new MemoryStream With {.Capacity = 10}.ToArray())
    End Sub
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [DataRow("File.OpenRead(Directory.GetCurrentDirectory() + \"aaa.txt\")")]
        [DataRow("File.OpenRead(Path.ChangeExtension(\"c:\\aaa.txt\", \".bin\"))")]
        [DataRow("File.OpenRead(Path.Combine(\"c:\\temp\", \"aaa.txt\"))")]
        [DataRow("File.OpenRead(Path.Combine(\"c:\\temp\", \"sub\", \"aaa.txt\"))")]
        [DataRow("File.OpenRead(Path.Combine(\"c:\\temp\", \"sub\", \"sub\", \"aaa.txt\"))")]
        [DataRow("File.OpenRead(Path.Combine(\"c:\\temp\", \"sub\", \"sub\", \"sub\", \"aaa.txt\"))")]
        [DataRow("File.OpenRead(Path.Combine(new [] {\"aaa\"}))")]
        [DataRow("File.OpenRead(Path.GetDirectoryName(\"c:\\aaa.txt\") + \"b.txt\")")]
        [DataRow("File.OpenRead(\"b\" + Path.GetExtension(\"c:\\aaa.txt\"))")]
        [DataRow("File.OpenRead(Path.GetFileName(\"c:\\aaa.txt\"))")]
        [DataRow("File.OpenRead(Path.GetFileNameWithoutExtension(\"c:\\aaa.txt\") + \".txt\")")]
        [DataRow("File.OpenRead(Path.GetFullPath(\"c:\\aaa.txt\"))")]
        [DataRow("File.OpenRead(Path.GetInvalidFileNameChars() + \".txt\")")]
        [DataRow("File.OpenRead(Path.GetInvalidPathChars() + \".txt\")")]
        [DataRow("File.OpenRead(Path.GetPathRoot(\"c:\\aaa.txt\") + \"b.txt\")")]
        [DataRow("File.OpenRead(Path.GetRandomFileName())")]
        [DataRow("File.OpenRead(Path.GetTempFileName())")]
        [DataRow("File.OpenRead(Path.GetTempPath() + \"b.txt\")")]
        [DataRow("File.OpenRead(Path.HasExtension(\"c:\\aaa.txt\").ToString())")]
        [DataRow("File.OpenRead(Path.IsPathRooted(\"c:\\aaa.txt\").ToString())")]
        [DataRow("File.OpenRead(1.ToString())")]
        [DataRow("File.OpenRead(Path.AltDirectorySeparatorChar.ToString())")]
        [DataRow("File.OpenRead(Path.DirectorySeparatorChar.ToString())")]
        [DataRow("File.OpenRead(Path.InvalidPathChars.ToString())")]
        [DataRow("File.OpenRead(Path.PathSeparator.ToString())")]
        [DataRow("File.OpenRead(Path.VolumeSeparatorChar.ToString())")]
        [DataTestMethod]
        public async Task TransferPathSafe(string method)
        {
            var cSharpTest = $@"
using System.IO;

class PathTraversal
{{
    public static void Run()
    {{
#pragma warning disable 618
        {method};
#pragma warning restore 618
    }}
}}
";
            method = method.Replace("new []", "");
            var visualBasicTest = $@"
Imports System.IO

Class PathTraversal
    Public Shared Sub Run()
#Disable Warning BC40000
        {method}
#Enable Warning BC40000
    End Sub
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task MemberCallWithoutArguments()
        {
            var cSharpTest = @"
using System.IO;

class PathTraversal
{
    public static void Run(int input)
    {
        File.OpenRead(input.ToString());
    }
}
";

            var visualBasicTest = @"
Imports System.IO

Class PathTraversal
    Public Shared Sub Run(input As System.Int32)
        File.OpenRead(input.ToString())
    End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0018",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task TransferStringConstructorSafe()
        {
            var cSharpTest = @"
using System.Data.SqlClient;

class SqlTransferTesting
{
    public static void Run()
    {
        new SqlCommand(new string(new []{'t'}));
        new SqlCommand(new string(new []{'t'}, 0, 3));
    }
}
";

            var visualBasicTest = @"
Imports System.Data.SqlClient

Class SqlTransferTesting
    Public Shared Sub Run()
        Dim chars1 = {""t""c, ""e""c}
        Dim safeQuery As String = New String(chars1)
        Dim com1 As New SqlCommand(safeQuery)

        safeQuery = New String(chars1, 0, 3)
        Dim com2 As New SqlCommand(safeQuery)
    End Sub
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
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
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
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
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
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

            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
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
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
        }
    }
}
