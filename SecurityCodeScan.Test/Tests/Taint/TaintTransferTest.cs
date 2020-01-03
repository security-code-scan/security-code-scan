using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Audit;
using SecurityCodeScan.Test.Config;
using SecurityCodeScan.Test.Helpers;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test.Taint
{
    [TestClass]
    public class TaintTransferTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            if (language == LanguageNames.CSharp)
                return new DiagnosticAnalyzer[] { new CSharpAnalyzers(new TaintAnalyzerCSharp()) };
            else
                return new DiagnosticAnalyzer[] { new VBasicAnalyzers(new TaintAnalyzerVisualBasic()) };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(System.Data.SqlClient.SqlCommand).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestCategory("Detect")]
        [DataRow("static ")]
        [DataRow("")]
        [DataTestMethod]
        public async Task MemberFunction(string modifier)
        {
            var cSharpTest = $@"
using System.IO;

class PathTraversal
{{
    private {modifier}string GetPath()
    {{
        return """";
    }}

    public {modifier}void Run()
    {{
        File.WriteAllBytes(GetPath(), null);
    }}
}}
";

            modifier = modifier.CSharpReplaceToVBasic();
            var visualBasicTest = $@"
Imports System.IO

Class PathTraversal
    Private {modifier}Function GetPath() As System.String
        return Nothing
    End Function
    Public {modifier}Sub Run()
        File.WriteAllBytes(GetPath, Nothing)
    End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0018",
                Severity = DiagnosticSeverity.Warning,
            };

            var testConfig = @"
AuditMode: true
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            // Methods are not expanded and taint of 'this' doesn't affect a member call without arguments
            await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        [Ignore("stream passed to Foo should be tainted")]
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

        [TestCategory("Safe")]
        [TestMethod]
        public async Task SelfTaintAssignment()
        {
            var cSharpTest = @"
namespace sample
{
    class MyFoo
    {
        int x = 1;

        int y = 0;

        void foo()
        {
        }

        public static void Run(MyFoo[] aa)
        {
            foreach(var a in aa)
            {
                a.foo();
                a.x = a.y;
            }
        }
    }
}
";

            var visualBasicTest = @"
Namespace sample
    Friend Class MyFoo
        Private x As Integer = 1
        Private y As Integer = 0

        Private Sub foo()
        End Sub

        Public Shared Sub Run(ByVal aa As MyFoo())
            For Each a In aa
                a.foo()
                a.x = a.y
            Next
        End Sub
    End Class
End Namespace
";

            // should not throw
            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
            var auditConfig = await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, null, auditConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, auditConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task SelfTaintAssignment2()
        {
            var cSharpTest = @"
namespace sample
{
    class B
    {
        public A z = null;
    }

    class A
    {
        public B y = null;

        public static void Run()
        {
            A x = null;
            x.y.z = x;
            var a = x;
            a.y = null;
        }
    }
}
";

            var visualBasicTest = @"
Namespace sample
    Friend Class MyFoo
        Private x As Integer = 1
        Private y As Integer = 0

        Private Sub foo()
        End Sub

        Public Shared Sub Run(ByVal aa As MyFoo())
            For Each a In aa
                a.foo()
                a.x = a.y
            Next
        End Sub
    End Class
End Namespace
";

            // should not throw
            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
            var auditConfig = await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, null, auditConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, auditConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task SelfTaintAssignment3()
        {
            var cSharpTest = @"
namespace sample
{
    class A
    {
        public A y = null;

        public static void Run()
        {
            A x = null;
            x.y = x;
        }
    }
}
";

            var visualBasicTest = @"
Namespace sample
    Class A
        Public y As A = Nothing

        Public Shared Sub Run()
            Dim x As A = Nothing
            x.y = x
        End Sub
    End Class
End Namespace

";

            // should not throw
            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
            var auditConfig = await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, null, auditConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, auditConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task RecursiveStateAssignment()
        {
            var cSharpTest = @"
namespace sample
{
    class TestClass
    {
        public TestClass child;

        public TestClass foo() { return null; }

        public TestClass foo2() { return null; }

        public void Run()
        {
            TestClass b = new TestClass();
            TestClass a;
            a = b.foo();
            a.child = b.foo2();
        }
    }
}
";

            var visualBasicTest = @"
Namespace sample
    Friend Class TestClass
        Public child As TestClass

        Public Function foo() As TestClass
            Return Nothing
        End Function

        Public Function foo2() As TestClass
            Return Nothing
        End Function

        Public Sub Run()
            Dim b As TestClass = New TestClass()
            Dim a As TestClass
            a = b.foo()
            a.child = b.foo2()
        End Sub
    End Class
End Namespace
";

            // should not throw
            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
            var auditConfig = await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, null, auditConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, auditConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
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
            var auditConfig = await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, null, auditConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, auditConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("sql",       new[] { "SCS0026" },           new[] { "SCS0026" },            false)]
        [DataRow("xyz",       new[] { "CS0103" },            new[] { "BC30451" },            false)]
        [DataRow("foo()",     new[] { "CS0029" },            new[] { "BC30311" },            false)]
        [DataRow("foo2(xyz)", new[] { "SCS0026", "CS0103" }, new[] { "SCS0026", "BC30451" }, true)]
        public async Task TransferSqlInitializerUnSafe(string right, string[] csErrors, string[] vbErrors, bool audit)
        {
            var cSharpTest = $@"
using System.Data.SqlClient;

namespace sample
{{
    class MyFoo
    {{
        public void Run(string sql)
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
        Public Sub Run(sql As System.String)
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

            var testConfig = $@"
AuditMode: {audit}

TaintEntryPoints:
  AAA:
    Namespace: sample
    ClassName: MyFoo
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest,
                                         csErrors.Select(x => new DiagnosticResult { Id = x }.WithLocation(10)).ToArray(), optionsWithProjectConfig)
                .ConfigureAwait(false);

            await VerifyVisualBasicDiagnostic(visualBasicTest,
                                              vbErrors.Select(x => new DiagnosticResult { Id = x }.WithLocation(7)).ToArray(), optionsWithProjectConfig)
                .ConfigureAwait(false);
        }

        [TestCategory("Safe")]
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
            var auditConfig = await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, null, auditConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, auditConfig).ConfigureAwait(false);
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
        [TestCategory("Safe")]
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
            method = method.CSharpReplaceToVBasic();
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
            var auditConfig = await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, null, auditConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, auditConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task MemberCallWithoutArguments()
        {
            var cSharpTest = @"
using System.IO;

class PathTraversal
{
    public void Run(string input)
    {
        File.OpenRead(input.ToString());
    }
}
";

            var visualBasicTest = @"
Imports System.IO

Class PathTraversal
    Public Sub Run(input As System.String)
        File.OpenRead(input.ToString())
    End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0018",
                Severity = DiagnosticSeverity.Warning,
            };

            var testConfig = @"
TaintEntryPoints:
  AAA:
    ClassName: PathTraversal
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
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
            var auditConfig = await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, null, auditConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, auditConfig).ConfigureAwait(false);
        }

        [DataTestMethod]
        [DataRow("var query = String.Format(\"SELECT * FROM {0}\", input)", true)]
        [DataRow("var query = String.Format(\"SELECT * FROM {0}\", \"\")", false)]
        [DataRow("var query = String.Format(\"SELECT * FROM {0}{1}\", \"\", input)", true)]
        [DataRow("var query = String.Format(\"SELECT * FROM {0}{1}\", \"\", \"\")", false)]
        [DataRow("var query = String.Format(\"SELECT * FROM {0}{1}{2}\", \"\", \"\", input)", true)]
        [DataRow("var query = String.Format(\"SELECT * FROM {0}{1}{2}\", \"\", \"\", \"\")", false)]
        [DataRow("var query = String.Format(\"SELECT {3} FROM {0}{1}{2}\", \"\", \"\", \"\", input)", true)]
        [DataRow("var query = String.Format(\"SELECT {3} FROM {0}{1}{2}\", \"\", \"\", \"\", \"\")", false)]

        [DataRow("var tableName = input; var query = String.Format(\"SELECT * FROM {0}\", tableName)", true)]
        [DataRow("var tableName = \"\"; var query = String.Format(\"SELECT * FROM {0}\", tableName)", false)]

        [DataRow("var query = $\"SELECT * FROM {input}\"", true)]
        [DataRow("var query = $\"SELECT * FROM {\"\"}\"", false)]
        [DataRow("var query = $\"SELECT * FROM table\"", false)]
        [DataRow("var a = input; var query = $\"SELECT * FROM {a}\"", true)]

        [DataRow("var query = input; query = input + \"\"", true)]
        [DataRow("var query = input; query += \"\"", true)]
        [DataRow("var query = \"\"; query += input", true)]
        [DataRow("var query = input; query = \"\"", false)]
        [DataRow("var query = \"\"; query = input", true)]

        [DataRow("var query = \"\"; var notused = query + input", false)]
        public async Task TransferString(string payload, bool warn)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System;
    using System.Data.SqlClient;
#pragma warning restore 8019

class SqlTransferTesting
{{
    public void Run(string input)
    {{
        {payload};
        new SqlCommand(query);
    }}
}}
";

            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System
    Imports System.Data.SqlClient
#Enable Warning BC50001

Class SqlTransferTesting
    Public Sub Run(input As String)
        {payload.CSharpReplaceToVBasic()}
        Dim com As New SqlCommand(query)
    End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            var testConfig = @"
TaintEntryPoints:
  AAA:
    ClassName: SqlTransferTesting
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            if (warn)
            {
                await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            }
        }

        [DataTestMethod]
        [DataRow("var query = input;input = null;", "Dim query = input\r\ninput = Nothing")]
        [DataRow("string query; query = input; input = null;", "Dim query As String\r\nquery = input\r\ninput = Nothing")]
        [DataRow("string query, q = \"const\"; q = query = input; input = null;",
                 "Dim query As String, q As String = \"const\"\r\nquery = input\r\ninput = Nothing")]
        public async Task TaintVariableReassign(string cs, string vb)
        {
            var cSharpTest = $@"
using System.Data.SqlClient;

class SqlTransferTesting
{{
    public void Run(string input, string input2)
    {{
        {cs}
        new SqlCommand(query);
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Data.SqlClient

Class SqlTransferTesting
    Public Sub Run(ByVal input As String)
        {vb}
        Dim temp = New SqlCommand(query)
    End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            var testConfig = @"
TaintEntryPoints:
  AAA:
    ClassName: SqlTransferTesting
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [DataTestMethod]
        [DataRow("var query = Foo5(ref a, b, null);", true)]

        [DataRow("var query = Foo(a, b);",       true)]
        [DataRow("var query = Foo(a, null);",    true)]
        [DataRow("var query = Foo(null, b);",    true)]
        [DataRow("var query = Foo(null, null);", false)]

        [DataRow("o.Foo(a, b); var query = o.ToString();",       false)]
        [DataRow("o.Foo(a, null); var query = o.ToString();",    false)]
        [DataRow("o.Foo(null, b); var query = o.ToString();",    false)]
        [DataRow("o.Foo(null, null); var query = o.ToString();", false)]

        [DataRow("o.Foo2(a, b); var query = o.ToString();",       true)]
        [DataRow("o.Foo2(a, null); var query = o.ToString();",    true)]
        [DataRow("o.Foo2(null, b); var query = o.ToString();",    true)]
        [DataRow("o.Foo2(null, null); var query = o.ToString();", false)]

        [DataRow("var query = \"\"; o.Foo3(a, out query);",       true)]
        [DataRow("var query = \"\"; o.Foo3(query, out a);",       false)]
        [DataRow("var query = \"\"; o.Foo3(null, out a);",        false)]
        [DataRow("var query = \"\"; o.Foo3(null, out query);",    false)]

        [DataRow("var query = \"\"; o.Foo4(a, ref query);",    true)]
        [DataRow("var query = \"\"; o.Foo4(query, ref a);",    false)]
        [DataRow("var query = \"\"; o.Foo4(null, ref a);",     false)]
        [DataRow("var query = \"\"; o.Foo4(null, ref query);", false)]

        [DataRow("o.Foo2(a, b); var query = \"\"; o.Foo2(a, query);", false)]
        [DataRow("o.Foo2(a, b); var query = \"\"; o.Foo2(query, b);", false)]

        [DataRow("StaticTest.Foo2(a, b); var query = StaticTest.Get();",       false)]
        [DataRow("StaticTest.Foo2(a, null); var query = StaticTest.Get();",    false)]
        [DataRow("StaticTest.Foo2(null, b); var query = StaticTest.Get();",    false)]
        [DataRow("StaticTest.Foo2(null, null); var query = StaticTest.Get();", false)]
        public async Task TaintArgumentsTransfer(string cs, bool warn)
        {
            var cSharpTest = $@"
using System.Data.SqlClient;

class StaticTest
{{
    public static void Foo2(string a, string b)
    {{
    }}

    public static string Get()
    {{
        return null;
    }}
}}

class Test
{{
    public string Foo(string a, string b)
    {{
        return null;
    }}

    public void Foo2(string a, string b) {{ }}

    public string Foo3(string a, out string b)
    {{
        b = null;
        return null;
    }}

    public string Foo4(string a, ref string b)
    {{
        return null;
    }}

    public string Foo5(ref string x, params string[] a)
    {{
        return null;
    }}

    public void Run(string a, string b)
    {{
#pragma warning disable CS0219
        Test o = null;
#pragma warning restore CS0219
        {cs}
        new SqlCommand(query);
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Data.SqlClient

Class StaticTest
    Public Shared Sub Foo2(ByVal a As String, ByVal b As String)
    End Sub

    Public Shared Function [Get]() As String
        Return Nothing
    End Function
End Class

Class Test
    Public Function Foo(ByVal a As String, ByVal b As String) As String
        Return Nothing
    End Function

    Public Sub Foo2(ByVal a As String, ByVal b As String)
    End Sub

    Public Function Foo3(ByVal a As String, <System.Runtime.InteropServices.Out> ByRef b As String) As String
        b = Nothing
        Return Nothing
    End Function

    Public Function Foo4(ByVal a As String, ByRef b As String) As String
        Return Nothing
    End Function

    Public Function Foo5(ByRef x As String, ParamArray a As String()) As String
        Return Nothing
    End Function

    Public Sub Run(ByVal a As String, ByVal b As String)
        Dim o As Test = Nothing
        {cs.CSharpReplaceToVBasic()}
        Dim temp = New SqlCommand(query)
    End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            var testConfig = @"
TaintEntryPoints:
  AAA:
    ClassName: Test
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            if (warn)
            {
                await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            }
        }

        [DataTestMethod]
        [DataRow("var query = Foo(a, \"\");", "Test", "Foo", "Returns", "TaintFromArguments: [0]", true)]
        public async Task MergePostConditions(string cs, string className, string name, string outParam, string taintFromArguments, bool warn)
        {
            var cSharpTest = $@"
using System.Data.SqlClient;

class Test
{{
    public string Foo(string a, string b)
    {{
        return null;
    }}

    public void Run(string a, string b)
    {{
#pragma warning disable CS0219
        Test o = null;
#pragma warning restore CS0219
        {cs}
        new SqlCommand(query);
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Data.SqlClient

Class Test
    Public Function Foo(ByVal a As String, ByVal b As String) As String
        Return Nothing
    End Function

    Public Sub Run(ByVal a As String, ByVal b As String)
        Dim o As Test = Nothing
        {cs.CSharpReplaceToVBasic()}
        Dim temp = New SqlCommand(query)
    End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            var testConfig = $@"
TaintEntryPoints:
  AAA:
    ClassName: Test

Behavior:
  BBB:
    ClassName: {className}
    Name: {name}
    Method:
      If:
        Condition: {{1: {{Value: """"}}}}
        Then:
          {outParam}:
            Taint: LocalUrl
      {outParam}:
        {taintFromArguments}
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            if (warn)
            {
                await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            }
        }

        [DataTestMethod]
        [DataRow("var query = Foo(a, b);", "Test", "Foo", "Returns", "TaintFromArguments: [0]", true)]
        [DataRow("var query = Foo(a, null);", "Test", "Foo", "Returns", "TaintFromArguments: [0]", true)]
        [DataRow("var query = Foo(null, b);", "Test", "Foo", "Returns", "TaintFromArguments: [0]", false)]
        [DataRow("var query = Foo(null, null);", "Test", "Foo", "Returns", "TaintFromArguments: [0]", false)]

        [DataRow("var query = Foo(a, b);", "Test", "Foo", "1", "TaintFromArguments: [0]", true)]
        [DataRow("var query = Foo(a, null);", "Test", "Foo", "1", "TaintFromArguments: [0]", true)]
        [DataRow("var query = Foo(null, b);", "Test", "Foo", "1", "TaintFromArguments: [0]", true)]
        [DataRow("var query = Foo(null, null);", "Test", "Foo", "1", "TaintFromArguments: [0]", false)]

        [DataRow("var query = Foo(a, b);", "Test", "Foo", "0", "TaintFromArguments: [1]", true)]
        [DataRow("var query = Foo(a, null);", "Test", "Foo", "0", "TaintFromArguments: [1]", true)]
        [DataRow("var query = Foo(null, b);", "Test", "Foo", "0", "TaintFromArguments: [1]", true)]
        [DataRow("var query = Foo(null, null);", "Test", "Foo", "0", "TaintFromArguments: [1]", false)]

        [DataRow("o.Foo(a, b); var query = o.ToString();", "Test", "Foo", "Returns", "TaintFromArguments: [0]", false)]
        [DataRow("o.Foo(a, null); var query = o.ToString();", "Test", "Foo", "Returns", "TaintFromArguments: [0]", false)]
        [DataRow("o.Foo(null, b); var query = o.ToString();", "Test", "Foo", "Returns", "TaintFromArguments: [0]", false)]
        [DataRow("o.Foo(null, null); var query = o.ToString();", "Test", "Foo", "Returns", "TaintFromArguments: [0]", false)]

        [DataRow("o.Foo2(a, b); var query = o.ToString();", "Test", "Foo2", "Returns", "TaintFromArguments: [0]", true)]
        [DataRow("o.Foo2(a, null); var query = o.ToString();", "Test", "Foo2", "Returns", "TaintFromArguments: [0]", true)]
        [DataRow("o.Foo2(null, b); var query = o.ToString();", "Test", "Foo2", "Returns", "TaintFromArguments: [0]", false)]
        [DataRow("o.Foo2(null, null); var query = o.ToString();", "Test", "Foo2", "Returns", "TaintFromArguments: [0]", false)]

        [DataRow("var query = \"\"; o.Foo3(a, out query);", "Test", "Foo3", "Returns", "TaintFromArguments: [0]", true)]
        [DataRow("var query = \"\"; o.Foo3(query, out a);", "Test", "Foo3", "Returns", "TaintFromArguments: [0]", false)]
        [DataRow("var query = \"\"; o.Foo3(null, out a);", "Test", "Foo3", "Returns", "TaintFromArguments: [0]", false)]
        [DataRow("var query = \"\"; o.Foo3(null, out query);", "Test", "Foo3", "Returns", "TaintFromArguments: [0]", false)]

        [DataRow("var query = \"\"; o.Foo3(a, out query);", "Test", "Foo3", "1", "TaintFromArguments: [0]", true)]
        [DataRow("var query = \"\"; o.Foo3(query, out a);", "Test", "Foo3", "1", "TaintFromArguments: [0]", false)]
        [DataRow("var query = \"\"; o.Foo3(null, out a);", "Test", "Foo3", "1", "TaintFromArguments: [0]", false)]
        [DataRow("var query = \"\"; o.Foo3(null, out query);", "Test", "Foo3", "1", "TaintFromArguments: [0]", false)]

        [DataRow("var query = \"\"; o.Foo3(a, out query);", "Test", "Foo3", "0", "TaintFromArguments: [1]", true)]
        [DataRow("var query = \"\"; o.Foo3(query, out a);", "Test", "Foo3", "0", "TaintFromArguments: [1]", true)]
        [DataRow("var query = \"\"; o.Foo3(null, out a);", "Test", "Foo3", "0", "TaintFromArguments: [1]", false)]
        [DataRow("var query = \"\"; o.Foo3(null, out query);", "Test", "Foo3", "0", "TaintFromArguments: [1]", false)]

        [DataRow("var query = \"\"; o.Foo4(a, ref query);", "Test", "Foo4", "Returns", "TaintFromArguments: [0]", true)]
        [DataRow("var query = \"\"; o.Foo4(query, ref a);", "Test", "Foo4", "Returns", "TaintFromArguments: [0]", false)]
        [DataRow("var query = \"\"; o.Foo4(null, ref a);", "Test", "Foo4", "Returns", "TaintFromArguments: [0]", false)]
        [DataRow("var query = \"\"; o.Foo4(null, ref query);", "Test", "Foo4", "Returns", "TaintFromArguments: [0]", false)]

        [DataRow("var query = \"\"; o.Foo4(a, ref query);", "Test", "Foo4", "1", "Taint: Safe", false)]
        [DataRow("var query = \"\"; o.Foo4(a, ref query);", "Test", "Foo4", "1", "Taint: Tainted", true)]
        [DataRow("var query = \"\"; o.Foo4(null, ref query);", "Test", "Foo4", "1", "Taint: Tainted", true)]

        [DataRow("var query = \"\"; o.Foo4(a, ref query);", "Test", "Foo4", "1", "TaintFromArguments: [0]", true)]
        [DataRow("var query = \"\"; o.Foo4(query, ref a);", "Test", "Foo4", "1", "TaintFromArguments: [0]", false)]
        [DataRow("var query = \"\"; o.Foo4(null, ref a);", "Test", "Foo4", "1", "TaintFromArguments: [0]", false)]
        [DataRow("var query = \"\"; o.Foo4(null, ref query);", "Test", "Foo4", "1", "TaintFromArguments: [0]", false)]

        [DataRow("var query = \"\"; o.Foo4(a, ref query);", "Test", "Foo4", "0", "TaintFromArguments: [1]", true)]
        [DataRow("var query = \"\"; o.Foo4(query, ref a);", "Test", "Foo4", "0", "TaintFromArguments: [1]", true)]
        [DataRow("var query = \"\"; o.Foo4(null, ref a);", "Test", "Foo4", "0", "TaintFromArguments: [1]", false)]
        [DataRow("var query = \"\"; o.Foo4(null, ref query);", "Test", "Foo4", "0", "TaintFromArguments: [1]", false)]

        [DataRow("o.Foo2(a, b); var query = \"\"; o.Foo2(a, query);", "Test", "Foo2", "Returns", "TaintFromArguments: [0]", false)]
        [DataRow("o.Foo2(a, b); var query = \"\"; o.Foo2(query, b);", "Test", "Foo2", "Returns", "TaintFromArguments: [0]", false)]
        [DataRow("o.Foo2(a, b); var query = \"\"; o.Foo2(a, query);", "Test", "Foo2", "1", "TaintFromArguments: [0]", true)]
        [DataRow("o.Foo2(a, b); var query = \"\"; o.Foo2(query, b);", "Test", "Foo2", "1", "TaintFromArguments: [0]", false)]
        [DataRow("o.Foo2(a, b); var query = \"\"; o.Foo2(a, query);", "Test", "Foo2", "0", "TaintFromArguments: [1]", false)]
        [DataRow("o.Foo2(a, b); var query = \"\"; o.Foo2(query, b);", "Test", "Foo2", "0", "TaintFromArguments: [1]", true)]

        [DataRow("StaticTest.Foo2(a, b); var query = StaticTest.Get();", "StaticTest", "Get", "Returns", "TaintFromArguments: [0]", false)]
        [DataRow("StaticTest.Foo2(a, null); var query = StaticTest.Get();", "StaticTest", "Get", "Returns", "TaintFromArguments: [0]", false)]
        [DataRow("StaticTest.Foo2(null, b); var query = StaticTest.Get();", "StaticTest", "Get", "Returns", "TaintFromArguments: [0]", false)]
        [DataRow("StaticTest.Foo2(null, null); var query = StaticTest.Get();", "StaticTest", "Get", "Returns", "TaintFromArguments: [0]", false)]
        public async Task TaintFromArguments(string cs, string className, string name, string outParam, string taintFromArguments, bool warn)
        {
            var cSharpTest = $@"
using System.Data.SqlClient;

class StaticTest
{{
    public static void Foo2(string a, string b)
    {{
    }}

    public static string Get()
    {{
        return null;
    }}
}}

class Test
{{
    public string Foo(string a, string b)
    {{
        return null;
    }}

    public void Foo2(string a, string b) {{ }}

    public string Foo3(string a, out string b)
    {{
        b = null;
        return null;
    }}

    public string Foo4(string a, ref string b)
    {{
        return null;
    }}

    public void Run(string a, string b)
    {{
#pragma warning disable CS0219
        Test o = null;
#pragma warning restore CS0219
        {cs}
        new SqlCommand(query);
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Data.SqlClient

Class StaticTest
    Public Shared Sub Foo2(ByVal a As String, ByVal b As String)
    End Sub

    Public Shared Function [Get]() As String
        Return Nothing
    End Function
End Class

Class Test
    Public Function Foo(ByVal a As String, ByVal b As String) As String
        Return Nothing
    End Function

    Public Sub Foo2(ByVal a As String, ByVal b As String)
    End Sub

    Public Function Foo3(ByVal a As String, <System.Runtime.InteropServices.Out> ByRef b As String) As String
        b = Nothing
        Return Nothing
    End Function

    Public Function Foo4(ByVal a As String, ByRef b As String) As String
        Return Nothing
    End Function

    Public Sub Run(ByVal a As String, ByVal b As String)
        Dim o As Test = Nothing
        {cs.CSharpReplaceToVBasic()}
        Dim temp = New SqlCommand(query)
    End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            var testConfig = $@"
TaintEntryPoints:
  AAA:
    ClassName: Test

Behavior:
  BBB:
    ClassName: {className}
    Name: {name}
    Method:
      {outParam}:
        {taintFromArguments}
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            if (warn)
            {
                await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            }
        }

        [TestMethod]
        public async Task TransferMemoryStream()
        {
            var cSharpTest = @"
#pragma warning disable 8019
    using System;
    using System.IO;
    using System.Text;
    using System.Data.SqlClient;
#pragma warning restore 8019

class SqlTransferTesting
{
    public void Run(string input)
    {
        var query = """";
        var bytes = Encoding.ASCII.GetBytes(input);
        using(var stream = new MemoryStream())
        {
            stream.Write(bytes, 0, bytes.Length);
            StreamReader reader = new StreamReader( stream );
            query = reader.ReadToEnd();
        }
        new SqlCommand(query);
    }
}
";

            var visualBasicTest = @"
#Disable Warning BC50001
    Imports System
    Imports System.IO
    Imports System.Text
    Imports System.Data.SqlClient
#Enable Warning BC50001

Friend Class SqlTransferTesting
    Public Sub Run(ByVal input As String)
        Dim query = """"
        Dim bytes = Encoding.ASCII.GetBytes(input)

        Using stream = New MemoryStream()
            stream.Write(bytes, 0, bytes.Length)
            Dim reader As StreamReader = New StreamReader(stream)
            query = reader.ReadToEnd()
        End Using

        Dim a = New SqlCommand(query)
    End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            var testConfig = @"
TaintEntryPoints:
  AAA:
    ClassName: SqlTransferTesting
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [DataTestMethod]
        [DataRow("String[]", "")]
        [DataRow("String[]", ", 0, 2")]
        [DataRow("Object[]", "")]
        public async Task TransferStringJoinSafe(string dataType, string additionalArguments)
        {
            var cSharpTest = $@"
using System;
using System.Data.SqlClient;
#pragma warning disable 8019
    using System.Collections.Generic;
#pragma warning restore 8019

namespace sample
{{
    class SqlConstant
    {{
        public static void Run()
        {{
            {dataType} array = new []{{""aaa"", ""bbb""}};
            new SqlCommand(String.Join("" "", array {additionalArguments}));
        }}
    }}
}}
";

            dataType = dataType.CSharpReplaceToVBasic();

            var visualBasicTest = $@"
Imports System.Data.SqlClient
#Disable Warning BC50001
    Imports System.Collections.Generic
#Enable Warning BC50001

Namespace sample
    Class SqlConstant
        Public Shared Sub Run()
            Dim array As {dataType} = {{""aaa"", ""bbb""}}
            Dim com As New SqlCommand(String.Join("" "", array {additionalArguments}))
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
            var auditConfig = await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, null, auditConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, auditConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [DataTestMethod]
        [DataRow("string", false)]
        [DataRow("object", true)]
        public async Task TransferStringJoinSafe2(string dataType, bool isMethodGeneric)
        {
            var cSharpTest = $@"
using System;
using System.Data.SqlClient;
#pragma warning disable 8019
    using System.Collections.Generic;
#pragma warning restore 8019

namespace sample
{{
    class SqlConstant
    {{
        public static void Run()
        {{
            IEnumerable<{dataType}> array = new []{{""aaa"", ""bbb""}};
            new SqlCommand(String.Join{(isMethodGeneric ? $"<{dataType}>" : "")}("" "", array));
        }}
    }}
}}
";

            dataType = dataType.CSharpReplaceToVBasic();

            var visualBasicTest = $@"
Imports System.Data.SqlClient
#Disable Warning BC50001
    Imports System.Collections.Generic
#Enable Warning BC50001

Namespace sample
    Class SqlConstant
        Public Shared Sub Run()
            Dim array As IEnumerable(Of {dataType}) = {{""aaa"", ""bbb""}}
            Dim com As New SqlCommand(String.Join{(isMethodGeneric ? $"(Of {dataType})" : "")}("" "", array))
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
            var auditConfig = await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, null, auditConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, auditConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("String[]", "")]
        [DataRow("String[]", ", 0, 2")]
        [DataRow("Object[]", "")]
        public async Task TransferStringJoinUnsafe(string dataType, string additionalArguments)
        {
            var cSharpTest = $@"
using System;
using System.Data.SqlClient;
#pragma warning disable 8019
    using System.Collections.Generic;
#pragma warning restore 8019

namespace sample
{{
    class SqlConstant
    {{
        public void Run(string input)
        {{
            {dataType} array = new []{{""aaa"", input, ""bbb""}};
            new SqlCommand(String.Join("" "", array {additionalArguments}));
        }}
    }}
}}
";

            dataType = dataType.CSharpReplaceToVBasic();

            var visualBasicTest = $@"
Imports System.Data.SqlClient
#Disable Warning BC50001
    Imports System.Collections.Generic
#Enable Warning BC50001

Namespace sample
    Class SqlConstant
        Public Sub Run(input As String)
            Dim array As {dataType} = {{""aaa"", input, ""bbb""}}
            Dim com As New SqlCommand(String.Join("" "", array {additionalArguments}))
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            var testConfig = @"
TaintEntryPoints:
  AAA:
    Namespace: sample
    ClassName: SqlConstant
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("string", false)]
        [DataRow("object", true)]
        public async Task TransferStringJoinUnsafe2(string dataType, bool isMethodGeneric)
        {
            var cSharpTest = $@"
using System;
using System.Data.SqlClient;
#pragma warning disable 8019
    using System.Collections.Generic;
#pragma warning restore 8019

namespace sample
{{
    class SqlConstant
    {{
        public void Run(string input)
        {{
            IEnumerable<{dataType}> array = new []{{""aaa"", input, ""bbb""}};
            new SqlCommand(String.Join{(isMethodGeneric ? $"<{dataType}>" : "")}("" "", array));
        }}
    }}
}}
";

            dataType = dataType.CSharpReplaceToVBasic();

            var visualBasicTest = $@"
Imports System.Data.SqlClient
#Disable Warning BC50001
    Imports System.Collections.Generic
#Enable Warning BC50001

Namespace sample
    Class SqlConstant
        Public Sub Run(input As String)
            Dim array As IEnumerable(Of {dataType}) = {{""aaa"", input, ""bbb""}}
            Dim com As New SqlCommand(String.Join{(isMethodGeneric ? $"(Of {dataType})" : "")}("" "", array))
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            var testConfig = @"
TaintEntryPoints:
  AAA:
    Namespace: sample
    ClassName: SqlConstant
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
        }
    }
}
