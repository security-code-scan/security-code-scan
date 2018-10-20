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
    public class TaintAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            return new List<DiagnosticAnalyzer> { new TaintAnalyzerCSharp(), new TaintAnalyzerVisualBasic(), };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(System.Data.SqlClient.SqlCommand).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestMethod]
        public async Task MethodMemberAccessWithVb()
        {
            var visualBasicTest = @"
Namespace sample
    Friend Class Foo
        Public Shared Sub Run()
            Dim a = """"
            With a
                Dim e = .Equals(""a"")
            End With
        End Sub
    End Class
End Namespace
";

            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task Return()
        {
            var cSharpTest = @"
namespace sample
{
    class Foo
    {
        public static void Run()
        {
            return;
        }
    }
}
";

            var visualBasicTest = @"
Namespace sample
    Friend Class Foo
        Public Shared Sub Run()
            Return
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task VariableLocalForEach()
        {
            var cSharpTest = @"
namespace sample
{
    class Foo
    {
        public static void Run()
        {
            foreach (string str in System.IO.Directory.GetFiles("""", """"))
            {
                var s = str;
            }
        }

        public static void Run2()
        {
            foreach (string str in System.IO.Directory.GetFiles("""", """"))
                Run2();
        }
    }
}
";

            var visualBasicTest = @"
Namespace sample
    Friend Class Foo
        Public Shared Sub Run()
            For Each str As String In System.IO.Directory.GetFiles("""", """")
                Dim s As String = str
            Next
        End Sub
        Public Shared Sub Run2()
            For Each str As String In System.IO.Directory.GetFiles("""", """")
                Run2()
            Next
        End Sub
        Sub Run3(args As String())
            Dim str As String

            For Each str In args
                Dim s As String = str
            Next
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task VariablePropertyNoBody()
        {
            var cSharpTest = @"
namespace sample
{
    class Foo
    {
        public static void Run()
        {
            string[] strArray = null;
            int length = strArray.Length;
        }

        private int Length { get; set; }

        public void Run2()
        {
            int length = Length;
        }
    }
}
";

            var visualBasicTest = @"
Namespace sample
    Friend Class Foo
        Public Shared Sub Run()
            Dim array As String() = Nothing
            Dim num As Integer = array.Length
        End Sub
        Private Property Length As Integer
        Public Sub Run2()
            Dim num As Integer = Length
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
        [DataRow("foo()",     new[] { "CS1503" },            new[] { "BC30311" })]
        [DataRow("foo2(xyz)", new[] { "SCS0026", "CS0103" }, new[] { "BC30451" })]
        public async Task Constructor(string right, string[] csErrors, string[] vbErrors)
        {
            var cSharpTest = $@"
using System.Data.SqlClient;

namespace sample
{{
    class Test
    {{
        public Test(string sql)
        {{
            new SqlCommand({right});
        }}

        static Test foo()
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
    Class Test
        Public Sub New(sql As String)
            Dim com As New SqlCommand({right})
        End Sub

        Private Shared Function foo() As Test
            Return Nothing
        End Function

        Private Shared Function foo2(ByVal a As String) As String
            Return """"
        End Function
    End Class
End Namespace
";
            await VerifyCSharpDiagnostic(cSharpTest,
                                         csErrors.Select(x => new DiagnosticResult { Id = x }.WithLocation(10)).ToArray())
                .ConfigureAwait(false);

            await VerifyVisualBasicDiagnostic(visualBasicTest,
                                              vbErrors.Select(x => new DiagnosticResult { Id = x }.WithLocation(7)).ToArray())
                .ConfigureAwait(false);
        }

        [TestMethod]
        public async Task Property()
        {
            var cSharpTest = @"
using System.Data.SqlClient;

namespace sample
{
    class Test
    {
        private string sql;

        public Test(string s)
        {
            sql = s;
        }

        public SqlCommand Command
        {
            get
            {
                return new SqlCommand(sql);
            }
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Data.SqlClient

Namespace sample
    Class Test
        Private sql As String
        Public Sub New(s As String)
            sql = s
        End Sub
        Public ReadOnly Property Command() As SqlCommand
            Get
                Return New SqlCommand(sql)
            End Get
        End Property
    End Class
End Namespace
";
            var expected        = new DiagnosticResult
            {
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task Destructor()
        {
            var cSharpTest = @"
using System.Data.SqlClient;

namespace sample
{
    class Test
    {
        private string sql;

        public Test(string s)
        {
            sql = s;
        }

        ~Test()
        {
            new SqlCommand(sql);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Data.SqlClient

Namespace sample
    Class Test
        Private sql As String
        Public Sub New(s As String)
            sql = s
        End Sub
        Protected Overrides Sub Finalize()
            Dim com As New SqlCommand(sql)
        End Sub

    End Class
End Namespace
";
            var expected        = new DiagnosticResult
            {
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
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

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task VariableConcatenationLocal()
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

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [DataRow("\"\"",                      "stringConst")]
        [DataRow("\"\"",                      "MyFoo.stringConst")]
        [DataRow("\"\"",                      "sample.MyFoo.stringConst")]
        [DataRow("String.Empty",              "stringConst")]
        [DataRow("String.Empty",              "MyFoo.stringConst")]
        [DataRow("String.Empty",              "sample.MyFoo.stringConst")]
        [DataRow("new string('x', 3)",        "stringConst")]
        [DataRow("new String('x', 3)",        "stringConst")]
        [DataRow("new System.String('x', 3)", "stringConst")]
        [DataTestMethod]
        public async Task VariableConcatenationMethod(string initializer, string accessor)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System;
#pragma warning restore 8019
using System.Data.SqlClient;

namespace sample
{{
    class MyFoo
    {{
        public static string stringConst()
        {{
            return {initializer};
        }}
        public static void Run()
        {{
            var s          = ""select * from Products"";
            var sqlCommand = new SqlCommand(s + {accessor}());
        }}
    }}
}}
";

            var visualBasicTest = @"
#Disable Warning BC50001
    Imports System
#Enable Warning BC50001
Imports System.Data.SqlClient

Namespace sample
    Class MyFoo
        Public Shared Function stringConst()
            return """"
        End Function
        Public Shared Sub Run()
            Dim s As String = ""select * from Products""

            Dim com As New SqlCommand(s + stringConst())
        End Sub
    End Class
End Namespace
";
            // todo: methods are not expanded yet
            var expected = new DiagnosticResult
            {
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task VariableConcatenationFieldReadonlyBackReference()
        {
            var cSharpTest = @"
namespace sample
{
    class MyFoo
    {
        private static readonly string stringConst = Foo(); // See if it doesn't go into the loop

        private static string Foo()
        {
            return stringConst;
        }
    }
}
";

            var visualBasicTest = @"
Namespace sample
    Class MyFoo
        Private Shared ReadOnly stringConst As String = Foo()
        Private Shared Function Foo() As String
            return stringConst
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task VariableConcatenationPropertyReadonlyBackReference()
        {
            var cSharpTest = @"
namespace sample
{
    class MyFoo
    {
        private static string stringConst2 { get { return stringConst; } }
        private static string stringConst { get { return stringConst2; } } // See if it doesn't go into the loop

        private static string Foo()
        {
            return stringConst;
        }
    }
}
";

            var visualBasicTest = @"
Namespace sample
    Class MyFoo
        Public Shared ReadOnly Property stringConst2() As String
            Get
                Return stringConst
            End Get
        End Property
        Public Shared ReadOnly Property stringConst() As String
            Get
                Return stringConst2
            End Get
        End Property
        Private Shared Function Foo() As String
            return stringConst
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [DataRow("\"\"", "stringConst")]
        [DataRow("\"\"", "MyFoo.stringConst")]
        [DataRow("\"\"", "sample.MyFoo.stringConst")]
        [DataTestMethod]
        public async Task VariableConcatenationFieldConst(string initializer, string accessor)
        {
            var cSharpTest = $@"
using System.Data.SqlClient;

namespace sample
{{
    class MyFoo
    {{
        private const string stringConst = {initializer};

        void Foo()
        {{
            var s          = ""select * from Products"";
            var sqlCommand = new SqlCommand(s + {accessor});
        }}
    }}
}}
";

            initializer = initializer.Replace("new ", "New ").Replace("'", "\"");
            var visualBasicTest = $@"
Imports System.Data.SqlClient

Namespace sample
    Class MyFoo
        Private Const stringConst As String = {initializer}
        Private Sub Foo()
            Dim s As String = ""select * from Products""

            Dim com As New SqlCommand(s + {accessor})
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [DataRow("\"\"",                      "stringConst")]
        [DataRow("\"\"",                      "MyFoo.stringConst")]
        [DataRow("\"\"",                      "sample.MyFoo.stringConst")]
        // [DataRow("new System.String[1] { \"xxx\" }.Length.ToString()", "stringConst")] // todo
        [DataRow("String.Empty",              "stringConst")]
        [DataRow("String.Empty",              "MyFoo.stringConst")]
        [DataRow("String.Empty",              "sample.MyFoo.stringConst")]
        [DataRow("new string('x', 3)",        "stringConst")]
        [DataRow("new String('x', 3)",        "stringConst")]
        [DataRow("new System.String('x', 3)", "stringConst")]
        [DataTestMethod]
        public async Task VariableConcatenationFieldReadonly(string initializer, string accessor)
        {
            var cSharpTest = $@"
using System.Data.SqlClient;
#pragma warning disable 8019
    using System;
#pragma warning restore 8019

namespace sample
{{
    class MyFoo
    {{
        private static readonly string stringConst = {initializer};

        void Foo()
        {{
            var s          = ""select * from Products"";
            var sqlCommand = new SqlCommand(s + {accessor});
        }}
    }}
}}
";

            initializer = initializer.Replace("new ", "New ").Replace("'", "\"");
            var visualBasicTest = $@"
Imports System.Data.SqlClient
#Disable Warning BC50001
    Imports System
#Enable Warning BC50001

Namespace sample
    Class MyFoo
        Private Shared ReadOnly stringConst As String = {initializer}
        Private Sub Foo()
            Dim s As String = ""select * from Products""

            Dim com As New SqlCommand(s + {accessor})
        End Sub
    End Class
End Namespace
";

            // todo: readonly fields aren't assumed const because no check for assignments in constructors is implemented
            var expected = new DiagnosticResult
            {
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [DataRow("\"\"",                      "stringConst")]
        [DataRow("\"\"",                      "this.stringConst")]
        [DataRow("String.Empty",              "stringConst")]
        [DataRow("String.Empty",              "this.stringConst")]
        [DataRow("new string('x', 3)",        "stringConst")]
        [DataRow("new String('x', 3)",        "stringConst")]
        [DataRow("new System.String('x', 3)", "stringConst")]
        [DataTestMethod]
        public async Task VariableConcatenationFieldReadonlyContructor(string initializer, string accessor)
        {
            var cSharpTest = $@"
using System.Data.SqlClient;
#pragma warning disable 8019
    using System;
#pragma warning restore 8019

namespace sample
{{
    class MyFoo
    {{
        readonly string stringConst = {initializer};

        public MyFoo(string x)
        {{
            stringConst = ""2"";
        }}

        void Foo()
        {{
            var s          = ""select * from Products"";
            var sqlCommand = new SqlCommand(s + {accessor});
        }}
    }}
}}
";

            initializer = initializer.Replace("new ", "New ").Replace("'", "\"");
            accessor    = accessor.Replace("this.", "Me.");
            var visualBasicTest = $@"
Imports System.Data.SqlClient
#Disable Warning BC50001
    Imports System
#Enable Warning BC50001

Namespace sample
    Class MyFoo
        Private ReadOnly stringConst As String = {initializer}
        Public Sub New(ByVal x as String)
            stringConst = x
        End Sub
        Private Sub Foo()
            Dim s As String = ""select * from Products""

            Dim com As New SqlCommand(s + {accessor})
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [DataRow("\"\"",                      "stringConst")]
        [DataRow("\"\"",                      "MyFoo.stringConst")]
        [DataRow("\"\"",                      "sample.MyFoo.stringConst")]
        [DataRow("String.Empty",              "stringConst")]
        [DataRow("String.Empty",              "MyFoo.stringConst")]
        [DataRow("String.Empty",              "sample.MyFoo.stringConst")]
        [DataRow("new string('x', 3)",        "stringConst")]
        [DataRow("new String('x', 3)",        "stringConst")]
        [DataRow("new System.String('x', 3)", "stringConst")]
        [DataTestMethod]
        public async Task VariableConcatenationProperty(string initializer, string accessor)
        {
            var cSharpTest = $@"
using System.Data.SqlClient;
#pragma warning disable 8019
    using System;
#pragma warning restore 8019

namespace sample
{{
    class MyFoo
    {{
        public static string stringConst
        {{
            get {{ return {initializer}; }}
        }}

        void Foo()
        {{
            var s          = ""select * from Products"";
            var sqlCommand = new SqlCommand(s + {accessor});
        }}
    }}
}}
";

            initializer         = initializer.Replace("new ", "New ").Replace("'", "\"");
            var visualBasicTest = $@"
Imports System.Data.SqlClient
#Disable Warning BC50001
    Imports System
#Enable Warning BC50001

Namespace sample
    Class MyFoo
        Public Shared ReadOnly Property stringConst() As String
            Get
                Return {initializer}
            End Get
        End Property
        Private Sub Foo()
            Dim s As String = ""select * from Products""

            Dim com As New SqlCommand(s + {accessor})
        End Sub
    End Class
End Namespace
";
            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [DataRow("\"\"", "stringConst")]
        [DataRow("\"\"", "MyFoo.stringConst")]
        [DataRow("\"\"", "sample.MyFoo.stringConst")]
        [DataTestMethod]
        public async Task VariableConcatenationPropertyConstBackingField(string initializer, string accessor)
        {
            var cSharpTest = $@"
using System.Data.SqlClient;
#pragma warning disable 8019
    using System;
#pragma warning restore 8019

namespace sample
{{
    class MyFoo
    {{
        private const string StringConst = {initializer};
        public static string stringConst
        {{
            get {{ return StringConst; }}
        }}

        void Foo()
        {{
            var s          = ""select * from Products"";
            var sqlCommand = new SqlCommand(s + {accessor});
        }}
    }}
}}
";

            initializer         = initializer.Replace("new ", "New ").Replace("'", "\"");
            var visualBasicTest = $@"
Imports System.Data.SqlClient
#Disable Warning BC50001
    Imports System
#Enable Warning BC50001

Namespace sample
    Class MyFoo
        Private Const StringConstField As String = {initializer}
        Public Shared ReadOnly Property stringConst() As String
            Get
                Return MyFoo.StringConstField
            End Get
        End Property
        Private Sub Foo()
            Dim s As String = ""select * from Products""

            Dim com As New SqlCommand(s + {accessor})
        End Sub
    End Class
End Namespace
";
            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [DataRow("\"\"",                      "stringConst")]
        [DataRow("\"\"",                      "MyFoo.stringConst")]
        [DataRow("\"\"",                      "sample.MyFoo.stringConst")]
        [DataRow("String.Empty",              "stringConst")]
        [DataRow("String.Empty",              "MyFoo.stringConst")]
        [DataRow("String.Empty",              "sample.MyFoo.stringConst")]
        [DataRow("new string('x', 3)",        "stringConst")]
        [DataRow("new String('x', 3)",        "stringConst")]
        [DataRow("new System.String('x', 3)", "stringConst")]
        [DataTestMethod]
        public async Task VariableConcatenationPropertyReadonlyBackingField(string initializer, string accessor)
        {
            var cSharpTest = $@"
using System.Data.SqlClient;
#pragma warning disable 8019
    using System;
#pragma warning restore 8019

namespace sample
{{
    class MyFoo
    {{
        private static readonly string StringConst = {initializer};
        public static string stringConst
        {{
            get {{ return StringConst; }}
        }}

        void Foo()
        {{
            var s          = ""select * from Products"";
            var sqlCommand = new SqlCommand(s + {accessor});
        }}
    }}
}}
";

            initializer         = initializer.Replace("new ", "New ").Replace("'", "\"");
            var visualBasicTest = $@"
Imports System.Data.SqlClient
#Disable Warning BC50001
    Imports System
#Enable Warning BC50001

Namespace sample
    Class MyFoo
        Private Shared ReadOnly StringConstField As String = {initializer}
        Public Shared ReadOnly Property stringConst() As String
            Get
                Return MyFoo.StringConstField
            End Get
        End Property
        Private Sub Foo()
            Dim s As String = ""select * from Products""

            Dim com As New SqlCommand(s + {accessor})
        End Sub
    End Class
End Namespace
";
            // todo: readonly fields aren't assumed const because no check for assignments in constructors is implemented
            var expected = new DiagnosticResult
            {
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [DataRow("\"\"",                      "stringConst")]
        [DataRow("\"\"",                      "this.stringConst")]
        [DataRow("String.Empty",              "stringConst")]
        [DataRow("String.Empty",              "this.stringConst")]
        [DataRow("new string('x', 3)",        "stringConst")]
        [DataRow("new String('x', 3)",        "stringConst")]
        [DataRow("new System.String('x', 3)", "stringConst")]
        [DataTestMethod]
        public async Task VariableConcatenationPropertyReadonlyContructorBackingField(string initializer, string accessor)
        {
            var cSharpTest = $@"
using System.Data.SqlClient;
#pragma warning disable 8019
    using System;
#pragma warning restore 8019

namespace sample
{{
    class MyFoo
    {{
        private readonly string StringConst = {initializer};
        public string stringConst
        {{
            get {{ return StringConst; }}
        }}

        public MyFoo(string x)
        {{
            StringConst = x;
        }}

        void Foo()
        {{
            var s          = ""select * from Products"";
            var sqlCommand = new SqlCommand(s + {accessor});
        }}
    }}
}}
";

            initializer = initializer.Replace("new ", "New ").Replace("'", "\"");
            accessor    = accessor.Replace("this.", "Me.");
            var visualBasicTest = $@"
Imports System.Data.SqlClient
#Disable Warning BC50001
    Imports System
#Enable Warning BC50001

Namespace sample
    Class MyFoo
        Private ReadOnly StringConstField As String = {initializer}
        Public ReadOnly Property stringConst() As String
            Get
                Return StringConstField
            End Get
        End Property
        Public Sub New(ByVal x as String)
            StringConstField = x
        End Sub
        Private Sub Foo()
            Dim s As String = ""select * from Products""

            Dim com As New SqlCommand(s + {accessor})
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [DataRow("\"\"",                      "stringConst")]
        [DataRow("\"\"",                      "MyFoo.stringConst")]
        [DataRow("\"\"",                      "sample.MyFoo.stringConst")]
        [DataRow("String.Empty",              "stringConst")]
        [DataRow("String.Empty",              "MyFoo.stringConst")]
        [DataRow("String.Empty",              "sample.MyFoo.stringConst")]
        [DataRow("new string('x', 3)",        "stringConst")]
        [DataRow("new String('x', 3)",        "stringConst")]
        [DataRow("new System.String('x', 3)", "stringConst")]
        [DataTestMethod]
        public async Task VariableConcatenationPropertyGetWithInitializer(string initializer, string accessor)
        {
            var cSharpTest = $@"
using System.Data.SqlClient;
#pragma warning disable 8019
    using System;
#pragma warning restore 8019

namespace sample
{{
    class MyFoo
    {{
        public static string stringConst {{ get; }} = {initializer};

        void Foo()
        {{
            var s          = ""select * from Products"";
            var sqlCommand = new SqlCommand(s + {accessor});
        }}
    }}
}}
";

            initializer = initializer.Replace("new ", "New ").Replace("'", "\"");
            var visualBasicTest = $@"
Imports System.Data.SqlClient
#Disable Warning BC50001
    Imports System
#Enable Warning BC50001

Namespace sample
    Friend Class MyFoo
        Public Shared Property stringConst As String = {initializer}
        Public Sub Foo()
            Dim s As String = ""select * from Products""
            Dim sqlCommand As New SqlCommand(s + {accessor})
        End Sub
    End Class
End Namespace
";

            // todo: readonly fields aren't assumed const because no check for assignments in constructors is implemented
            var expected = new DiagnosticResult
            {
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [DataRow("\"\"",                      "stringConst")]
        [DataRow("\"\"",                      "MyFoo.stringConst")]
        [DataRow("\"\"",                      "sample.MyFoo.stringConst")]
        [DataRow("String.Empty",              "stringConst")]
        [DataRow("String.Empty",              "MyFoo.stringConst")]
        [DataRow("String.Empty",              "sample.MyFoo.stringConst")]
        [DataRow("new string('x', 3)",        "stringConst")]
        [DataRow("new String('x', 3)",        "stringConst")]
        [DataRow("new System.String('x', 3)", "stringConst")]
        [DataTestMethod]
        public async Task VariableConcatenationPropertyGetPrivateSetWithInitializerCSharp(string initializer, string accessor)
        {
            var cSharpTest = $@"
using System.Data.SqlClient;
#pragma warning disable 8019
    using System;
#pragma warning restore 8019

namespace sample
{{
    class MyFoo
    {{
        public static string stringConst {{ get; private set; }} = {initializer};

        void Foo()
        {{
            var s          = ""select * from Products"";
            var sqlCommand = new SqlCommand(s + {accessor});
        }}
    }}
}}
";
            // todo: readonly fields aren't assumed const because no check for assignments in constructors is implemented
            var expected = new DiagnosticResult
            {
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
        }

        [DataRow("\"\"",                      "stringConst")]
        [DataRow("\"\"",                      "MyFoo.stringConst")]
        [DataRow("\"\"",                      "sample.MyFoo.stringConst")]
        [DataRow("String.Empty",              "stringConst")]
        [DataRow("String.Empty",              "MyFoo.stringConst")]
        [DataRow("String.Empty",              "sample.MyFoo.stringConst")]
        [DataRow("new string('x', 3)",        "stringConst")]
        [DataRow("new String('x', 3)",        "stringConst")]
        [DataRow("new System.String('x', 3)", "stringConst")]
        [DataTestMethod]
        public async Task VariableConcatenationPropertyExpressionBodyCSharp(string initializer, string accessor)
        {
            var cSharpTest = $@"
using System.Data.SqlClient;
#pragma warning disable 8019
    using System;
#pragma warning restore 8019

namespace sample
{{
    class MyFoo
    {{
        public static string stringConst => {initializer};

        void Foo()
        {{
            var s          = ""select * from Products"";
            var sqlCommand = new SqlCommand(s + {accessor});
        }}
    }}
}}
";
            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
        }

        [DataRow("\"\"",                      "stringConst")]
        [DataRow("\"\"",                      "MyFoo.stringConst")]
        [DataRow("\"\"",                      "sample.MyFoo.stringConst")]
        [DataRow("String.Empty",              "stringConst")]
        [DataRow("String.Empty",              "MyFoo.stringConst")]
        [DataRow("String.Empty",              "sample.MyFoo.stringConst")]
        [DataRow("new string('x', 3)",        "stringConst")]
        [DataRow("new String('x', 3)",        "stringConst")]
        [DataRow("new System.String('x', 3)", "stringConst")]
        [DataTestMethod, Ignore] // todo: add C# 7.0 support
        public async Task VariableConcatenationPropertyExpressionBodyGetCSharp(string initializer, string accessor)
        {
            var cSharpTest = $@"
using System.Data.SqlClient;
#pragma warning disable 8019
    using System;
#pragma warning restore 8019

namespace sample
{{
    class MyFoo
    {{
        public static string stringConst
        {{
            get => """";
        }}

        void Foo()
        {{
            var s          = ""select * from Products"";
            var sqlCommand = new SqlCommand(s + {accessor});
        }}
    }}
}}
";
            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
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

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
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
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
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
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task VariableOverride()
        {
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
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task VariableReuseFromSafeToUnknown()
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
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task VariableReuseFromUnknownToSafe()
        {
            var cSharpTest = @"
using System.Data.SqlClient;

namespace sample
{
    class SqlConstant
    {
        public static void Run(string input)
        {
            string query = input;
            SqlCommand cmd1 = new SqlCommand(query);

            query = ""SELECT * FROM [User] WHERE user_id = 1"";
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
            Dim query As String = input
            Dim cmd1 As New SqlCommand(query)

            query = ""SELECT * FROM [User] WHERE user_id = 1""
            Dim cmd2 As SqlCommand = New SqlCommand(query)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task VariableReuseFromUnknownToSafeInObject()
        {
            var cSharpTest = @"
using System.Data.SqlClient;

namespace sample
{
    class QueryDataClass
    {
        public string query { get; set; }
    }

    class SqlConstant
    {
        public static void Run(string input)
        {
            var queryObject = new QueryDataClass{
                query = input
            };

            SqlCommand cmd1 = new SqlCommand(queryObject.query);

            queryObject.query = ""SELECT * FROM [User] WHERE user_id = 1"";
            SqlCommand cmd2 = new SqlCommand(queryObject.query);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Data.SqlClient

Namespace sample
    Class QueryDataClass
        Public Property query As String
    End Class

    Class SqlConstant
        Public Shared Sub Run(input As String)
            Dim queryObject As QueryDataClass = new QueryDataClass With {
                .query = input
            }

            Dim cmd1 As New SqlCommand(queryObject.query)

            queryObject.query = ""SELECT * FROM [User] WHERE user_id = 1""
            Dim cmd2 As SqlCommand = New SqlCommand(queryObject.query)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task VariableReuseReplaceObject()
        {
            var cSharpTest = @"
using System.Data.SqlClient;

namespace sample
{
    class QueryDataClass
    {
        public string query { get; set; }
    }

    class SqlConstant
    {
        public static QueryDataClass GetQueryDataClass(string input)
        {
            return null;
        }

        public static void Run(string input)
        {
            var queryObject = new QueryDataClass{
                query = ""SELECT * FROM [User] WHERE user_id = 1""
            };

            SqlCommand cmd1 = new SqlCommand(queryObject.query);

            queryObject = GetQueryDataClass(input);
            SqlCommand cmd2 = new SqlCommand(queryObject.query);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Data.SqlClient

Namespace sample
    Class QueryDataClass
        Public Property query As String
    End Class

    Class SqlConstant
        Public Shared Function GetQueryDataClass(ByVal input As String) As QueryDataClass
            Return Nothing
        End Function

        Public Shared Sub Run(ByVal input As String)
            Dim queryObject = New QueryDataClass With {
                .query = ""SELECT * FROM [User] WHERE user_id = 1""
            }

            Dim cmd1 As SqlCommand = New SqlCommand(queryObject.query)

            queryObject = GetQueryDataClass(input)
            Dim cmd2 As SqlCommand = New SqlCommand(queryObject.query)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task UnsafeFunctionPassedAsParameter()
        {
            var cSharpTest = @"
using System.Data.SqlClient;

namespace sample
{
    class SqlConstant
    {
        public static void Run(string input)
        {
            UsesSqlCommand(new SqlCommand(input));
        }

        public static void UsesSqlCommand(SqlCommand command)
        {
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Data.SqlClient

Namespace sample
    Class SqlConstant
        Public Shared Sub Run(input As String)
            UsesSqlCommand(new SqlCommand(input))
        End Sub

        Public Shared Sub UsesSqlCommand(command as SqlCommand)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task ConfilctingLocalVariableAndObjectPropertyNames()
        {
            var cSharpTest = @"
using System.Data.SqlClient;

namespace sample
{
    class QueryDataClass
    {
        public string query { get; set; }
    }

    class SqlConstant
    {
        public static void Run(string input)
        {
            var query = ""SELECT * FROM [User] WHERE user_id = 1"";
            SqlCommand cmd1 = new SqlCommand(query);

            var queryObject = new QueryDataClass{
                query = input
            };

            cmd1 = new SqlCommand(query);
            SqlCommand cmd2 = new SqlCommand(queryObject.query);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Data.SqlClient

Namespace sample
    Class QueryDataClass
        Public Property query As String
    End Class

    Class SqlConstant
        Public Shared Sub Run(ByVal input As String)
            Dim query = ""SELECT* FROM[User] WHERE user_id = 1""
            Dim cmd1 As SqlCommand = New SqlCommand(query)
            Dim queryObject = New QueryDataClass With {
                .query = input
            }
            cmd1 = New SqlCommand(query)
            Dim cmd2 As SqlCommand = New SqlCommand(queryObject.query)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [Ignore] //TODO: Copy structure state when assigned to new variable
        [TestMethod]
        public async Task StructReuseChangePropertyFromTaintedToSafe()
        {
            var cSharpTest = @"
using System.Data.SqlClient;

namespace sample
{
    struct QueryDataClass
    {
        public string query { get; set; }
    }

    class SqlConstant
    {
        public static void Run(string input)
        {
            var queryObject = new QueryDataClass{
                query = input
            };
            var queryObject2 = queryObject;

            SqlCommand cmd1 = new SqlCommand(queryObject.query);
            cmd1 = new SqlCommand(queryObject2.query);

            queryObject.query = ""SELECT * FROM [User] WHERE user_id = 1"";
            SqlCommand cmd2 = new SqlCommand(queryObject.query);
            cmd2 = new SqlCommand(queryObject2.query);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Data.SqlClient

Namespace sample
    Structure  QueryDataClass
        Public Property query As String
    End Structure

Class SqlConstant
    Public Shared Sub Run(ByVal input As String)
        Dim queryObject = New QueryDataClass With {
            .query = input
        }
        Dim queryObject2 = queryObject

        Dim cmd1 As SqlCommand = New SqlCommand(queryObject.query)
        cmd1 = New SqlCommand(queryObject2.query)

        queryObject.query = ""SELECT* FROM[User] WHERE user_id = 1""
        Dim cmd2 As SqlCommand = New SqlCommand(queryObject.query)
        cmd2 = New SqlCommand(queryObject2.query)
    End Sub
End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, new [] {expected, expected, expected }).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new[] { expected, expected, expected }).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task ObjectReuseChangePropertyFromTaintedToSafe()
        {
            var cSharpTest = @"
using System.Data.SqlClient;

namespace sample
{
    class QueryDataClass
    {
        public string query { get; set; }
    }

    class SqlConstant
    {
        public static void Run(string input)
        {
            var queryObject = new QueryDataClass{
                query = input
            };
            var queryObject2 = queryObject;

            SqlCommand cmd1 = new SqlCommand(queryObject.query);
            cmd1 = new SqlCommand(queryObject2.query);

            queryObject.query = ""SELECT * FROM [User] WHERE user_id = 1"";
            SqlCommand cmd2 = new SqlCommand(queryObject.query);
            cmd2 = new SqlCommand(queryObject2.query);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Data.SqlClient

Namespace sample
    Class QueryDataClass
        Public Property query As String
    End Class

Class SqlConstant
    Public Shared Sub Run(ByVal input As String)
        Dim queryObject = New QueryDataClass With {
            .query = input
        }
        Dim queryObject2 = queryObject

        Dim cmd1 As SqlCommand = New SqlCommand(queryObject.query)
        cmd1 = New SqlCommand(queryObject2.query)

        queryObject.query = ""SELECT* FROM[User] WHERE user_id = 1""
        Dim cmd2 As SqlCommand = New SqlCommand(queryObject.query)
        cmd2 = New SqlCommand(queryObject2.query)
    End Sub
End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, new[] { expected, expected }).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new[] { expected, expected }).ConfigureAwait(false);
        }
    }
}
