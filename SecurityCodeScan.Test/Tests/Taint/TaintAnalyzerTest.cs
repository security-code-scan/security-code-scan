using System.Collections.Generic;
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
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new List<DiagnosticAnalyzer> { new TaintAnalyzer() };
        }

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[] { MetadataReference.CreateFromFile(typeof(System.Data.SqlClient.SqlCommand).Assembly.Location) };
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
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [TestMethod]
        public async Task VariableNoPropertyBody()
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
        Private Property Length As Integer ' todo = 5
        Public Sub Run2()
            Dim num As Integer = Length
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
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

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
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
        [DataTestMethod, Ignore] // todo: methods are not expanded yet
        public async Task VariableConcatenationMethod(string initializer, string accessor)
        {
            var cSharpTest = $@"
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

            var visualBasicTest = $@"
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

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [TestMethod]
        public async Task VariableConcatenationReadonlyFieldBackReference()
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

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [TestMethod]
        public async Task VariableConcatenationReadonlyPropertyBackReference()
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

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
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
        public async Task VariableConcatenationField(string initializer, string accessor)
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

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [TestMethod]
        public async Task VariableConcatenationReadonlyFieldInContructor()
        {
            var cSharpTest = @"
using System.Data.SqlClient;

namespace sample
{
    class MyFoo
    {
        readonly string stringConst;

        public MyFoo()
        {
            stringConst = ""1"";
        }

        public MyFoo(bool b)
        {
            stringConst = ""2"";
        }

        void Foo()
        {
            var s          = ""select * from Products"";
            var sqlCommand = new SqlCommand(s + stringConst);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Data.SqlClient

Namespace sample
    Class MyFoo
        Private ReadOnly stringConst As String
        Public Sub New()
            Me.stringConst = ""1""
        End Sub
        Public Sub New(b as Boolean)
            Me.stringConst = ""2""
        End Sub
        Private Sub Foo()
            Dim s As String = ""select * from Products""

            Dim com As New SqlCommand(s + stringConst)
        End Sub
    End Class
End Namespace
";

            // todo: Although it is readonly and assigned to a const i constructor, it is not implemented yet
            var expected = new DiagnosticResult
            {
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
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
            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [DataRow("\"\"", "stringConst")]
        [DataRow("\"\"", "MyFoo.stringConst")]
        [DataRow("\"\"", "sample.MyFoo.stringConst")]
        [DataTestMethod]
        public async Task VariableConcatenationConstPropertyBackingField(string initializer, string accessor)
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
            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
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
        public async Task VariableConcatenationPropertyBackingField(string initializer, string accessor)
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
            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [DataRow("\"\"",                      "stringConst")]
        [DataRow("\"\"",                      "this.stringConst")]
        [DataRow("String.Empty",              "stringConst")]
        [DataRow("String.Empty",              "this.stringConst")]
        [DataRow("new string('x', 3)",        "stringConst")]
        [DataRow("new String('x', 3)",        "stringConst")]
        [DataRow("new System.String('x', 3)", "stringConst")]
        [DataTestMethod, Ignore]
        public async Task VariableConcatenationReadonlyContructorPropertyBackingField(string initializer, string accessor)
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
            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
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
        public async Task VariableConcatenationProperty2CSharp(string initializer, string accessor)
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
            await VerifyCSharpDiagnostic(cSharpTest);
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
        public async Task VariableConcatenationProperty3CSharp(string initializer, string accessor)
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
            await VerifyCSharpDiagnostic(cSharpTest);
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
        public async Task VariableConcatenationProperty4CSharp(string initializer, string accessor)
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
            await VerifyCSharpDiagnostic(cSharpTest);
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
                Id       = "SCS0026",
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
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
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
                Id       = "SCS0026",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }
    }
}
