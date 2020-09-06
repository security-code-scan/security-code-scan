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
    /// <summary>
    /// This class regroup test cases covering condition, loop and other structural statements..
    /// </summary>
    [TestClass]
    public class TaintAnalyzerControlFlowTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string _)
        {
            return new[] { new SqlInjectionTaintAnalyzer() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(System.Data.SqlClient.SqlCommand).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Web.Mvc.Controller).Assembly.Location)
        };

        private DiagnosticResult Expected = new DiagnosticResult
        {
            Id       = "SCS0002",
            Severity = DiagnosticSeverity.Warning,
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("string var1 = input; if (var1 == null) var1 = \"const\";",
                 "Dim var1 As String = input\r\nIf var1 Is Nothing Then var1 = \"const\"", true)]
        [DataRow("string var1 = \"const\"; if (var1 == null) var1 = input;",
                 "Dim var1 As String = \"const\"\r\nIf var1 Is Nothing Then var1 = input", false)]
        [DataRow("string var1 = null; if (var1 == null) var1 = input;",
                 "Dim var1 As String = Nothing\r\nIf var1 Is Nothing Then var1 = input", true)]
        [DataRow(@"string var1 = input;
                   if (var1 == null)
                       var1 = ""const1"";
                   else
                       var1 = ""const2"";",
                 @"Dim var1 As String = input
                   If var1 Is Nothing Then
                        var1 = ""const1""
                   Else
                        var1 = ""const2""
                   End If", false)]
        [DataRow(@"string var1 = input;
                   if (var1 == null)
                       var1 = ""const1"";
                   else if (var1 == ""a"")
                       var1 = ""const2"";",
                 @"Dim var1 As String = input
                    If var1 Is Nothing Then
                        var1 = ""const1""
                    ElseIf var1 = ""a"" Then
                        var1 = ""const2""
                    End If", true)]
        [DataRow(@"string var1 = input;
                   if (var1 == null)
                       var1 = ""const1"";
                   else if (var1 == ""a"")
                       var1 = ""const2"";
                   else
                       var1 = ""const3"";",
                 @"Dim var1 As String = input
                    If var1 Is Nothing Then
                        var1 = ""const1""
                    ElseIf var1 = ""a"" Then
                        var1 = ""const2""
                    Else
                        var1 = ""const3""
                    End If", false)]
        [DataRow(@"var var1 = input;
                   if (var1 == null)
                    {
                       var local = """";
                       b.x = local;
                    }",
                 @"Dim var1 As String = input
                    If var1 Is Nothing Then
                        Dim local = """"
                        b.x = local
                    End If", true)]
        [DataRow(@"string var1 = null;
                   switch (abc) {
                       case ABC.A:
                            var1 = input;
                       break;}",
                  @"Dim var1 As String = Nothing
                    Select Case abc
                    Case ABC.A
                        var1 = input
                    End Select", true)]
        [DataRow(@"string var1 = null;
                   switch (abc) {
                       case ABC.A:
                            var1 = input;
                       break;
                       default:
                            var1 = ""const1"";
                       break; }",
                  @"Dim var1 As String = Nothing
                    Select Case abc
                    Case ABC.A
                        var1 = input
                    Case Else
                        var1 = ""const1""
                    End Select", true)]
        [DataRow(@"string var1 = null;
                   switch (abc) {
                       case ABC.A:
                            var1 = ""const1"";
                       break;
                       default:
                            var1 = input;
                       break; }",
                  @"Dim var1 As String = Nothing
                    Select Case abc
                    Case ABC.A
                        var1 = ""const1""
                    Case Else
                        var1 = input
                    End Select", true)]
        [DataRow(@"string var1 = input;
                   switch (abc) {
                       case ABC.A:
                            var1 = ""const1"";
                       break;
                       default:
                            var1 = ""const1"";
                       break; }",
                  @"Dim var1 As String = input
                    Select Case abc
                    Case ABC.A
                        var1 = ""const1""
                    Case Else
                        var1 = ""const1""
                    End Select", false)]
        [DataRow(@"string var1 = input;
                   switch (abc) {
                       case ABC.A:
                            var1 = ""const1"";
                       break;
                       case ABC.B:
                            var1 = ""const1"";
                       break; }",
                  @"Dim var1 As String = input
                    Select Case abc
                    Case ABC.A
                        var1 = ""const1""
                    Case ABC.B
                        var1 = ""const1""
                    End Select", true)]
        [DataRow(@"string var1 = input;
                   var1 = var1 == null ? ""const1"" : ""const2"";",
                  @"Dim var1 As String = input
                    var1 = If(var1 Is Nothing, ""const1"", ""const2"")", false)]
        [DataRow(@"string var1 = input;
                   var1 = var1 == null ? ""const1"" : input;",
                  @"Dim var1 As String = input
                    var1 = If(var1 Is Nothing, ""const1"", input)", true)]
        [DataRow(@"string var1 = ""const"";
                   var1 = var1 ?? input;",
                  @"Dim var1 As String = ""const""
                    var1 = If(var1, input)", false)]
        [DataRow(@"string var1 = ""const"";
                   var1 = var1 == ""const"" ? input : var1;",
                  @"Dim var1 As String = ""const""
                    var1 = If(var1 = ""const"", input, var1)", true)]
        [DataRow(@"string var1 = ""const1"";
                   var1 = var1 ?? ""const2"";",
                  @"Dim var1 As String = ""const1""
                    var1 = If(var1, ""const2"")", false)]
        [DataRow(@"string var1 = ""const"";
                   b.x = input;
                   var1 = b.x;",
                  @"Dim var1 As String = ""const""
                    b.x = input
                    var1 = b.x", true)]
        [DataRow(@"string var1 = ""const"";
                   b.x = input;
                   var1 = b?.x;",
                  @"Dim var1 As String = ""const""
                    b.x = input
                    var1 = b?.x", true)]
        public async Task IfElse(string cs, string vb, bool warn)
        {
            var cSharpTest = $@"
using System.Data.SqlClient;
using System.Web.Mvc;

namespace sample
{{
    public class B
    {{
        public string x = null;
    }}

    public enum ABC
    {{
        A,
        B,
        C
    }}

    public class SqlConstantController : Controller
    {{
        public void Run(string input, ABC abc)
        {{
#pragma warning disable CS0219
            B b = new B();
#pragma warning restore CS0219
            {cs}

            var temp = new SqlCommand(var1);
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Data.SqlClient
Imports System.Web.Mvc

Namespace sample
    Public Class B
        Public x As String = Nothing
    End Class

    Public Enum ABC
        A
        B
        C
    End Enum

    Public Class SqlConstantController
        Inherits Controller

        Public Sub Run(ByVal input As String, ByVal abc As ABC)
            Dim b As B = New B()
            {vb}
            Dim temp = New SqlCommand(var1)
        End Sub
    End Class
End Namespace
";
            if (warn)
            {
                await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
            }
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task Condition1()
        {
            var cSharpTest = @"
using System.Data.SqlClient;
using System.Web.Mvc;

namespace sample
{
    public class SqlConstantController : Controller
    {
        public void Run(string input)
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

            var visualBasicTest = @"
Imports System.Data.SqlClient
Imports System.Web.Mvc

Namespace sample
    Public Class SqlConstantController
        Inherits Controller

        Public Sub Run(input As String)
            Dim username As String = input
            Dim variable1 = username
            Dim variable2 = variable1

            If variable2 <> """" Then
                Dim com As New SqlCommand(variable2)
            End If
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task Condition2()
        {
            var cSharpTest = @"
using System.Data.SqlClient;
using System.Web.Mvc;

namespace sample
{
    public class SqlConstantController : Controller
    {
        public void Run(string input)
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

            var visualBasicTest = @"
Imports System.Data.SqlClient
Imports System.Web.Mvc

Namespace sample
    Public Class SqlConstantController
        Inherits Controller

        Public Sub Run(input As String)
            Dim username As String = input
            Dim variable1 = username
            Dim variable2 = variable1

            Dim com As SqlCommand
            If (variable2 <> """") Then com = New SqlCommand(variable2)
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task ReThrow()
        {
            var cSharpTest = @"
using System.Web.Mvc;

namespace sample
{
    public class SqlConstantController : Controller
    {
        public void Run()
        {
            try
            {
            }
            catch
            {
                throw;
            }
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Web.Mvc

Namespace sample
    Public Class SqlConstantController
        Inherits Controller

        Public Sub Run()
            Try
            Catch
                Throw
            End Try
        End Sub
    End Class
End Namespace
";

            // should not throw
            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task Loop1()
        {
            var cSharpTest = @"
using System.Data.SqlClient;
using System.Web.Mvc;

namespace sample
{
    public class SqlConstantController : Controller
    {
        public void Run(string input)
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

            var visualBasicTest = @"
Imports System.Data.SqlClient
Imports System.Web.Mvc

Namespace sample
    Public Class SqlConstantController
        Inherits Controller

        Public Sub Run(input As String)
            Dim username As String = input
            Dim variable1 = username
            Dim variable2 = variable1

            For i As Integer = 0 To 9
                Dim com As New SqlCommand(variable2)
            Next
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task Loop2()
        {
            var cSharpTest = @"
using System.Data.SqlClient;
using System.Web.Mvc;

namespace sample
{
    public class SqlConstantController : Controller
    {
        public void Run(string input)
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

            var visualBasicTest = @"
Imports System.Data.SqlClient
Imports System.Web.Mvc

Namespace sample
    Public Class SqlConstantController
        Inherits Controller

        Public Sub Run(input As String)
            Dim username As String = input
            Dim variable1 = username
            Dim variable2 = variable1

            For i As Integer = 0 To 9
                Dim com As New SqlCommand(variable2)
            Next
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task ConditionIsCSharp()
        {
            var cSharpTest = @"
using System;
using System.Data.SqlClient;
using System.Web.Mvc;

namespace sample
{
    public class TestController : Controller
    {
        public void Foo(object o)
        {
            if (o is String)
                new SqlCommand((string)null);
        }
    }
}
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task PatternMatchingSwitch()
        {
            var cSharpTest = @"
using System;
using System.Data.SqlClient;
using System.Web.Mvc;

namespace sample
{
    public class TestController : Controller
    {
        public void Foo(object o)
        {
            switch(o)
            {
            case String s:
                new SqlCommand(s);
                break;
            }
        }
    }
}
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task PatternMatchingSwitch2()
        {
            var cSharpTest = @"
using System;
using System.Data.SqlClient;
using System.Web.Mvc;

namespace sample
{
    public class TestController : Controller
    {
        public void Foo(object o)
        {
            string x = null;
            switch(o)
            {
            case String s:
                x = s;
                break;
            }
            new SqlCommand(x);
        }
    }
}
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task Cast()
        {
            var cSharpTest = @"
using System;
using System.Data.SqlClient;
using System.Web.Mvc;

namespace sample
{
    public class TestController : Controller
    {
        public void Foo()
        {
            new SqlCommand((string)null);
            new SqlCommand(null as string);
            new SqlCommand(default(string));

            object o = null;
            switch(o)
            {
            case String s:
                new SqlCommand(s);
                break;
            }
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Data.SqlClient
Imports System.Web.Mvc

Namespace sample
    Public Class Test
        Inherits Controller

        Public Sub Foo()
#Disable Warning BC42024
            Dim a As New SqlCommand(DirectCast(Nothing, String))
            Dim b As New SqlCommand(CType(Nothing, String))
            Dim c As New SqlCommand(Nothing)
#Enable Warning BC42024
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }
    }
}
