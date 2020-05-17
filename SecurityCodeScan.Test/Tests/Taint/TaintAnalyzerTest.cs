using System.Collections.Generic;
using System.Linq;
using System.Reflection;
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
    public class TaintAnalyzerTest : DiagnosticVerifier
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
            MetadataReference.CreateFromFile(typeof(System.Data.SqlClient.SqlCommand).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Web.Mvc.Controller).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Web.HttpRequestBase).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.Controller).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.ControllerBase).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Http.HttpRequest).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Http.IRequestCookieCollection).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.Extensions.Primitives.StringValues).Assembly.Location),
            MetadataReference.CreateFromFile(Assembly.Load("System.Runtime, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")
                                                     .Location),
            MetadataReference.CreateFromFile(Assembly.Load("netstandard, Version=2.0.0.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51")
                                                     .Location),
        };

        private DiagnosticResult Expected = new DiagnosticResult
        {
            Id       = "SCS0026",
            Severity = DiagnosticSeverity.Warning,
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestMethod]
        public async Task NamedArgumentsPostCondition()
        {
            var cSharpTest = @"
class Test
{
    public void Encode(string input, int x = 0, System.Text.StringBuilder output = null)
    {
        if (output == null)
            return;
    }
    public void Injectable(string input)
    {
        // pretend it does something
    }
}
class TestInput
{
    public void Input(string userProvided)
    {
        var t = new Test();
        var encoded = new System.Text.StringBuilder();
        t.Encode(userProvided, output: encoded);
        t.Injectable(encoded.ToString());
    }
}
";

            var vbTest = $@"
Class Test
    Public Sub Encode(ByVal input As String, ByVal Optional x As Integer = 0, ByVal Optional output As System.Text.StringBuilder = Nothing)
        If output Is Nothing Then Return
    End Sub
    Public Sub Injectable(ByVal input As String)
    End Sub
End Class
Class TestInput
    Public Sub Input(ByVal userProvided As String)
        Dim t = New Test()
        Dim encoded = New System.Text.StringBuilder()
        t.Encode(userProvided, output:=encoded)
        t.Injectable(encoded.ToString())
    End Sub
End Class
";

            var config = @"
Behavior:
  Injectable:
    ClassName: Test
    Name: Injectable
    Method:
      InjectableArguments: [SCS0026: 0]
  Encode:
    ClassName: Test
    Name: Encode
    Method:
      2:
        TaintFromArguments: [0]
TaintEntryPoints:
  Test:
    ClassName: TestInput
";

            var testConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(config);

            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(21), testConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(vbTest, Expected.WithLocation(14), testConfig).ConfigureAwait(false);
        }

        [DataTestMethod]
        [DataRow("Injectable", "userProvided, userProvided",            true)]
        [DataRow("Injectable", "\"\", userProvided",                    false)]
        [DataRow("Injectable", "userProvided, \"\"",                    true)]
        [DataRow("Injectable", "\"\", \"\"",                            false)]
        [DataRow("Injectable", "dangerous: userProvided, safe: \"\"",   true)]
        [DataRow("Injectable", "dangerous: \"\", safe: userProvided",   false)]
        [DataRow("Injectable", "safe: userProvided, dangerous: \"\"",   false)]
        [DataRow("Injectable", "safe: \"\", dangerous: userProvided",   true)]

        [DataRow("Injectable2", "userProvided, userProvided",           true)]
        [DataRow("Injectable2", "\"\", userProvided",                   false)]
        [DataRow("Injectable2", "userProvided, \"\"",                   true)]
        [DataRow("Injectable2", "\"\", \"\"",                           false)]
        [DataRow("Injectable2", "dangerous: userProvided, safe: \"\"",  true)]
        [DataRow("Injectable2", "dangerous: \"\", safe: userProvided",  false)]
        [DataRow("Injectable2", "safe: userProvided, dangerous: \"\"",  false)]
        [DataRow("Injectable2", "safe: \"\", dangerous: userProvided",  true)]

        [DataRow("InjectableOpt", "",                                   false)]
        [DataRow("InjectableOpt", "userProvided, userProvided",         true)]
        [DataRow("InjectableOpt", "safe: userProvided",                 false)]
        [DataRow("InjectableOpt", "dangerous: userProvided",            true)]
        [DataRow("InjectableOpt", "dangerous: \"\"",                    false)]

        [DataRow("InjectableOpt2", "",                                  false)]
        [DataRow("InjectableOpt2", "userProvided, userProvided",        true)]
        [DataRow("InjectableOpt2", "safe: userProvided",                false)]
        [DataRow("InjectableOpt2", "dangerous: userProvided",           true)]
        [DataRow("InjectableOpt2", "dangerous: \"\"",                   false)]
        public async Task NamedArguments(string function, string payload, bool warn)
        {
            var cSharpTest = $@"
class Test
{{
    public void Injectable(string dangerous, string safe)
    {{
        // pretend it does something
    }}
    public void InjectableOpt(string dangerous=""foo"", string safe=""bar"")
    {{
        // pretend it does something
    }}
}}
static class TestExtensions
{{
    public static void Injectable2(this Test self, string dangerous, string safe)
    {{
        // pretend it does something
    }}
    public static void InjectableOpt2(this Test self, string dangerous=""foo"", string safe=""bar"")
    {{
        // pretend it does something
    }}
}}
class TestInput
{{
    public void Input(string userProvided)
    {{
        new Test().{function}({payload});
    }}
}}
";

            function = function.Replace("this", "Me");
            payload = payload.Replace(":", ":=");

            var vbTest = $@"
Imports System.Runtime.CompilerServices
Class Test
    Public Sub Injectable(ByVal dangerous As String, ByVal safe As String)
    End Sub
    Public Sub InjectableOpt(ByVal Optional dangerous As String = ""foo"", ByVal Optional safe As String = ""bar"")
    End Sub
End Class
Module TestExtensions
    <Extension()>
    Public Sub Injectable2(ByVal self As Test, ByVal dangerous As String, ByVal safe As String)
    End Sub
    <Extension()>
    Public Sub InjectableOpt2(ByVal self As Test, ByVal Optional dangerous As String = ""foo"", ByVal Optional safe As String = ""bar"")
    End Sub
End Module
Class TestInput
    Public Sub Input(ByVal userProvided As String)
        Dim a As New Test()
        a.{function}({payload})
    End Sub
End Class
";

            var config = @"
Behavior:
  Injectable:
    ClassName: Test
    Name: Injectable
    Method:
      InjectableArguments: [SCS0026: 0]
  InjectableOpt:
    ClassName: Test
    Name: InjectableOpt
    Method:
      InjectableArguments: [SCS0026: 0]
  InjectableExtension:
    ClassName: TestExtensions
    Name: Injectable2
    Method:
      InjectableArguments: [SCS0026: 1]
  InjectableExtensionOpt:
    ClassName: TestExtensions
    Name: InjectableOpt2
    Method:
      InjectableArguments: [SCS0026: 1]
TaintEntryPoints:
  Test:
    ClassName: TestInput
";

            var testConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(config);

            if (warn)
            {
                await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(28), testConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(vbTest, Expected.WithLocation(20), testConfig).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest, null, testConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(vbTest, null, testConfig).ConfigureAwait(false);
            }
        }

        [TestCategory("Safe")]
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

        [TestCategory("Safe")]
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

        [TestCategory("Safe")]
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

        [TestCategory("Safe")]
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

        [TestCategory("Detect")]
        [TestMethod]
        public async Task This()
        {
            var cSharpTest = @"
using System.Text;

class Test
{
    string GetUntrusted()
    {
        return null;
    }

    void Sink(string value)
    {
    }

    public Test()
    {
        string id = GetUntrusted();
        var st = new StringBuilder();
        st.Append(""Select *from families where id = ""+id);
        Sink(st.ToString());
    }
}
";

            var visualBasicTest = @"
Imports System.Text

Class Test
    Private Function GetUntrusted() As String
        Return Nothing
    End Function

    Private Sub Sink(ByVal value As String)
    End Sub

    Public Sub New()
        Dim id As String = GetUntrusted()
        Dim st = New StringBuilder()
        st.Append(""Select *from families where id = "" & id)
        Sink(st.ToString())
    End Sub
End Class
";

            var testConfig = @"
Behavior:
  Untrusted:
    ClassName: Test
    Name: GetUntrusted
    Method:
      Returns:
        Taint: Tainted

  Sink:
    ClassName: Test
    Name: Sink
    Method:
      InjectableArguments: [SCS0026: 0]

  StringBuilder_Append:
    Namespace: System.Text
    ClassName: StringBuilder
    Name: Append
    Method:
      This:
        TaintFromArguments: [0]
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic     (cSharpTest,      Expected.WithLocation(20), optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(16), optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("SetValue(input)", "GetValue()", true,  false)]
        [DataRow("SetValue(input)", "GetValue()", true,  true)]
        [DataRow("SetConst(input)", "GetValue()", true,  false)]
        [DataRow("SetConst(input)", "GetValue()", false, true)]
        [DataRow("DoNothing()",     "GetValue()", false, false)]
        [DataRow("DoNothing()",     "GetValue()", false, true)]

        [DataRow("SetValue(input)", "GetConst()", true,  false)]
        [DataRow("SetValue(input)", "GetConst()", false,  true)]
        [DataRow("SetConst(input)", "GetConst()", true,  false)]
        [DataRow("SetConst(input)", "GetConst()", false, true)]
        [DataRow("DoNothing()",     "GetConst()", false, false)]
        [DataRow("DoNothing()",     "GetConst()", false, true)]

        [DataRow("DoNothing()",     "CallAndReturn(input)", true, false)]
        [DataRow("DoNothing()",     "CallAndReturn(input)", true, true)]
        [DataRow("DoNothing()",     "CallAndReturnConst(input)", true, false)]
        [DataRow("DoNothing()",     "CallAndReturnConst(input)", false, true)]

        [DataRow("CallRef(input, out outVar)", "CallAndReturn(outVar)",                 true,  false)]
        [DataRow("CallRef(input, out outVar)", "CallAndReturn(outVar)",                 true,  true)]
        [DataRow("DoNothing()",                "CallRefReturn(input, out outVar)",      true,  false)]
        [DataRow("DoNothing()",                "CallRefReturn(input, out outVar)",      true,  true)]
        [DataRow("DoNothing()",                "CallRefReturnConst(input, out outVar)", true,  false)]
        [DataRow("DoNothing()",                "CallRefReturnConst(input, out outVar)", false, true)]
        public async Task This2(string functionName1, string functionName2, bool detect, bool withBehavior)
        {
            var cSharpTest = $@"
class Test
{{
    string GetUntrusted()
    {{
        return null;
    }}

    void Sink(string value)
    {{
    }}

    public Test()
    {{
        string input = GetUntrusted();
        var x = new SomeClass();
#pragma warning disable CS0168
        string outVar;
#pragma warning restore CS0168
        x.{functionName1};
        Sink(x.{functionName2});
    }}
}}

class SomeClass
{{
    private string _value;

    public void SetValue(string value)
    {{
        _value = value;
    }}

    public void SetConst(string value)
    {{
        _value = """";
    }}

    public string CallAndReturnConst(string value)
    {{
        return """";
    }}

    public string CallAndReturn(string value)
    {{
        return value;
    }}

    public string GetConst()
    {{
        return """";
    }}

    public string GetValue()
    {{
        return _value;
    }}

    public void DoNothing()
    {{
    }}

    public void CallRef(string value, out string outValue)
    {{
        outValue = value;
    }}

    public string CallRefReturn(string value, out string outValue)
    {{
        outValue = value;
        return value;
    }}

    public string CallRefReturnConst(string value, out string outValue)
    {{
        outValue = value;
        return """";
    }}
}}
";

            var visualBasicTest = $@"
Class Test
    Private Function GetUntrusted() As String
        Return Nothing
    End Function

    Private Sub Sink(ByVal value As String)
    End Sub

    Public Sub New()
        Dim input As String = GetUntrusted()
        Dim x = New SomeClass()
#Disable Warning BC42024, BC42030
        Dim outVar As String
        x.{functionName1.CSharpReplaceToVBasic()}
        Sink(x.{functionName2.CSharpReplaceToVBasic()})
#Enable Warning BC42024, BC42030
    End Sub
End Class

Class SomeClass
    Private _value As String

    Public Sub SetValue(ByVal value As String)
        _value = value
    End Sub

    Public Sub SetConst(ByVal value As String)
        _value = """"
    End Sub

    Public Function CallAndReturnConst(ByVal value As String) As String
        Return """"
    End Function

    Public Function CallAndReturn(ByVal value As String) As String
        Return value
    End Function

    Public Function GetConst() As String
        Return """"
    End Function

    Public Function GetValue() As String
        Return _value
    End Function

    Public Sub DoNothing()
    End Sub

    Public Sub CallRef(ByVal value As String, ByRef outValue As String)
        outValue = value
    End Sub

    Public Function CallRefReturn(ByVal value As String, ByRef outValue As String) As String
        outValue = value
        Return value
    End Function

    Public Function CallRefReturnConst(ByVal value As String, ByRef outValue As String) As String
        outValue = value
        Return """"
    End Function
End Class
";

            var testConfig = @"
Behavior:
  Untrusted:
    ClassName: Test
    Name: GetUntrusted
    Method:
      Returns:
        Taint: Tainted

  Sink:
    ClassName: Test
    Name: Sink
    Method:
      InjectableArguments: [SCS0026: 0]
";

            var testConfigWithBehavior = @"
Behavior:
  Untrusted:
    ClassName: Test
    Name: GetUntrusted
    Method:
      Returns:
        Taint: Tainted

  Sink:
    ClassName: Test
    Name: Sink
    Method:
      InjectableArguments: [SCS0026: 0]

  SomeClass_SetValue:
    ClassName: SomeClass
    Name: SetValue
    Method:
      This:
        TaintFromArguments: [0]

  SomeClass_SetConst:
    ClassName: SomeClass
    Name: SetConst
    Method:
      This:
        Taint: Constant

  SomeClass_CallAndReturn:
    ClassName: SomeClass
    Name: CallAndReturn
    Method:
      Returns:
        TaintFromArguments: [0]

  SomeClass_CallAndReturnConst:
    ClassName: SomeClass
    Name: CallAndReturnConst
    Method:
      Returns:
        Taint: Constant

  SomeClass_GetValue:
    ClassName: SomeClass
    Name: GetValue
    Method:
      Returns:
        TaintFromArguments: [This]

  SomeClass_GetConst:
    ClassName: SomeClass
    Name: GetConst
    Method:
      Returns:
        Taint: Constant

  SomeClass_CallRef:
    ClassName: SomeClass
    Name: CallRef
    Method:
      1:
        TaintFromArguments: [0]

  SomeClass_CallRefReturn:
    ClassName: SomeClass
    Name: CallRefReturn
    Method:
      1:
        TaintFromArguments: [0]
      Returns:
        TaintFromArguments: [0]

  SomeClass_CallRefReturnConst:
    ClassName: SomeClass
    Name: CallRefReturnConst
    Method:
      1:
        TaintFromArguments: [0]
      Returns:
        Taint: Constant
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(withBehavior ? testConfigWithBehavior : testConfig);

            if (detect)
            {
                await VerifyCSharpDiagnostic     (cSharpTest,      Expected.WithLocation(21), optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(16), optionsWithProjectConfig).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic     (cSharpTest,      null, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            }
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("sql",       new[] { "SCS0026" }, new[] { "SCS0026" })]
        [DataRow("xyz",       new[] { "CS0103" },  new[] { "BC30451" })]
        [DataRow("foo()",     new[] { "CS1503" },  new[] { "BC30311" })]
        [DataRow("foo2(xyz)", new[] { "CS0103" },  new[] { "BC30451" })]
        public async Task Constructor(string right, string[] csErrors, string[] vbErrors)
        {
            var cSharpTest = $@"
using System.Data.SqlClient;

namespace sample
{{
    class Test
    {{
        static string GetUntrusted()
        {{
            return null;
        }}

        public Test()
        {{
            string sql = GetUntrusted();
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
        Private Shared Function GetUntrusted() As String
            Return Nothing
        End Function

        Public Sub New()
            Dim sql As String = GetUntrusted()
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

            var testConfig = @"
Behavior:
  AAA:
    Namespace: sample
    ClassName: Test
    Name: GetUntrusted
    Method:
      Returns:
        Taint: Tainted
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest,
                                         csErrors.Select(x => new DiagnosticResult { Id = x }.WithLocation(16)).ToArray(), optionsWithProjectConfig)
                .ConfigureAwait(false);

            await VerifyVisualBasicDiagnostic(visualBasicTest,
                                              vbErrors.Select(x => new DiagnosticResult { Id = x }.WithLocation(12)).ToArray(), optionsWithProjectConfig)
                .ConfigureAwait(false);
        }

        [TestCategory("Detect")]
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

            var testConfig = @"
AuditMode: true
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
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

            var testConfig = @"
AuditMode: true
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
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
            var auditConfig = await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, null, auditConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, auditConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
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
            var auditConfig = await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, null, auditConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, auditConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
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
        [Ignore("methods are not expanded yet")]
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
            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
            var auditConfig = await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, null, auditConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, auditConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
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
            var auditConfig = await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, null, auditConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, auditConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
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
            var auditConfig = await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, null, auditConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, auditConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
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

            initializer = initializer.CSharpReplaceToVBasic();
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
            var auditConfig = await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, null, auditConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, auditConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
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
        [Ignore("readonly fields aren't assumed const because no check for assignments in constructors is implemented")]
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

            initializer = initializer.CSharpReplaceToVBasic();
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
            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
            var auditConfig = await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, null, auditConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, auditConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataRow("\"\"",                      "stringConst")]
        [DataRow("\"\"",                      "this.stringConst")]
        [DataRow("String.Empty",              "stringConst")]
        [DataRow("String.Empty",              "this.stringConst")]
        [DataRow("new string('x', 3)",        "stringConst")]
        [DataRow("new String('x', 3)",        "stringConst")]
        [DataRow("new System.String('x', 3)", "stringConst")]
        [DataTestMethod]
        [Ignore("readonly fields aren't assumed const because no check for assignments in constructors is implemented")]
        public async Task VariableConcatenationFieldReadonlyConstructor(string initializer, string accessor)
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

            initializer = initializer.CSharpReplaceToVBasic();
            accessor    = accessor.CSharpReplaceToVBasic();
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

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
            var auditConfig = await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, null, auditConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, auditConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [DataRow("\"\"",                      "stringConst")]
        [DataRow("\"a\" + \"b\"",             "stringConst")]
        [DataRow("\"\"",                      "MyFoo.stringConst")]
        [DataRow("\"\"",                      "sample.MyFoo.stringConst")]
        [DataRow("String.Empty",              "stringConst")]
        [DataRow("String.Empty",              "MyFoo.stringConst")]
        [DataRow("String.Empty",              "sample.MyFoo.stringConst")]
        // isn't treated as const by new control flow implementation, but it is questionable if it is needed
        //[DataRow("new string('x', 3)",        "stringConst")]
        //[DataRow("new String('x', 3)",        "stringConst")]
        //[DataRow("new System.String('x', 3)", "stringConst")]
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

            initializer         = initializer.CSharpReplaceToVBasic();
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
            var auditConfig = await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, null, auditConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, auditConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
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

            initializer         = initializer.CSharpReplaceToVBasic();
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
            var auditConfig = await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, null, auditConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, auditConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
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
        [Ignore("readonly fields aren't assumed const because no check for assignments in constructors is implemented")]
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

            initializer         = initializer.CSharpReplaceToVBasic();
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
            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
            var auditConfig = await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, null, auditConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, auditConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataRow("\"\"",                      "stringConst")]
        [DataRow("\"\"",                      "this.stringConst")]
        [DataRow("String.Empty",              "stringConst")]
        [DataRow("String.Empty",              "this.stringConst")]
        [DataRow("new string('x', 3)",        "stringConst")]
        [DataRow("new String('x', 3)",        "stringConst")]
        [DataRow("new System.String('x', 3)", "stringConst")]
        [DataTestMethod]
        [Ignore("readonly fields aren't assumed const because no check for assignments in constructors is implemented")]
        public async Task VariableConcatenationPropertyReadonlyConstructorBackingField(string initializer, string accessor)
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

            initializer = initializer.CSharpReplaceToVBasic();
            accessor    = accessor.CSharpReplaceToVBasic();
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
            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
            var auditConfig = await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, null, auditConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, auditConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
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
        [Ignore("'property = {}' is not implemented")]
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

            initializer = initializer.CSharpReplaceToVBasic();
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

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
            var auditConfig = await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, null, auditConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, auditConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
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
        [Ignore("'property = {}' is not implemented")]
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
            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [DataRow("\"\"",                      "stringConst")]
        [DataRow("\"\"",                      "MyFoo.stringConst")]
        [DataRow("\"\"",                      "sample.MyFoo.stringConst")]
        [DataRow("String.Empty",              "stringConst")]
        [DataRow("String.Empty",              "MyFoo.stringConst")]
        [DataRow("String.Empty",              "sample.MyFoo.stringConst")]
        // isn't treated as const by new control flow implementation, but it is questionable if it is needed
        //[DataRow("new string('x', 3)",        "stringConst")]
        //[DataRow("new String('x', 3)",        "stringConst")]
        //[DataRow("new System.String('x', 3)", "stringConst")]
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
            var auditConfig = await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, null, auditConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
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
        [Ignore("add C# 7.0 support")]
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
            var auditConfig = await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, null, auditConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
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
            var auditConfig = await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, null, auditConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, auditConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task VariableTransferUnsafe()
        {
            var cSharpTest = @"
using System.Data.SqlClient;
using System.Web.Mvc;

namespace sample
{
    class SqlConstant : Controller
    {
        public void Run(string input)
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
Imports System.Web.Mvc

Namespace sample
    Class SqlConstant
        Inherits Controller

        Public Sub Run(input As String)
            Dim username As String = input
            Dim variable1 = username
            Dim variable2 = variable1

            Dim com As New SqlCommand(variable2)
        End Sub

    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task VariableConcatenationUnsafe()
        {
            var cSharpTest = @"
using System.Data.SqlClient;
using System.Web.Mvc;

namespace sample
{
    class SqlConstant : Controller
    {
        public void Run(string input)
        {
            new SqlCommand(""SELECT* FROM users WHERE username = '"" + input + ""' LIMIT 1"");
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Data.SqlClient
Imports System.Web.Mvc

Namespace sample
    Class SqlConstant
        Inherits Controller

        Public Sub Run(input As String)
            Dim com As New SqlCommand(""SELECT* FROM users WHERE username = '"" & input & ""' LIMIT 1"")
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task VariableOverride()
        {
            var cSharpTest = @"
using System.Data.SqlClient;
using System.Web.Mvc;

namespace sample
{
    class SqlConstant : Controller
    {
        public void Run(string input)
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
Imports System.Web.Mvc

Namespace sample
    Class SqlConstant
        Inherits Controller

        Public Sub Run(input As String)
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

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task VariableReuseFromSafeToUnknown()
        {
            var cSharpTest = @"
using System.Data.SqlClient;
using System.Web.Mvc;

namespace sample
{
    class SqlConstant : Controller
    {
        public void Run(string input)
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
Imports System.Web.Mvc

Namespace sample
    Class SqlConstant
        Inherits Controller

        Public Sub Run(input As String)
            Dim query As String = ""SELECT * FROM [User] WHERE user_id = 1""
            Dim cmd1 As New SqlCommand(query)

            query = input
            Dim cmd2 As SqlCommand = New SqlCommand(query)
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task VariableReuseFromUnknownToSafe()
        {
            var cSharpTest = @"
using System.Data.SqlClient;
using System.Web.Mvc;

namespace sample
{
    class SqlConstant : Controller
    {
        public void Run(string input)
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
Imports System.Web.Mvc

Namespace sample
    Class SqlConstant
        Inherits Controller

        Public Sub Run(input As String)
            Dim query As String = input
            Dim cmd1 As New SqlCommand(query)

            query = ""SELECT * FROM [User] WHERE user_id = 1""
            Dim cmd2 As SqlCommand = New SqlCommand(query)
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task VariableReuseFromUnknownToSafeInObject()
        {
            var cSharpTest = @"
using System.Data.SqlClient;
using System.Web.Mvc;

namespace sample
{
    class QueryDataClass
    {
        public string query { get; set; }
    }

    class SqlConstant : Controller
    {
        public void Run(string input)
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
Imports System.Web.Mvc

Namespace sample
    Class QueryDataClass
        Public Property query As String
    End Class

    Class SqlConstant
        Inherits Controller

        Public Sub Run(input As String)
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

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task VariableReuseReplaceObject()
        {
            var cSharpTest = @"
using System.Data.SqlClient;
using System.Web.Mvc;

namespace sample
{
    class QueryDataClass
    {
        public string query { get; set; }
    }

    class SqlConstant : Controller
    {
        public static QueryDataClass GetQueryDataClass(string input)
        {
            return null;
        }

        public void Run(string input)
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
Imports System.Web.Mvc

Namespace sample
    Class QueryDataClass
        Public Property query As String
    End Class

    Class SqlConstant
        Inherits Controller

        Public Shared Function GetQueryDataClass(ByVal input As String) As QueryDataClass
            Return Nothing
        End Function

        Public Sub Run(ByVal input As String)
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

            var testConfig = @"
Behavior:
  AAA:
    Namespace: sample
    ClassName: SqlConstant
    Name: GetQueryDataClass
    Method:
      Returns:
        Taint: Tainted
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task UnsafeFunctionPassedAsParameter()
        {
            var cSharpTest = @"
using System.Data.SqlClient;
using System.Web.Mvc;

namespace sample
{
    class SqlConstant : Controller
    {
        public void Run(string input)
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
Imports System.Web.Mvc

Namespace sample
    Class SqlConstant
        Inherits Controller

        Public Sub Run(input As String)
            UsesSqlCommand(new SqlCommand(input))
        End Sub

        Public Shared Sub UsesSqlCommand(command as SqlCommand)
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task ConflictingLocalVariableAndObjectPropertyNames()
        {
            var cSharpTest = @"
using System.Data.SqlClient;
using System.Web.Mvc;

namespace sample
{
    class QueryDataClass
    {
        public string query { get; set; }
    }

    class SqlConstant : Controller
    {
        public void Run(string input)
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
Imports System.Web.Mvc

Namespace sample
    Class QueryDataClass
        Public Property query As String
    End Class

    Class SqlConstant
        Inherits Controller

        Public Sub Run(ByVal input As String)
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

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [Ignore("Copy structure state when assigned to new variable")]
        [TestMethod]
        public async Task StructReuseChangePropertyFromTaintedToSafe()
        {
            var cSharpTest = @"
using System.Data.SqlClient;
using System.Web.Mvc;

namespace sample
{
    struct QueryDataClass
    {
        public string query { get; set; }
    }

    class SqlConstant : Controller
    {
        public void Run(string input)
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
Imports System.Web.Mvc

Namespace sample
    Structure  QueryDataClass
        Public Property query As String
    End Structure

Class SqlConstant
    Inherits Controller

    Public Sub Run(ByVal input As String)
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

            await VerifyCSharpDiagnostic(cSharpTest, new [] {Expected, Expected, Expected }).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new[] { Expected, Expected, Expected }).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task ObjectReuseChangePropertyFromTaintedToSafe()
        {
            var cSharpTest = @"
using System.Data.SqlClient;
using System.Web.Mvc;

namespace sample
{
    class QueryDataClass
    {
        public string query { get; set; }
    }

    class SqlConstant : Controller
    {
        public void Run(string input)
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
Imports System.Web.Mvc

Namespace sample
    Class QueryDataClass
        Public Property query As String
    End Class

Class SqlConstant
    Inherits Controller

    Public Sub Run(ByVal input As String)
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

            await VerifyCSharpDiagnostic(cSharpTest, new[] { Expected, Expected }).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new[] { Expected, Expected }).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task VariableStateMerge()
        {
            var cSharpTest = @"
namespace sample
{
    class EventArgs
    {
        public Items Item = null;
    }

    class Items
    {
        public bool Checked = false;
    }

    class SqlConstant
    {
        protected void OnDrawItem (EventArgs e)
        {
            e.Item.Checked = true;
            e.Item.Checked = false;
        }
    }
}
";

            var visualBasicTest = @"
Namespace sample
    Friend Class EventArgs
        Public Item As Items = Nothing
    End Class

    Friend Class Items
        Public Checked As Boolean = False
    End Class

    Friend Class SqlConstant
        Protected Sub OnDrawItem(ByVal e As EventArgs)
            e.Item.Checked = True
            e.Item.Checked = False
        End Sub
    End Class
End Namespace
";

            // should be no exception
            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
            var auditConfig = await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false);
            await VerifyCSharpDiagnostic(cSharpTest, null, auditConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, auditConfig).ConfigureAwait(false);
        }

        [DataTestMethod]
        [DataRow("public ",    "",         true)]
        [DataRow("private ",   "",         false)]
        [DataRow("protected ", "",         false)]
        [DataRow("public ",    "static ",  true)]
        [DataRow("private ",   "static ",  false)]
        [DataRow("protected ", "static ",  false)]
        public async Task TaintSourceClass(string @public, string @static, bool warn)
        {
            var cSharpTest = $@"
class Test
{{
    public Test(string input)
    {{
        Sink(input);
    }}

    {@public}{@static}void Run(string input)
    {{
        Sink(input);
    }}

    private static void Sink(string input) {{}}
}}
";

            var visualBasicTest = $@"
Class Test
    Public Sub New(ByVal input As String)
        Sink(input)
    End Sub

    {@public.CSharpReplaceToVBasic()}{@static.CSharpReplaceToVBasic()}Sub Run(input As System.String)
        Sink(input)
    End Sub

    Private Shared Sub Sink(ByVal input As String)
    End Sub
End Class
";

            var testConfig = @"
TaintEntryPoints:
  MyKey:
    ClassName: Test

Behavior:
  MyKey:
    ClassName: Test
    Name: Sink
    Method:
      InjectableArguments: [SCS0026: 0]
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            if (warn)
            {
                await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            }
        }

        [DataTestMethod]
        [DataRow("public ",    "",        true)]
        [DataRow("private ",   "",        true)]
        [DataRow("protected ", "",        true)]
        [DataRow("public ",    "static ", true)]
        [DataRow("private ",   "static ", true)]
        [DataRow("protected ", "static ", true)]
        public async Task TaintSourceMethod(string @public, string @static, bool warn)
        {
            var cSharpTest = $@"
class Test
{{
    public Test(string input)
    {{
        Sink(input);
    }}

    {@public}{@static}void Run(string input)
    {{
        Sink(input);
    }}

    private static void Sink(string input) {{}}
}}
";

            var visualBasicTest = $@"
Class Test
    Public Sub New(ByVal input As String)
        Sink(input)
    End Sub

    {@public.CSharpReplaceToVBasic()}{@static.CSharpReplaceToVBasic()}Sub Run(input As System.String)
        Sink(input)
    End Sub

    Private Shared Sub Sink(ByVal input As String)
    End Sub
End Class
";

            var testConfig = @"
TaintEntryPoints:
  MyKey:
    ClassName: Test
    Name: Run

Behavior:
  MyKey:
    ClassName: Test
    Name: Sink
    Method:
      InjectableArguments: [SCS0026: 0]
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            if (warn)
            {
                await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            }
        }

        [DataTestMethod]
        [DataRow("input",                                             true)]
        [DataRow("Request.ToString()",                                false)]
        [DataRow("Request.AcceptTypes[0]",                            true)]
        [DataRow("Request.AnonymousID",                               true)]
        [DataRow("Request.ApplicationPath",                           false)]
        [DataRow("Request.AppRelativeCurrentExecutionFilePath",       false)]
        [DataRow("Request.Browser.ToString()",                        true)]
        [DataRow("Request.ClientCertificate.Issuer",                  true)]
        [DataRow("Request.ContentEncoding.ToString()",                false)]
        [DataRow("Request.ContentLength.ToString()",                  false)]
        [DataRow("Request.ContentType.ToString()",                    true)]
        [DataRow("Request.Cookies[\"auth\"].Value",                   true)]
        [DataRow("Request.CurrentExecutionFilePath",                  false)]
        [DataRow("Request.CurrentExecutionFilePathExtension",         false)]
        [DataRow("Request.FilePath",                                  false)]
        [DataRow("Request.Files[0].FileName",                         true)]
        [DataRow("Request.Filter.ToString()",                         false)]
        [DataRow("Request.Form[\"id\"]",                              true)]
        [DataRow("Request.Headers[0]",                                true)]
        [DataRow("Request.HttpChannelBinding.ToString()",             false)]
        [DataRow("Request.HttpMethod",                                false)]
        [DataRow("Request.InputStream.ToString()",                    true)]
        [DataRow("Request.IsAuthenticated.ToString()",                false)]
        [DataRow("Request.IsLocal.ToString()",                        false)]
        [DataRow("Request.IsSecureConnection.ToString()",             false)]
        [DataRow("Request[\"id\"]",                                   true)]
        [DataRow("Request.LogonUserIdentity.ToString()",              false)]
        [DataRow("Request.Params[\"id\"]",                            true)]
        [DataRow("Request.Path",                                      false)]
        [DataRow("Request.PathInfo",                                  false)]
        [DataRow("Request.PhysicalApplicationPath",                   false)]
        [DataRow("Request.PhysicalPath",                              false)]
        [DataRow("Request.QueryString[\"id\"]",                       true)]
        [DataRow("Request.RawUrl",                                    true)]
        [DataRow("Request.ReadEntityBodyMode.ToString()",             false)]
        [DataRow("Request.RequestContext.HttpContext.ToString()",     true)]
        [DataRow("Request.RequestType",                               false)]
        [DataRow("Request.ServerVariables[\"ALL_HTTP\"]",             true)]
        [DataRow("Request.TimedOutToken.ToString()",                  false)]
        [DataRow("Request.TlsTokenBindingInfo.ToString()",            false)]
        [DataRow("Request.TotalBytes.ToString()",                     false)]
        [DataRow("Request.Unvalidated.ToString()",                    true)]
        [DataRow("Request.Url.ToString()",                            true)]
        [DataRow("Request.UrlReferrer.ToString()",                    true)]
        [DataRow("Request.UserAgent",                                 true)]
        [DataRow("Request.UserHostAddress",                           true)]
        [DataRow("Request.UserHostName",                              true)]
        [DataRow("Request.UserLanguages[0]",                          true)]
        [DataRow("Request.BinaryRead(100).ToString()",                true)]
        [DataRow("Request.GetBufferedInputStream().ToString()",       true)]
        [DataRow("Request.GetBufferlessInputStream(true).ToString()", true)]
        [DataRow("Request.GetBufferlessInputStream().ToString()",     true)]
        public async Task TaintSourceController(string payload, bool warn)
        {
            var cSharpTest = $@"
using System.Web.Mvc;

class MyController : Controller
{{
    public void Run(string input)
    {{
        Sink({payload});
    }}

    private void Sink(string input) {{}}
}}
";

            payload = payload.CSharpReplaceToVBasic();
            var visualBasicTest = $@"
Imports System.Web.Mvc

Friend Class MyController
    Inherits Controller

    Public Sub Run(ByVal input As String)
        Sink({payload})
    End Sub

    Private Sub Sink(ByVal input As String)
    End Sub
End Class

";

            var testConfig = @"
Behavior:
  MyKey:
    ClassName: MyController
    Name: Sink
    Method:
      InjectableArguments: [SCS0026: 0]
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            if (warn)
            {
                await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            }
        }

        [DataTestMethod]
        [DataRow("input",                                                                     true)]
        [DataRow("Request.ToString()",                                                        false)]
        [DataRow("Request.Body.ToString()",                                                   true)]
        [DataRow("Request.ContentLength.ToString()",                                          false)]
        [DataRow("Request.ContentType.ToString()",                                            true)]
        [DataRow("Request.Cookies[\"auth\"]",                                                 true)]
        [DataRow("Request.Form[\"id\"]",                                                      true)]
        [DataRow("Request.HasFormContentType.ToString()",                                     false)]
        [DataRow("Request.Headers[\"x\"]",                                                    true)]
        [DataRow("Request.Host.Host",                                                         true)]
        [DataRow("Request.HttpContext.Items[0].ToString()",                                   true)]
        [DataRow("Request.IsHttps.ToString()",                                                false)]
        [DataRow("Request.Method",                                                            false)]
        [DataRow("Request.Path",                                                              false)]
        [DataRow("Request.PathBase",                                                          false)]
        [DataRow("Request.Protocol",                                                          false)]
        [DataRow("Request.Query[\"id\"]",                                                     true)]
        [DataRow("Request.QueryString.Value",                                                 true)]
        [DataRow("Request.Scheme",                                                            false)]
        [DataRow("Request.ReadFormAsync(System.Threading.CancellationToken.None).ToString()", true)]
        public async Task TaintSourceControllerCore(string payload, bool warn)
        {
            var cSharpTest = $@"
using Microsoft.AspNetCore.Mvc;

class MyController : Controller
{{
    public void Run(string input)
    {{
        Sink({payload});
    }}

    private void Sink(string input) {{}}
}}
";

            payload = payload.CSharpReplaceToVBasic();
            var visualBasicTest = $@"
Imports Microsoft.AspNetCore.Mvc

Friend Class MyController
    Inherits Controller

    Public Sub Run(ByVal input As String)
        Sink({payload})
    End Sub

    Private Sub Sink(ByVal input As String)
    End Sub
End Class

";

            var testConfig = @"
Behavior:
  MyKey:
    ClassName: MyController
    Name: Sink
    Method:
      InjectableArguments: [SCS0026: 0]
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            if (warn)
            {
                await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            }
        }

        [TestMethod]
        public async Task TaintInitializer()
        {
            var cSharpTest = @"
class MyClass
{
    private void Foo(string input)
    {
        var x = new { Data = Sink(input) };
    }

    private string Sink(string input) { return input; }
}
";

            var visualBasicTest = $@"
Class [MyClass]
    Private Sub Foo(ByVal input As String)
        Dim x = New With {{ .Data = Sink(input) }}
    End Sub

    Private Function Sink(ByVal input As String) As String
        Return input
    End Function
End Class
";

            var testConfig = @"
AuditMode: true

Behavior:
  MyKey:
    ClassName: MyClass
    Name: Sink
    Method:
      InjectableArguments: [SCS0026: 0]
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task TaintNameof()
        {
            var cSharpTest = @"
class MyClass
{
    private void Foo(string input)
    {
        Sink(nameof(input));
    }

    private void Sink(string input) {}
}
";

            var visualBasicTest = $@"
Class [MyClass]
    Private Sub Foo(ByVal input As String)
        Sink(NameOf(input))
    End Sub

    Private Sub Sink(ByVal input As String)
    End Sub
End Class
";

            var testConfig = @"
AuditMode: true

Behavior:
  MyKey:
    ClassName: MyClass
    Name: Sink
    Method:
      InjectableArguments: [SCS0026: 0]
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task TaintSourceConsole()
        {
            var cSharpTest = @"
using System;

class MyClass
{
    private void Foo()
    {
        Sink(Console.ReadLine());
    }

    private void Sink(string input) {}
}
";

            var visualBasicTest = $@"
Imports System

Class [MyClass]
    Private Sub Foo()
        Sink(Console.ReadLine())
    End Sub

    Private Sub Sink(ByVal input As String)
    End Sub
End Class
";

            var testConfig = @"
Behavior:
  MyKey:
    ClassName: MyClass
    Name: Sink
    Method:
      InjectableArguments: [SCS0026: 0]
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task TaintSourceMain()
        {
            var cSharpTest = @"
class MyClass
{
    private static void Main(string[] args)
    {
        Sink(args[1]);
    }

    private static void Sink(string input) {}
}
";

            var visualBasicTest = $@"
Class [MyClass]
    Private Shared Sub Main(ByVal args As String())
        Sink(args(1))
    End Sub

    Private Shared Sub Sink(ByVal input As String)
    End Sub
End Class
";

            var testConfig = @"
Behavior:
  MyKey:
    ClassName: MyClass
    Name: Sink
    Method:
      InjectableArguments: [SCS0026: 0]
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [DataTestMethod]
        [DataRow("HtmlTextArea",            "m_control.Value",                  true)]
        [DataRow("HtmlInputText",           "m_control.Value",                  true)]
        [DataRow("HtmlInputHidden",         "m_control.Value",                  true)]
        [DataRow("HtmlInputGenericControl", "m_control.Value",                  true)]
        [DataRow("HtmlInputFile",           "m_control.Value",                  true)]
        [DataRow("HtmlInputFile",           "m_control.PostedFile.FileName",    true)]
        [DataRow("FileUpload",              "m_control.FileName",               true)]
        [DataRow("FileUpload",              "m_control.FileContent.ToString()", true)]
        [DataRow("FileUpload",              "m_control.PostedFile.FileName",    true)]
        [DataRow("HiddenField",             "m_control.Value",                  true)]
        [DataRow("TextBox",                 "m_control.Text",                   true)]
        public async Task TaintSourceWebForms(string type, string payload, bool warn)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System.Web.UI.HtmlControls;
    using System.Web.UI.WebControls;
    using System.Web.UI;
#pragma warning restore 8019

class MyPage : Page
{{
    private {type} m_control = new {type}();

    public void Run()
    {{
        Sink({payload});
    }}

    private void Sink(string input) {{}}
}}
";

            payload = payload.CSharpReplaceToVBasic();
            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System.Web.UI.HtmlControls
    Imports System.Web.UI.WebControls
    Imports System.Web.UI
#Enable Warning BC50001

Friend Class MyPage
    Inherits Page

    Private m_control As {type} = New {type}()

    Public Sub Run()
        Sink({payload})
    End Sub

    Private Sub Sink(ByVal input As String)
    End Sub
End Class
";

            var testConfig = @"
Behavior:
  MyKey:
    ClassName: MyPage
    Name: Sink
    Method:
      InjectableArguments: [SCS0026: 0]
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            if (warn)
            {
                await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            }
        }

        [TestMethod]
        public async Task TaintBehavior()
        {
            var cSharpTest = @"
namespace sample
{
    class Parameters
    {
        public string[] Params { get; }
    }

    class HttpRequest
    {
        public Parameters GetParams() { return null; }
    }

    class HttpResponse
    {
        public void Write(string x) {}
    }

    class Test
    {
        private static HttpRequest  Request  = null;
        private static HttpResponse Response = null;

        public static void Run()
        {
            var userInput = Request.GetParams().Params[0].ToString();
            Response.Write(userInput);
        }
    }
}
";

var visualBasicTest = @"
Namespace sample
    Class Parameters
        Public ReadOnly Property Params As String()
    End Class

    Class HttpRequest
        Public Function GetParams() As Parameters
            Return Nothing
        End Function
    End Class

    Class HttpResponse
        Public Sub Write(ByVal x As String)
        End Sub
    End Class

    Class Test
        Private Shared Request  As HttpRequest  = Nothing
        Private Shared Response As HttpResponse = Nothing

        Public Shared Sub Run()
            Dim userInput = Request.GetParams().Params(0).ToString()
            Response.Write(userInput)
        End Sub
    End Class
End Namespace
";
            var expected = new DiagnosticResult
            {
                Id       = "SCS0029",
                Severity = DiagnosticSeverity.Warning
            };

            var testConfig = @"
Behavior:
  MyKey:
    Namespace: sample
    ClassName: HttpResponse
    Name: Write
    Method:
      InjectableArguments: [SCS0029: 0]

  sample_HttpRequest:
    Namespace: sample
    ClassName: HttpRequest
    Method:
      Returns:
        Taint: Tainted
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);

            testConfig = @"
Behavior:
  MyKey:
    Namespace: sample
    ClassName: HttpResponse
    Name: Write
    Method:
      InjectableArguments: [SCS0029: 0]

  sample_HttpRequest:
    Namespace: sample
    ClassName: HttpRequest
    Method:
      Returns:
        Taint: Tainted
";

            optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task EnumTaint()
        {
            var cSharpTest = @"
class Test
{
    private enum MyEnum
    {
        Val = 1
    }

    public void Run()
    {
        Sink(MyEnum.Val);
    }

    private static void Sink(MyEnum input) {}
}
";

            var visualBasicTest = @"
Friend Class Test
    Private Enum MyEnum
        Val = 1
    End Enum

    Public Sub Run()
        Sink(MyEnum.Val)
    End Sub

    Private Shared Sub Sink(ByVal input As MyEnum)
    End Sub
End Class

";

            var testConfig = @"
AuditMode: true

Behavior:
  MyKey:
    ClassName: Test
    Name: Sink
    Method:
      InjectableArguments: [SCS0026: 0]
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestMethod]
        [TestCategory("Safe")]
        public async Task ExtensionMethodWithRef()
        {
            var cSharpTest = @"
class Test
{
    public void Foo(string bar)
    {
        int c = 1;
        bar.ExtensionMethodRef(ref c);
        int d;
        bar.ExtensionMethodOut(out d);
    }
}

static class Exts
{
    public static void ExtensionMethodRef(this string str, ref int a)
    {
        a = str.Length;
    }

    public static void ExtensionMethodOut(this string str, out int a)
    {
        a = str.Length;
    }
}
";

            var vbTest = @"
Imports System.Runtime.CompilerServices
Imports System.Runtime.InteropServices

Class Test
    Public Sub Foo(ByVal bar As String)
        Dim c As Integer = 1
        bar.ExtensionMethodRef(c)
        Dim d As Integer
        bar.ExtensionMethodOut(d)
    End Sub
End Class

Module Exts
    <Extension()>
    Sub ExtensionMethodRef(ByVal str As String, ByRef a As Integer)
        a = str.Length
    End Sub

    <Extension()>
    Sub ExtensionMethodOut(ByVal str As String, <Out> ByRef a As Integer)
        a = str.Length
    End Sub
End Module
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(vbTest).ConfigureAwait(false);
        }

        [TestMethod]
        [TestCategory("Detect")]
        public async Task ExtensionMethodWithPostCondition()
        {
            var cSharpTest = @"
class Test
{
    public void Foo(string userInput)
    {
        string foo = """";
        userInput.ExtensionMethodRef(ref foo);
        Sink(foo);
    }

    private void Sink(string input)
    {
    }
}

static class Exts
{
    public static void ExtensionMethodRef(this string str, ref string a)
    {
        a += str;
    }
}
";

            var vbTest = @"
Imports System.Runtime.CompilerServices

Class Test
    Public Sub Foo(ByVal userInput As String)
        Dim foo As String = ""
        ""
        userInput.ExtensionMethodRef(foo)
        Sink(foo)
    End Sub

    Private Sub Sink(ByVal input As String)
    End Sub
End Class

Module Exts
    <Extension()>
    Sub ExtensionMethodRef(ByVal str As String, ByRef a As String)
        a += str
    End Sub
End Module
";

            var testConfig = @"
TaintEntryPoints:
  Test:
    ClassName: Test

Behavior:
  123:
    ClassName: Exts
    Name: ExtensionMethodRef
    Method:
      1:
        TaintFromArguments: [0]

  MyKey:
    ClassName: Test
    Name: Sink
    Method:
      InjectableArguments: [SCS0026: 0]
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(vbTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestMethod]
        [TestCategory("Detect")]
        public async Task ExtensionMethodWithPostCondition2()
        {
            var cSharpTest = @"
class Test
{
    public void Foo(string userInput)
    {
        string foo = """";
        userInput.ExtensionMethodRef(ref foo, userInput);
        Sink(foo);
    }

    private void Sink(string input)
    {
    }
}

static class Exts
{
    public static void ExtensionMethodRef(this string str, ref string a, string b)
    {
        a += b;
    }
}
";

            var vbTest = @"
Imports System.Runtime.CompilerServices

Class Test
    Public Sub Foo(ByVal userInput As String)
        Dim foo As String = ""
        ""
        userInput.ExtensionMethodRef(foo, userInput)
        Sink(foo)
    End Sub

    Private Sub Sink(ByVal input As String)
    End Sub
End Class

Module Exts
    <Extension()>
    Sub ExtensionMethodRef(ByVal str As String, ByRef a As String, ByVal b As String)
        a += b
    End Sub
End Module
";

            var testConfig = @"
TaintEntryPoints:
  Test:
    ClassName: Test

Behavior:
  123:
    ClassName: Exts
    Name: ExtensionMethodRef
    Method:
      1:
        TaintFromArguments: [2]

  MyKey:
    ClassName: Test
    Name: Sink
    Method:
      InjectableArguments: [SCS0026: 0]
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(vbTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestMethod]
        [TestCategory("Detect")]
        public async Task ExtensionMethodWithParams()
        {
            var cSharpTest = @"
class Test
{
    public void Foo(string userInput)
    {
        string foo = """";
        Sink(foo.ExtensionMethod(foo, foo, userInput));
    }

    private void Sink(string input)
    {
    }
}

static class Exts
{
    public static string ExtensionMethod(this string str, params string[] args)
    {
        return args[0];
    }
}
";

            var vbTest = @"
Imports System.Runtime.CompilerServices

Class Test
    Public Sub Foo(ByVal userInput As String)
        Dim foo As String = ""
        ""
        Sink(foo.ExtensionMethod(foo, foo, userInput))
    End Sub

    Private Sub Sink(ByVal input As String)
    End Sub
End Class

Module Exts
    <Extension()>
    Function ExtensionMethod(ByVal str As String, ParamArray args As String()) As String
        Return args(0)
    End Function
End Module
";

            var testConfig = @"
TaintEntryPoints:
  Test:
    ClassName: Test

Behavior:
  123:
    ClassName: Exts
    Name: ExtensionMethod
    Method:
      Returns:
        TaintFromArguments: [1]

  MyKey:
    ClassName: Test
    Name: Sink
    Method:
      InjectableArguments: [SCS0026: 0]
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(vbTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
        }
    }
}
