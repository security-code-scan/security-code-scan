using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test.Config
{
    [TestClass]
    public class TaintAnalysisConfigurationTest : DiagnosticVerifier
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
            MetadataReference.CreateFromFile(typeof(System.Web.Mvc.Controller).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestCategory("Safe")]
        [TestMethod]
        public async Task RemoveSink()
        {
            var cSharpTest = @"
using System.Data.SqlClient;
using System.Web.Mvc;

namespace sample
{
    class Test : Controller
    {
        public void Foo(string sql)
        {
            new SqlCommand(sql);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Data.SqlClient
Imports System.Web.Mvc

Namespace sample
    Class Test
        Inherits Controller

        Public Sub Foo(sql As String)
            Dim com As New SqlCommand(sql)
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

            var testConfig = @"
Behavior:
  sqlcommand_constructor:
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task AddSink()
        {
            var cSharpTest = @"
using System.Web.Mvc;

namespace sample
{
    class Test : Controller
    {
        public void Vulnerable(string param)
        {
        }

        public void TestMethod(string param)
        {
            Vulnerable(param);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Web.Mvc

Namespace sample
    Class Test
        Inherits Controller

        Public Sub Vulnerable(param As String)
        End Sub

        Public Sub TestMethod(param As String)
            Vulnerable(param)
        End Sub

    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);

            var testConfig = @"
Behavior:
  MyKey:
    Namespace: sample
    ClassName: Test
    Name: Vulnerable
    Method:
      InjectableArguments: [SCS0001: 0]
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            var expected = new DiagnosticResult
            {
                Id       = "SCS0001",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task RemoveBehavior()
        {
            var cSharpTest = @"
using System.Xml.Serialization;
using System.IO;

namespace sample
{
    class Test
    {
        static void TestMethod()
        {
            var formatter = new XmlSerializer(typeof(Test));
            formatter.Deserialize(new MemoryStream());
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Xml.Serialization
Imports System.IO

Namespace sample
    Class Test
        Private Sub TestMethod()
            Dim formatter = New XmlSerializer(GetType(Test))
            formatter.Deserialize(new MemoryStream())
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
AuditMode: true
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);

            testConfig = @"
AuditMode: true

Behavior:
  MemoryStream_Constructor0:
";

            optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            var expected = new DiagnosticResult
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task AddBehavior()
        {
            var cSharpTest = @"
using System.Data.SqlClient;
using System.Web.Mvc;

namespace sample
{
    class Test : Controller
    {
        public string Safe (string param)
        {
            return param;
        }

        public void TestMethod()
        {
            var testString = ""test"";
            new SqlCommand(Safe(testString));
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Web.Mvc
Imports System.Data.SqlClient

Namespace sample
    Class Test
        Inherits Controller

        Public Function Safe(param As String) As String
            Return param
        End Function

        Public Sub TestMethod()
            Dim testString = ""test""
            Dim com As New SqlCommand(Safe(testString))
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
AuditMode: true
";
            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);

            testConfig = @"
AuditMode: true

Behavior:
  MyKey:
    Namespace: sample
    ClassName: Test
    Name: Safe
    Method:
      Returns:
        Taint: Safe
";

            optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task TwoDifferentProjectConfigs()
        {
            var cSharpTest = @"
using System.Web.Mvc;

namespace sample
{
    class Test : Controller
    {
        public static string Safe (string param)
        {
            return param;
        }

        public void Vulnerable(string param)
        {
        }

        public void TestMethod(string param)
        {
            Vulnerable(param);
            Vulnerable(Safe(""test""));
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Web.Mvc

Namespace sample
    Class Test
        Inherits Controller

        Public Shared Function Safe(param As String) As String
            Return param
        End Function

        Public Sub Vulnerable(param As String)
        End Sub

        Public Sub TestMethod(param As String)
            Vulnerable(param)
            Vulnerable(Safe(""test""))
        End Sub

    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);

            var testConfig = @"
AuditMode: true

Behavior:
  MyKey:
    Namespace: sample
    ClassName: Test
    Name: Vulnerable
    Method:
      InjectableArguments: [SCS0001: 0]
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            var expected = new DiagnosticResult
            {
                Id       = "SCS0001",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, new []{expected, expected}, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new[] { expected, expected }, optionsWithProjectConfig).ConfigureAwait(false);

            testConfig = @"
AuditMode: true

Behavior:
  MyKey1:
    Namespace: sample
    ClassName: Test
    Name: Vulnerable
    Method:
      InjectableArguments: [SCS0001: 0]

  MyKey2:
    Namespace: sample
    ClassName: Test
    Name: Safe
    Method:
      Returns:
        Taint: Safe
";

            optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task AddConstantValue()
        {
            var cSharpTest = @"
using System.Data.SqlClient;
using System.Web.Mvc;

namespace sample
{
    class Test : Controller
    {
        public static readonly string Safe = ""Safe"";

        static void TestMethod()
        {
            new SqlCommand(Safe);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Data.SqlClient
Imports System.Web.Mvc

Namespace sample
    Class Test
        Inherits Controller

        Public Shared ReadOnly Safe As String = ""Safe""

        Private Shared Sub TestMethod()
            Dim com As New SqlCommand(Safe)
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
AuditMode: true
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);

            testConfig = @"
AuditMode: true

ConstantFields: [sample.Test.Safe]
";

            optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DynamicArgument()
        {
            var cSharpTest = @"
class Test
{
    public void Action(string foo)
    {
        Method(foo);
    }

    private void Method(dynamic d)
    {

    }
}
";


            var testConfig = @"
TaintEntryPoints:
  Test:
    ClassName: Test

Behavior:
  DynamicMethod:
    ClassName: Test
    Name: Method
    Method:
      ArgTypes: ""(dynamic)""
      InjectableArguments: [SCS0001: 0]";

            var options = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            var cSharpExpected =
                new[]
                {
                    new DiagnosticResult
                    {
                        Id       = "SCS0001",
                        Severity = DiagnosticSeverity.Warning,
                    }.WithLocation(6, 16)
                };

            await VerifyCSharpDiagnostic(cSharpTest, cSharpExpected, options).ConfigureAwait(false);
            // there's not really an equivalent to dynamic in VB.NET, so no test for it
        }
    }
}
