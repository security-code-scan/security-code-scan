using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test.Config
{
    [TestClass]
    public class TaintAnalyzisConfigurationTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            return new DiagnosticAnalyzer[] { new TaintAnalyzerCSharp(), new TaintAnalyzerVisualBasic() };
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task RemoveSink()
        {
            var cSharpTest = @"
using System.Data.SqlClient;

namespace sample
{
    class Test
    {
        public Test(string sql)
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
        Public Sub New(sql As String)
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
Sinks:
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
namespace sample
{
    class Test
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
Namespace sample
    Class Test
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
Sinks:
  MyKey:
    Namespace: sample
    ClassName: Test
    Member: method
    Name: Vulnerable
    InjectableArguments: [0]
    Locale: SCS0001
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

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);

            var testConfig = @"
Behavior:
  MemoryStream_Constructor0:
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
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

namespace sample
{
    class Test
    {
        public static string Safe (string param)
        {
            return param;
        }

        static void TestMethod()
        {
            var testString = ""test"";
            new SqlCommand(Safe(testString));
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Data.SqlClient

Namespace sample
    Class Test
        Public Shared Function Safe(param As String) As String
            Return param
        End Function
        Private Sub TestMethod()
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

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);

            var testConfig = @"
Behavior:
  MyKey:
    Namespace: sample
    ClassName: Test
    Member: method
    Name: Safe
    TaintFromArguments: [-1]
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task TwoDifferentProjectConfigs()
        {
            var cSharpTest = @"
namespace sample
{
    class Test
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
Namespace sample
    Class Test
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
Sinks:
  MyKey:
    Namespace: sample
    ClassName: Test
    Member: method
    Name: Vulnerable
    InjectableArguments: [0]
    Locale: SCS0001
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
Sinks:
  MyKey:
    Namespace: sample
    ClassName: Test
    Member: method
    Name: Vulnerable
    InjectableArguments: [0]
    Locale: SCS0001

Behavior:
  MyKey:
    Namespace: sample
    ClassName: Test
    Member: method
    Name: Safe
    TaintFromArguments: [-1]
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

namespace sample
{
    class Test
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

Namespace sample
    Class Test
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

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);

            var testConfig = @"
ConstantFields: [sample.Test.Safe]
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
        }
    }
}
