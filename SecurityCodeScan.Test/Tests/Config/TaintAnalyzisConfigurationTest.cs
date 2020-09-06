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
    public class TaintAnalysisConfigurationTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string _)
        {
            return new[] { new SqlInjectionTaintAnalyzer() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(System.Web.Mvc.Controller).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestCategory("Detect")]
        [TestMethod]
        public async Task RemoveSink()
        {
            var cSharpTest = @"
using System.Web.Mvc;

namespace sample
{
    public class TestController : Controller
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
    Public Class TestController
        Inherits Controller

        Public Sub Vulnerable(param As String)
        End Sub

        Public Sub TestMethod(param As String)
            Vulnerable(param)
        End Sub

    End Class
End Namespace
";

            var testConfig = @"
Sinks:
  - Type: sample.TestController
    TaintTypes:
      - SCS0002
    Methods:
      - Name: Vulnerable
        Arguments:
          - param
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            var expected = new DiagnosticResult
            {
                Id       = "SCS0002",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);

            testConfig = @"
Sinks:
  - Type: sample.TestController
    TaintTypes:
      - SCS0002
";

            optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
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
    public class TestController : Controller
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
    Public Class TestController
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
Sinks:
  - Type: sample.TestController
    TaintTypes:
      - SCS0002
    Methods:
    - Name: Vulnerable
      Arguments:
        - param
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            var expected = new DiagnosticResult
            {
                Id       = "SCS0002",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task AddTaintSource()
        {
            var cSharpTest = @"
using System.Data.SqlClient;
using System.Web.Mvc;

namespace sample
{
    public class TestController : Controller
    {
        public string Tainted ()
        {
            return """";
        }

        public void TestMethod()
        {
            new SqlCommand(Tainted());
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Web.Mvc
Imports System.Data.SqlClient

Namespace sample
    Public Class TestController
        Inherits Controller

        Public Function Tainted() As String
            Return """"
        End Function

        Public Sub TestMethod()
            Dim com As New SqlCommand(Tainted())
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);

            var expected = new DiagnosticResult
            {
                Id       = "SCS0002",
                Severity = DiagnosticSeverity.Warning,
            };

            var testConfig = @"
TaintSources:
  - Type: sample.TestController
    TaintTypes:
      - SCS0002
    Methods:
      - Tainted
";
            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task TwoDifferentProjectConfigs()
        {
            var cSharpTest = @"
using System.Web.Mvc;

namespace sample
{
    public class TestController : Controller
    {
        public static string Safe (string param)
        {
            return """";
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
    Public Class TestController
        Inherits Controller

        Public Shared Function Safe(param As String) As String
            Return """"
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

            // todo: review the test, why this is unused?
            var testConfig = @"
Sinks:
  - Type: sample.TestController
    TaintTypes:
      - SCS0002
    Methods:
    - Name: Vulnerable
      Arguments:
        - param
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);

            testConfig = @"
Sinks:
  - Type: sample.TestController
    TaintTypes:
      - SCS0002
    Methods:
    - Name: Vulnerable
      Arguments:
        - param

TaintSources:
  - Type: sample.TestController
    TaintTypes:
      - SCS0002
    Methods:
      - Tainted
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            var expected = new DiagnosticResult
            {
                Id       = "SCS0002",
                Severity = DiagnosticSeverity.Warning,
            };

            optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
        }
    }
}
