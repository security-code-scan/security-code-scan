using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test.Config
{
    [TestClass]
    public class CsrfProtectionConfigurationTests : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            if (language == LanguageNames.CSharp)
                return new DiagnosticAnalyzer[] { new CoreCsrfTokenAnalyzerCSharp(), new MvcCsrfTokenAnalyzerCSharp() };
            else
                return new DiagnosticAnalyzer[] { new CoreCsrfTokenAnalyzerVBasic(), new MvcCsrfTokenAnalyzerVBasic() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(System.Web.Mvc.HttpPostAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.HttpPostAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.Controller).Assembly.Location),
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestCategory("Safe")]
        [TestMethod]
        public async Task AddCustomCsrfAttributeForMvc()
        {
            var cSharpTest = @"
using System;
using System.Web.Mvc;

namespace VulnerableApp
{
    [System.AttributeUsage(System.AttributeTargets.Class | System.AttributeTargets.Method)]
    public class TestAttribute : Attribute
    {
    }

    public class TestController : Controller
    {
        [HttpPost]
        [TestAttribute]
        public ActionResult ControllerMethod(string input)
        {
            return null;
        }
    }
}
";

            var visualBasicTest = @"
Imports System
Imports System.Web.Mvc

Namespace VulnerableApp
    <System.AttributeUsage(System.AttributeTargets.Class Or System.AttributeTargets.Method)>
    Public Class TestAttribute
        Inherits Attribute
    End Class

    Public Class TestController
        Inherits Controller

        <HttpPost>
        <TestAttribute>
        Public Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = CsrfTokenDiagnosticAnalyzer.DiagnosticId,
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation(16, 29)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation(16, 25)).ConfigureAwait(false);

            var testConfig = @"
CsrfProtectionAttributes:
  -  HttpMethodsNameSpace: System.Web.Mvc
     AntiCsrfAttribute: VulnerableApp.TestAttribute
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task AddCustomCsrfAttributeForCore()
        {
            var cSharpTest = @"
using System;
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp
{
    [System.AttributeUsage(System.AttributeTargets.Class | System.AttributeTargets.Method)]
    public class TestAttribute : Attribute
    {
    }

    public class TestController : Controller
    {
        [HttpPost]
        [TestAttribute]
        public ActionResult ControllerMethod(string input)
        {
            return null;
        }
    }
}
";

            var visualBasicTest = @"
Imports System
Imports Microsoft.AspNetCore.Mvc

Namespace VulnerableApp
    <AttributeUsage(System.AttributeTargets.Class Or System.AttributeTargets.Method)>
    Public Class TestAttribute
        Inherits Attribute
    End Class

    Public Class TestController
        Inherits Controller

        <HttpPost>
        <TestAttribute>
        Public Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = CsrfTokenDiagnosticAnalyzer.DiagnosticId,
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation(16, 29)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation(16, 25)).ConfigureAwait(false);

            var testConfig = @"
CsrfProtectionAttributes:
  -  HttpMethodsNameSpace: Microsoft.AspNetCore.Mvc
     AntiCsrfAttribute: VulnerableApp.TestAttribute
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
        }
    }
}
