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
    public class CsrfProtectionConfigurationTests : ConfigurationTest
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            return new DiagnosticAnalyzer[]{ new CoreCsrfTokenAnalyzer(), new MvcCsrfTokenAnalyzer() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(System.Web.Mvc.HttpPostAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.HttpPostAttribute).Assembly.Location),
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

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

    public class TestController
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
                Id       = CsrfTokenAnalyzer.DiagnosticId,
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 16, 29)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 14, 25)).ConfigureAwait(false);

            var testConfig = @"
CsrfProtectionAttributes:
  -  HttpMethodsNameSpace: System.Web.Mvc
     AntiCsrfAttribute: VulnerableApp.TestAttribute
";

            var optionsWithProjectConfig = await CreateAnalyzersOptionsWithConfig(testConfig).ConfigureAwait(false);

            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
        }

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

    public class TestController
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

            var visualBasicTest = $@"
Imports System
Imports Microsoft.AspNetCore.Mvc

Namespace VulnerableApp
    <AttributeUsage(System.AttributeTargets.Class Or System.AttributeTargets.Method)>
    Public Class TestAttribute
        Inherits Attribute
    End Class

    Public Class TestController
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
                Id       = CsrfTokenAnalyzer.DiagnosticId,
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 16, 29)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 14, 25)).ConfigureAwait(false);

            var testConfig = @"
CsrfProtectionAttributes:
  -  HttpMethodsNameSpace: Microsoft.AspNetCore.Mvc
     AntiCsrfAttribute: VulnerableApp.TestAttribute
";

            var optionsWithProjectConfig = await CreateAnalyzersOptionsWithConfig(testConfig).ConfigureAwait(false);

            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
        }
    }
}
