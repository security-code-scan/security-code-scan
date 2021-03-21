using System.Collections.Generic;
using System.Reflection;
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
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string _)
        {
            return new[] { new CsrfTokenDiagnosticAnalyzer() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(System.Web.Mvc.HttpPostAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.HttpPostAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.Controller).Assembly.Location),
            MetadataReference.CreateFromFile(Assembly.Load("netstandard, Version=2.0.0.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51")
                                                     .Location)
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
CsrfCheck:
  Test:
    Name: ASP.NET MVC
    RequiredAttributes:
      Include:
        - Type: VulnerableApp.TestAttribute
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
CsrfCheck:
  Test:
    Name: ASP.NET Core MVC
    RequiredAttributes:
      Include:
        - Type: VulnerableApp.TestAttribute
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task AddCustomCsrfAttributeWithCondition()
        {
            var cSharpTest = @"
using System;
using System.Web.Mvc;

namespace VulnerableApp
{
    [System.AttributeUsage(System.AttributeTargets.Method)]
    public class TestAttribute : Attribute
    {
        public HttpVerbs AppliesFor { get; private set; }
        public bool PreventsCsrf { get; private set; }

        public TestAttribute(HttpVerbs appliesFor, bool preventsCsrf)
        {
            AppliesFor = appliesFor;
            PreventsCsrf = preventsCsrf;
        }
    }

    public class TestController : Controller
    {
        [TestAttribute(HttpVerbs.Post, true)]
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
    <AttributeUsage(System.AttributeTargets.Method)>
    Public Class TestAttribute
        Inherits Attribute

    Public AppliesFor As HttpVerbs
    Public PreventsCsrf As Boolean

    Sub New(appliesFor As HttpVerbs, preventsCsrf As Boolean)
        AppliesFor = appliesFor
        PreventsCsrf = preventsCsrf
    End Sub

    End Class

    Public Class TestController
        Inherits Controller

        <TestAttribute(HttpVerbs.Post, True)>
        Public Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";

            var testConfig = @"
CsrfCheck:
  Test:
    Name: ASP.NET MVC
    Method:
      Attributes:
        Include:
          - Type: VulnerableApp.TestAttribute
            Condition:
              - {0: {Value: 2}}
    RequiredAttributes:
      Include:
        - Type: VulnerableApp.TestAttribute
          Condition:
            - {1: {Value: true}}
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
        }
    }
}
