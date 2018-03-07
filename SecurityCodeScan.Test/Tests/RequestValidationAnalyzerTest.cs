using System.Collections.Generic;
using System.Threading.Tasks;
using System.Web.Mvc;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Test.Helpers;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test
{
    [TestClass]
    public class RequestValidationAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new[] { new RequestValidationAnalyzer() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(ValidateInputAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Web.HttpRequestBase).Assembly.Location),
#pragma warning disable 618
            MetadataReference.CreateFromFile(typeof(System.Web.Helpers.Validation).Assembly.Location)
#pragma warning restore 618
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestMethod]
        public async Task DetectAnnotationValidateInput()
        {
            var cSharpTest = @"
using System.Web.Mvc;

namespace VulnerableApp
{
    public class TestController
    {
        [HttpPost]
        [ValidateInput(false)]
        public ActionResult ControllerMethod(string input) {
            return null;
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Web.Mvc

Namespace VulnerableApp
    Public Class TestController
        <HttpPost> _
        <ValidateInput(False)> _
        Public Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0017",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectUnvalidatedProperty()
        {
            var cSharpTest = @"
using System.Web.Mvc;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [HttpPost]
        public ActionResult ControllerMethod(string input) {
            var test = Request.Unvalidated;
            return null;
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Web.Mvc

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller
        <HttpPost> _
        Public Function ControllerMethod(input As String) As ActionResult
            Dim test = Request.Unvalidated
            Return Nothing
        End Function
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id = "SCS0017",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 10, 32)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 9, 32)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectUnvalidatedMethod()
        {
            var cSharpTest = @"
using System.Web.Mvc;
using System.Web.Helpers;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [HttpPost]
        public ActionResult ControllerMethod(string input) {
            var test = Request.Unvalidated();
            return null;
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Web.Mvc
Imports System.Web.Helpers

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller
        <HttpPost> _
        Public Function ControllerMethod(input As String) As ActionResult
#Disable Warning BC40000
            Dim test = Validation.Unvalidated(Request)
#Enable Warning BC40000
            Return Nothing
        End Function
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id = "SCS0017",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 11, 32)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test.vb", 11, 35)).ConfigureAwait(false); 
        }

        [TestMethod]
        public async Task IgnoreUnrelatedUnvalidatedMethod()
        {

            var cSharpTest = @"
using System.Web.Mvc;

namespace VulnerableApp
{
    public class TestController
    {
        public void Unvalidated(){
        }
        [HttpPost]
        public ActionResult ControllerMethod(string input) {
            Unvalidated();
            return null;
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Web.Mvc

Namespace VulnerableApp
    Public Class TestController
        Public Sub Unvalidated()
        End Sub
        <HttpPost> _
        Public Function ControllerMethod(input As String) As ActionResult
            Unvalidated()
            Return Nothing
        End Function
    End Class
End Namespace
";


            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task IgnoreUnrelatedStaticUnvalidatedMethod()
        {

            var cSharpTest = @"
using System.Web.Mvc;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        public class Test
        {
            public static void Unvalidated(){
            }
        }
        [HttpPost]
        public ActionResult ControllerMethod(string input) {
            Test.Unvalidated();
            return null;
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Web.Mvc

Namespace VulnerableApp
    Public Class TestController
        Class Test
            Public Shared Sub Unvalidated()
            End Sub
        End Class
        <HttpPost> _
        Public Function ControllerMethod(input As String) As ActionResult
            Test.Unvalidated()
            Return Nothing
        End Function
    End Class
End Namespace
";


            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectAllowHtmlAttribute()
        {
            var cSharpTest = @"
using System.Web.Mvc;

namespace VulnerableApp
{
    public class TestModel
    {
        [AllowHtml]
        public string TestProperty { get; set; }
    }
}
";

            var visualBasicTest = @"
Imports System.Web.Mvc

Namespace VulnerableApp
    Public Class TestModel

        <AllowHtml>
        Public Property TestProperty As String
            Get
                Return ""Test""
            End Get
            Set(value As String)
            End Set
        End Property
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id = "SCS0017",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 8, 10)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 7, 10)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectAllowHtmlAttributeWithNamespace()
        {
            var cSharpTest = @"
namespace VulnerableApp
{
    public class TestModel
    {
        [System.Web.Mvc.AllowHtml]
        public string TestProperty { get; set; }
    }
}
";

            var visualBasicTest = @"
Namespace VulnerableApp
    Public Class TestModel

        <System.Web.Mvc.AllowHtml>
        Public Property TestProperty As String
            Get
                Return ""Test""
            End Get
            Set(value As String)
            End Set
        End Property
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id = "SCS0017",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 6, 10)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 5, 10)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectInlineAllowHtmlAttribute()
        {
            var cSharpTest = @"
using System.Web.Mvc;

namespace VulnerableApp
{
    public class Test : System.Attribute
    {
    }

    public class TestModel
    {
        [Test, AllowHtml]
        public string TestProperty { get; set; }
    }
}
";

            var visualBasicTest = @"
Imports System.Web.Mvc

Namespace VulnerableApp
    Public Class Test
        Inherits System.Attribute
    End Class

    Public Class TestModel
        <Test, AllowHtml>
        Public Property TestProperty As String
            Get
                Return ""Test""
            End Get
            Set(value As String)
            End Set
        End Property
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id = "SCS0017",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 12, 16)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 10, 16)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectAllowHtmlAttributeAfterAtrributeContainingAllowHtmlInName()
        {
            var cSharpTest = @"
using System.Web.Mvc;

namespace VulnerableApp
{
    public class TestAllowHtmlTest : System.Attribute
    {
    }

    public class TestModel
    {
        [TestAllowHtmlTest]
        [AllowHtml]
        public string TestProperty { get; set; }
    }
}
";

            var visualBasicTest = @"
Imports System.Web.Mvc

Namespace VulnerableApp
    Public Class TestAllowHtmlTest
        Inherits System.Attribute
    End Class

    Public Class TestModel
        <TestAllowHtmlTest>
        <AllowHtml>
        Public Property TestProperty As String
            Get
                Return ""Test""
            End Get
            Set(value As String)
            End Set
        End Property
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id = "SCS0017",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 13, 10)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 11, 10)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task IgnoreUnrelatedAllowHtmlAttribute()
        {
            var cSharpTest = @"
namespace VulnerableApp
{
    public class AllowHtml : System.Attribute
    {
    }

    public class TestModel
    {
        [VulnerableApp.AllowHtml]
        public string TestProperty { get; set; }
    }
}
";

            var visualBasicTest = @"
Namespace VulnerableApp
    Public Class AllowHtml
        Inherits System.Attribute
    End Class

    Public Class TestModel
        <VulnerableApp.AllowHtml>
        Public Property TestProperty As String
            Get
                Return ""Test""
            End Get
            Set(value As String)
            End Set
        End Property
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }
    }
}
