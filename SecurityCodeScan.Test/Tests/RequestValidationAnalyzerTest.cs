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
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            if (language == LanguageNames.CSharp)
                return new DiagnosticAnalyzer[] { new RequestValidationAnalyzerCSharp() };
            else
                return new DiagnosticAnalyzer[] { new RequestValidationAnalyzerVisualBasic() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(ValidateInputAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Web.HttpRequestBase).Assembly.Location),
#pragma warning disable 618
            MetadataReference.CreateFromFile(typeof(System.Web.Helpers.Validation).Assembly.Location)
#pragma warning restore 618
        };

        private DiagnosticResult Expected = new DiagnosticResult
        {
            Id       = "SCS0017",
            Severity = DiagnosticSeverity.Warning
        };

        private DiagnosticResult ExpectedWithMessage_ValidationIsDisabled = new DiagnosticResult
        {
            Id       = "SCS0017",
            Severity = DiagnosticSeverity.Warning,
            Message  = "Request validation is disabled."
        };

        private DiagnosticResult ExpectedWithMessage_ValidationIsDisabledInBaseClass = new DiagnosticResult
        {
            Id       = "SCS0017",
            Severity = DiagnosticSeverity.Warning,
            Message  = "Request validation disabled in base class."
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectValidateInputAttribute()
        {
            const string cSharpTest = @"
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

            const string visualBasicTest = @"
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

            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(9, 24)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(7, 24)).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectValidateInputAttribute2()
        {
            const string cSharpTest = @"
using System.Web.Mvc;
using VI = System.Web.Mvc.ValidateInputAttribute;

namespace VulnerableApp
{
    public class TestController
    {
        [HttpPost]
        [VI(false)]
        public ActionResult ControllerMethod(string input) {
            return null;
        }
    }
}
";

            const string visualBasicTest = @"
Imports System.Web.Mvc
Imports VI = System.Web.Mvc.ValidateInputAttribute

Namespace VulnerableApp
    Public Class TestController
        <HttpPost> _
        <VI(False)> _
        Public Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(10, 13)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(8, 13)).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectValidateInputAttributeOnClass()
        {
            const string cSharpTest = @"
using System.Web.Mvc;

namespace VulnerableApp
{
    [ValidateInput(false)]
    public class TestController
    {
        [HttpPost]
        public ActionResult ControllerMethod(string input) {
            return null;
        }
    }
}
";

            const string visualBasicTest = @"
Imports System.Web.Mvc

Namespace VulnerableApp
    <ValidateInput(False)> _
    Public Class TestController
        <HttpPost> _
        Public Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(6, 20)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(5, 20)).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectInlineValidateInputAttribute()
        {
            const string cSharpTest = @"
using System.Web.Mvc;

namespace VulnerableApp
{
    public class TestController
    {
        [HttpPost, ValidateInput(false)]
        public ActionResult ControllerMethod(string input) {
            return null;
        }
    }
}
";

            const string visualBasicTest = @"
Imports System.Web.Mvc

Namespace VulnerableApp
    Public Class TestController
        <HttpPost, ValidateInput(False)> _
        Public Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(8, 34)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(6, 34)).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectValidateInputAttributeWithNamespace()
        {
            const string cSharpTest = @"
using System.Web.Mvc;

namespace VulnerableApp
{
    public class TestController
    {
        [HttpPost]
        [System.Web.Mvc.ValidateInput(false)]
        public ActionResult ControllerMethod(string input) {
            return null;
        }
    }
}
";

            const string visualBasicTest = @"
Imports System.Web.Mvc

Namespace VulnerableApp
    Public Class TestController
        <HttpPost> _
        <System.Web.Mvc.ValidateInput(False)> _
        Public Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(9, 39)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(7, 39)).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectValidateInputAttributeWithContantEqualToFalse()
        {
            const string cSharpTest = @"
using System.Web.Mvc;

namespace VulnerableApp
{
    public class TestController
    {
        private const bool test = false;

        [HttpPost]
        [ValidateInput(test)]
        public ActionResult ControllerMethod(string input) {
            return null;
        }
    }
}
";

            const string visualBasicTest = @"
Imports System.Web.Mvc

Namespace VulnerableApp
    Public Class TestController
        Public Const test = False

        <HttpPost> _
        <ValidateInput(test)> _
        Public Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(11, 24)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(9, 24)).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task IgnoreUnrelatedValidateInputAttribute()
        {
            const string cSharpTest = @"
using System.Web.Mvc;

namespace VulnerableApp
{
    public class ValidateInput : System.Attribute
    {
        public ValidateInput(bool test){}
    }

    public class TestController
    {
        [HttpPost]
        [VulnerableApp.ValidateInput(false)]
        public ActionResult ControllerMethod(string input) {
            return null;
        }
    }
}
";

            const string visualBasicTest = @"
Imports System.Web.Mvc

Namespace VulnerableApp
    Public Class ValidateInput
        Inherits System.Attribute
        Public Sub New(test As Boolean)
        End Sub
    End Class

    Public Class TestController
        <HttpPost> _
        <VulnerableApp.ValidateInput(false)> _
        Public Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectValidateInputAttributeWasSetOnParentClass()
        {
            const string cSharpTest = @"
using System.Web.Mvc;

namespace VulnerableApp
{
    [ValidateInput(false)]
    public class TestControllerBase : Controller
    {
    }

    public class TestController : TestControllerBase
    {
        [HttpPost]
        public ActionResult ControllerMethod(string input) {
            return null;
        }
    }
}
";

            const string visualBasicTest = @"
Imports System.Web.Mvc

Namespace VulnerableApp
    <ValidateInput(false)>
    Public Class TestControllerBase
        Inherits Controller
    End Class

    Public Class TestController
        Inherits TestControllerBase

        <HttpPost> _
        Public Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, new[]
            {
                ExpectedWithMessage_ValidationIsDisabled.WithLocation(6, 20),
                ExpectedWithMessage_ValidationIsDisabledInBaseClass.WithLocation(11, 18)
            }).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new []
            {
                ExpectedWithMessage_ValidationIsDisabled.WithLocation(5, 20),
                ExpectedWithMessage_ValidationIsDisabledInBaseClass.WithLocation(10, 18)
            }).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectValidateInputAttributeWasSetOnOverridenMethod()
        {
            const string cSharpTest = @"
using System.Web.Mvc;

namespace VulnerableApp
{
    public class TestControllerBase : Controller
    {
        [HttpPost]
        [ValidateInput(false)]
        public virtual ActionResult ControllerMethod(string input) {
            return null;
        }
    }

    public class TestController : TestControllerBase
    {
        public override ActionResult ControllerMethod(string input) {
            return null;
        }
    }
}
";

            const string visualBasicTest = @"
Imports System.Web.Mvc

Namespace VulnerableApp
    Public Class TestControllerBase
        Inherits Controller
        <HttpPost>
        <ValidateInput(false)> _
        Public Overridable Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class

    Public Class TestController
        Inherits TestControllerBase

        Public Overrides Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, new[]
            {
                ExpectedWithMessage_ValidationIsDisabled.WithLocation(9, 24),
                ExpectedWithMessage_ValidationIsDisabledInBaseClass.WithLocation(17, 38)
            }).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new[]
            {
                ExpectedWithMessage_ValidationIsDisabled.WithLocation(8, 24),
                ExpectedWithMessage_ValidationIsDisabledInBaseClass.WithLocation(17, 35)
            }).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task IgnoreValidateInputAttributeWasSetOnClassAndNoMethodEffected()
        {
            const string cSharpTest = @"
using System.Web.Mvc;

namespace VulnerableApp
{
    [ValidateInput(false)]
    public class TestControllerBase : Controller
    {
    }

    public class TestController : TestControllerBase
    {
        [HttpPost]
        [ValidateInput(true)]
        public ActionResult ControllerMethod(string input) {
            return null;
        }
    }
}
";

            const string visualBasicTest = @"
Imports System.Web.Mvc

Namespace VulnerableApp
    <ValidateInput(false)>
    Public Class TestControllerBase
        Inherits Controller
    End Class

    Public Class TestController
        Inherits TestControllerBase

        <HttpPost>
        <ValidateInput(true)>
        Public Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, new[]
            {
                ExpectedWithMessage_ValidationIsDisabled.WithLocation(6, 20)
            }).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new[]
            {
                ExpectedWithMessage_ValidationIsDisabled.WithLocation(5, 20)
            }).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestCategory("ValidateInput")]
        [TestMethod]
        public async Task IgnoreOverridenValidateInputAttributeWasSetOnParentClass()
        {
            const string cSharpTest = @"
using System.Web.Mvc;

namespace VulnerableApp
{
    [ValidateInput(false)]
    public class TestControllerBase : Controller
    {
    }

    [ValidateInput(true)]
    public class TestController : TestControllerBase
    {
        [HttpPost]
        public ActionResult ControllerMethod(string input) {
            return null;
        }
    }
}
";

            const string visualBasicTest = @"
Imports System.Web.Mvc

Namespace VulnerableApp
    <ValidateInput(false)>
    Public Class TestControllerBase
        Inherits Controller
    End Class

    <ValidateInput(true)>
    Public Class TestController
        Inherits TestControllerBase

        <HttpPost> _
        Public Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, new[]
            {
                ExpectedWithMessage_ValidationIsDisabled.WithLocation(6, 20)
            }).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new[]
            {
                ExpectedWithMessage_ValidationIsDisabled.WithLocation(5, 20)
            }).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task IgnoreOverridenValidateInputAttributeWasSetOnOverridenMethod()
        {
            const string cSharpTest = @"
using System.Web.Mvc;

namespace VulnerableApp
{
    public class TestControllerBase : Controller
    {
        [HttpPost]
        [ValidateInput(false)]
        public virtual ActionResult ControllerMethod(string input) {
            return null;
        }
    }

    public class TestController : TestControllerBase
    {
        [ValidateInput(true)]
        public override ActionResult ControllerMethod(string input) {
            return null;
        }
    }
}
";

            const string visualBasicTest = @"
Imports System.Web.Mvc

Namespace VulnerableApp
    Public Class TestControllerBase
        Inherits Controller
        <HttpPost>
        <ValidateInput(false)> _
        Public Overridable Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class

    Public Class TestController
        Inherits TestControllerBase

        <ValidateInput(true)>
        Public Overrides Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, new[]
            {
                ExpectedWithMessage_ValidationIsDisabled.WithLocation(9, 24)
            }).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new[]
            {
                ExpectedWithMessage_ValidationIsDisabled.WithLocation(8, 24)
            }).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectUnvalidatedProperty()
        {
            const string cSharpTest = @"
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

            const string visualBasicTest = @"
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
            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(10, 32)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(9, 32)).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectUnvalidatedMethod()
        {
            const string cSharpTest = @"
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

            const string visualBasicTest = @"
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

            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(11, 32)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(11, 35)).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task IgnoreUnrelatedUnvalidatedMethod()
        {

            const string cSharpTest = @"
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

            const string visualBasicTest = @"
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

        [TestCategory("Safe")]
        [TestMethod]
        public async Task IgnoreUnrelatedStaticUnvalidatedMethod()
        {

            const string cSharpTest = @"
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

            const string visualBasicTest = @"
Imports System.Web.Mvc

Namespace VulnerableApp
    Public Class TestController
        Public Class Test
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

        [TestCategory("Detect")]
        [DataRow("System.Web.Mvc",                          "AllowHtml")]
        [DataRow("AH = System.Web.Mvc.AllowHtmlAttribute",  "AH")]
        [DataTestMethod]
        public async Task DetectAllowHtmlAttribute(string nameSpace, string attribute)
        {
            var cSharpTest = $@"
using {nameSpace};

namespace VulnerableApp
{{
    public class TestModel
    {{
        [{attribute}]
        public string TestProperty {{ get; set; }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {nameSpace}

Namespace VulnerableApp
    Public Class TestModel

        <{attribute}>
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

            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(8, 10)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(7, 10)).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectAllowHtmlAttributeWithNamespace()
        {
            const string cSharpTest = @"
namespace VulnerableApp
{
    public class TestModel
    {
        [System.Web.Mvc.AllowHtml]
        public string TestProperty { get; set; }
    }
}
";

            const string visualBasicTest = @"
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

            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(6, 10)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(5, 10)).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectInlineAllowHtmlAttribute()
        {
            const string cSharpTest = @"
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

            const string visualBasicTest = @"
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

            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(12, 16)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(10, 16)).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectAllowHtmlAttributeAfterAtrributeContainingAllowHtmlInName()
        {
            const string cSharpTest = @"
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

            const string visualBasicTest = @"
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

            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(13, 10)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(11, 10)).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task IgnoreUnrelatedAllowHtmlAttribute()
        {
            const string cSharpTest = @"
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

            const string visualBasicTest = @"
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
