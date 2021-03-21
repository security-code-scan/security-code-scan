using System.Collections.Generic;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Test.Config;
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test.AntiCsrf
{
    public abstract class CsrfTokenAnalyzerTest : DiagnosticVerifier
    {
        protected abstract string Namespace { get; }

        protected abstract string AllowAnonymousNamespace { get; }

        protected abstract string AntiCsrfTokenName { get; }

        protected DiagnosticResult Expected = new DiagnosticResult
        {
            Id = CsrfTokenDiagnosticAnalyzer.DiagnosticId,
            Severity = DiagnosticSeverity.Warning
        };

        [TestCategory("Detect")]
        [TestMethod]
        public async Task CsrfDetectMissingToken()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    public class TestController : Controller
    {{
        public int NotUsed;

        [HttpPost]
        public ActionResult ControllerMethod(string input)
        {{
            return null;
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {Namespace}

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller

        Public NotUsed As Integer

        <HttpPost> _
        Public Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";
            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(11, 29)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(11, 25)).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task CsrfDetectMissingTokenDerived()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    public class BaseController : Controller
    {{
        [HttpPost]
        public virtual ActionResult ControllerMethod(string input)
        {{
            return null;
        }}
    }}

    public class TestController : BaseController
    {{
        public override ActionResult ControllerMethod(string input)
        {{
            return null;
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {Namespace}

Namespace VulnerableApp
    Public Class BaseController
        Inherits Controller

        <HttpPost> _
        Public Overridable Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class

    Public Class TestController
        Inherits BaseController

        Public Overrides Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, new[] { Expected.WithLocation(9, 37), Expected.WithLocation(17, 38) }).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new[] { Expected.WithLocation(9, 37), Expected.WithLocation(17, 35) }).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task CsrfDetectAliasToken()
        {
            var cSharpTest = $@"
using {Namespace};
using AFT = {Namespace}.{AntiCsrfTokenName}Attribute;

namespace VulnerableApp
{{
    public class TestController : Controller
    {{
        [HttpPost]
        [AFT]
        public ActionResult ControllerMethod(string input)
        {{
            return null;
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {Namespace}
Imports AFT = {Namespace}.{AntiCsrfTokenName}Attribute

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller

        <HttpPost> _
        <AFT> _
        Public Function ControllerMethod(input As String) As ActionResult
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
        public async Task CsrfDetectAliasTokenDerived1()
        {
            var cSharpTest = $@"
using {Namespace};
using AFT = {Namespace}.{AntiCsrfTokenName}Attribute;

namespace VulnerableApp
{{
    public class BaseController : Controller
    {{
        [HttpPost]
        public virtual ActionResult ControllerMethod(string input)
        {{
            return null;
        }}
    }}

    public class TestController : BaseController
    {{
        [AFT]
        public override ActionResult ControllerMethod(string input)
        {{
            return null;
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {Namespace}
Imports AFT = {Namespace}.{AntiCsrfTokenName}Attribute

Namespace VulnerableApp
    Public Class BaseController
        Inherits Controller

        <HttpPost> _
        Public Overridable Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class

    Public Class TestController
        Inherits BaseController

        <AFT> _
        Public Overrides Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";
            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(10, 37)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(10, 37)).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task CsrfDetectAliasTokenDerived2()
        {
            var cSharpTest = $@"
using {Namespace};
using AFT = {Namespace}.{AntiCsrfTokenName}Attribute;

namespace VulnerableApp
{{
    public class BaseController : Controller
    {{
        [AFT]
        public virtual ActionResult ControllerMethod(string input)
        {{
            return null;
        }}
    }}

    public class TestController : BaseController
    {{
        [HttpPost]
        public override ActionResult ControllerMethod(string input)
        {{
            return null;
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {Namespace}
Imports AFT = {Namespace}.{AntiCsrfTokenName}Attribute

Namespace VulnerableApp
    Public Class BaseController
        Inherits Controller

        <AFT> _
        Public Overridable Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class

    Public Class TestController
        Inherits BaseController

        <HttpPost> _
        Public Overrides Function ControllerMethod(input As String) As ActionResult
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
        public async Task CsrfDetectFullNameToken()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    public class {AntiCsrfTokenName}Attribute : System.Attribute
        {{
        }}

    public class TestController : Controller
    {{
        [HttpPost]
        [{AntiCsrfTokenName}]
        public ActionResult ControllerMethod(string input) {{
            return null;
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {Namespace}

Namespace VulnerableApp
    Public Class {AntiCsrfTokenName}
        Inherits System.Attribute
    End Class

    Public Class TestController
        Inherits Controller

        <HttpPost> _
        <VulnerableApp.{AntiCsrfTokenName}> _
        Public Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(14, 29)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(14, 25)).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task CsrfMissingTokenOnGet()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    public class TestController : Controller
    {{
        //[HttpGet] default
        public ActionResult ControllerMethod(string input) {{
            return null;
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {Namespace}

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller

        <HttpGet> _
        Public Function ControllerMethod(input As String) As ActionResult
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
        public async Task CsrfMissingTokenOnAnonymous()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    public class TestController : Controller
    {{
        [HttpPost]
        [{AllowAnonymousNamespace}.AllowAnonymous]
        public ActionResult ControllerMethod(string input) {{
            return null;
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {Namespace}

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller

        <HttpPost> _
        <{AllowAnonymousNamespace}.AllowAnonymous> _
        Public Function ControllerMethod(input As String) As ActionResult
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
        public async Task CsrfMissingTokenOnAnonymousClass()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    [{AllowAnonymousNamespace}.AllowAnonymous]
    public class TestController : Controller
    {{
        [HttpPost]
        public ActionResult ControllerMethod(string input) {{
            return null;
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {Namespace}

Namespace VulnerableApp
    <{AllowAnonymousNamespace}.AllowAnonymous> _
    Public Class TestController
        Inherits Controller

        <HttpPost> _
        Public Function ControllerMethod(input As String) As ActionResult
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
        public async Task CsrfValidateAntiForgeryTokenPresent()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    public class TestController : Controller
    {{
        [HttpPost]
        [{AntiCsrfTokenName}]
        public ActionResult ControllerMethod(string input) {{

            return null;
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {Namespace}

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller

        <HttpPost> _
        <{AntiCsrfTokenName}> _
        Public Function ControllerMethod(input As String) As ActionResult
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
        public async Task CsrfValidateAntiForgeryTokenControllerPresent()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    [{AntiCsrfTokenName}]
    public class TestController : Controller
    {{
        [HttpPost]
        public ActionResult ControllerMethod(string input) {{

            return null;
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {Namespace}

Namespace VulnerableApp
    <{AntiCsrfTokenName}> _
    Public Class TestController
        Inherits Controller

        <HttpPost> _
        Public Function ControllerMethod(input As String) As ActionResult
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
        public async Task CsrfValidateAntiForgeryTokenParentControllerPresent()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    [{AntiCsrfTokenName}]
    public class BaseController : Controller
    {{
        [HttpPost]
        public virtual ActionResult ControllerMethod(string input)
        {{
            return null;
        }}
    }}

    public class TestController : BaseController
    {{
        [HttpPost]
        public override ActionResult ControllerMethod(string input)
        {{
            return null;
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {Namespace}

Namespace VulnerableApp
    <{AntiCsrfTokenName}> _
    Public Class BaseController
        Inherits Controller

        <HttpPost> _
        Public Overridable Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class

    Public Class TestController
        Inherits BaseController
        <HttpPost> _
        Public Overrides Function ControllerMethod(input As String) As ActionResult
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
        public async Task CsrfValidateAntiForgeryTokenPresentWithInlinedAttributes()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    public class TestController : Controller
    {{
        [HttpPost, {AntiCsrfTokenName}]
        public ActionResult ControllerMethod(string input) {{
            return null;
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {Namespace}

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller

        <HttpPost, {AntiCsrfTokenName}> _
        Public Function ControllerMethod(input As String) As ActionResult
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
        public async Task CsrfValidateAntiForgeryTokenNonAction()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    public class BaseController : Controller
    {{
        [HttpPost]
        public virtual void ControllerMethod(string input) {{
        }}
    }}

    public class TestController : BaseController
    {{
        [NonAction]
        public override void ControllerMethod(string input) {{
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {Namespace}

Namespace VulnerableApp
    Public Class BaseController
        Inherits Controller

        <HttpPost> _
        Public Overridable Sub ControllerMethod(input As String)
        End Sub
    End Class

    Public Class TestController
        Inherits BaseController

        <NonAction> _
        Public Overrides Sub ControllerMethod(input As String)
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(9, 29)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(9, 32)).ConfigureAwait(false);
        }
    }

    [TestClass]
    public class MvcCsrfTokenAnalyzerTest : CsrfTokenAnalyzerTest
    {
        protected override string Namespace => "System.Web.Mvc";

        protected override string AllowAnonymousNamespace => "System.Web.Mvc";

        protected override string AntiCsrfTokenName => "ValidateAntiForgeryToken";

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(System.Web.Mvc.ValidateAntiForgeryTokenAttribute).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string _)
        {
            return new[] { new CsrfTokenDiagnosticAnalyzer() };
        }
    }

    public abstract class CoreCsrfTokenAnalyzerBaseTest : CsrfTokenAnalyzerTest
    {
        protected override string Namespace => "Microsoft.AspNetCore.Mvc";

        protected override string AllowAnonymousNamespace => "Microsoft.AspNetCore.Authorization";

        protected override string AntiCsrfTokenName => "ValidateAntiForgeryToken";

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.ValidateAntiForgeryTokenAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.HttpPostAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Authorization.AllowAnonymousAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(Assembly.Load("netstandard, Version=2.0.0.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51")
                                                     .Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string _)
        {
            return new[] { new CsrfTokenDiagnosticAnalyzer() };
        }
    }

    [TestClass]
    public class CoreCsrfTokenAnalyzerTest : CoreCsrfTokenAnalyzerBaseTest
    {
        private const string ExpectedMessage = "Controller method is potentially vulnerable to Cross Site Request Forgery (CSRF).";

        [TestMethod]
        public async Task CsrfValidateAntiForgeryTokenApiControllerDefault()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    [ApiController]
    public class TestController : Controller
    {{
        [HttpPost]
        public virtual void ControllerMethod(string input) {{
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {Namespace}

Namespace VulnerableApp
    <ApiController>
    Public Class TestController
        Inherits Controller

        <HttpPost> _
        Public Overridable Sub ControllerMethod(input As String)
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task CsrfValidateAntiForgeryTokenFromBody()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    [ApiController]
    public class TestController : Controller
    {{
        [HttpPost]
        public virtual void ControllerMethod([FromBody]string input) {{
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {Namespace}

Namespace VulnerableApp
    <ApiController>
    Public Class TestController
        Inherits Controller

        <HttpPost> _
        Public Overridable Sub ControllerMethod(<FromBody> input As String)
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task CsrfValidateAntiForgeryTokenFromBody2()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    public class TestController : Controller
    {{
        [HttpPost]
        public virtual void ControllerMethod([FromBody]string input) {{
        }}

        [HttpPost]
        public virtual void ControllerMethod2(string input) {{
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {Namespace}

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller

        <HttpPost> _
        Public Overridable Sub ControllerMethod(<FromBody> input As String)
        End Sub

        <HttpPost> _
        Public Overridable Sub ControllerMethod2(input As String)
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(13, 29).WithMessage(ExpectedMessage)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(13, 32).WithMessage(ExpectedMessage)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task CsrfValidateAntiForgeryTokenFromForm()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    [ApiController]
    public class TestController : Controller
    {{
        [HttpPost]
        public virtual void ControllerMethod([FromForm]string input) {{
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {Namespace}

Namespace VulnerableApp
    <ApiController>
    Public Class TestController
        Inherits Controller

        <HttpPost> _
        Public Overridable Sub ControllerMethod(<FromForm> input As String)
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(10, 29).WithMessage(ExpectedMessage)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(10, 32).WithMessage(ExpectedMessage)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task CsrfValidateAntiForgeryTokenIgnoreOnBaseClass()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    [IgnoreAntiforgeryTokenAttribute]
    public class BaseController : Controller
    {{
        [HttpPost]
        public virtual void ControllerMethod(string input) {{
        }}
    }}

    public class TestController : BaseController
    {{
        [HttpPost]
        public override void ControllerMethod(string input) {{
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {Namespace}

Namespace VulnerableApp
    <IgnoreAntiforgeryTokenAttribute> _
    Public Class BaseController
        Inherits Controller

        <HttpPost> _
        Public Overridable Sub ControllerMethod(input As String)
        End Sub
    End Class

    Public Class TestController
        Inherits BaseController

        <HttpPost> _
        Public Overrides Sub ControllerMethod(input As String)
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task CsrfValidateAntiForgeryTokenIgnoreOnClass()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    public class BaseController : Controller
    {{
        [HttpPost]
        public virtual void ControllerMethod(string input) {{
        }}
    }}

    [IgnoreAntiforgeryTokenAttribute]
    public class TestController : BaseController
    {{
        [HttpPost]
        public override void ControllerMethod(string input) {{
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {Namespace}

Namespace VulnerableApp
    Public Class BaseController
        Inherits Controller

        <HttpPost> _
        Public Overridable Sub ControllerMethod(input As String)
        End Sub
    End Class

    <IgnoreAntiforgeryTokenAttribute> _
    Public Class TestController
        Inherits BaseController

        <HttpPost> _
        Public Overrides Sub ControllerMethod(input As String)
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(9, 29).WithMessage(ExpectedMessage)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(9, 32).WithMessage(ExpectedMessage)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task CsrfValidateAntiForgeryTokenIgnoreOnBaseMethod()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    public class BaseController : Controller
    {{
        [HttpPost]
        [IgnoreAntiforgeryTokenAttribute]
        public virtual void ControllerMethod(string input) {{
        }}
    }}

    public class TestController : BaseController
    {{
        [HttpPost]
        public override void ControllerMethod(string input) {{
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {Namespace}

Namespace VulnerableApp
    Public Class BaseController
        Inherits Controller

        <HttpPost> _
        <IgnoreAntiforgeryTokenAttribute> _
        Public Overridable Sub ControllerMethod(input As String)
        End Sub
    End Class

    Public Class TestController
        Inherits BaseController

        <HttpPost> _
        Public Overrides Sub ControllerMethod(input As String)
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task CsrfValidateAntiForgeryTokenIgnoreOnMethod()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    public class BaseController : Controller
    {{
        [HttpPost]
        public virtual void ControllerMethod(string input) {{
        }}
    }}

    public class TestController : BaseController
    {{
        [HttpPost]
        [IgnoreAntiforgeryTokenAttribute]
        public override void ControllerMethod(string input) {{
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {Namespace}

Namespace VulnerableApp
    Public Class BaseController
        Inherits Controller

        <HttpPost> _
        Public Overridable Sub ControllerMethod(input As String)
        End Sub
    End Class

    Public Class TestController
        Inherits BaseController

        <HttpPost> _
        <IgnoreAntiforgeryTokenAttribute> _
        Public Overrides Sub ControllerMethod(input As String)
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(9, 29).WithMessage(ExpectedMessage)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(9, 32).WithMessage(ExpectedMessage)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task CsrfValidateAntiForgeryTokenIgnoreOnMethod2()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    public class TestController : Controller
    {{
        [HttpPost]
        [IgnoreAntiforgeryTokenAttribute]
        public void ControllerMethod(string input) {{
        }}

        [HttpPost]
        public void ControllerMethod2(string input) {{
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {Namespace}

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller

        <HttpPost> _
        <IgnoreAntiforgeryTokenAttribute> _
        Public Sub ControllerMethod(input As String)
        End Sub

        <HttpPost> _
        Public Sub ControllerMethod2(input As String)
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(14, 21).WithMessage(ExpectedMessage)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(14, 20).WithMessage(ExpectedMessage)).ConfigureAwait(false);
        }
    }

    [TestClass]
    public class CoreAutoCsrfTokenAnalyzerTest : CsrfTokenAnalyzerTest
    {
        protected override string Namespace => "Microsoft.AspNetCore.Mvc";

        protected override string AllowAnonymousNamespace => "Microsoft.AspNetCore.Authorization";

        protected override string AntiCsrfTokenName => "AutoValidateAntiforgeryToken";

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.AutoValidateAntiforgeryTokenAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.HttpPostAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Authorization.AllowAnonymousAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(Assembly.Load("netstandard, Version=2.0.0.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51")
                                                     .Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string _)
        {
            return new[] { new CsrfTokenDiagnosticAnalyzer() };
        }
    }

    [TestClass]
    public class MixupCsrfTokenTest : DiagnosticVerifier
    {
        [TestCategory("Detect")]
        [TestMethod]
        public async Task CsrfValidateWrongAntiForgeryTokenPresent()
        {
            var cSharpTest = @"
namespace VulnerableApp
{
    public class TestController : Microsoft.AspNetCore.Mvc.Controller
    {
        [Microsoft.AspNetCore.Mvc.HttpPost]
        [System.Web.Mvc.ValidateAntiForgeryToken]
        public Microsoft.AspNetCore.Mvc.ActionResult ControllerMethod(string input)
        {
            return null;
        }
    }
}
";

            var visualBasicTest = @"
Namespace VulnerableApp
    Public Class TestController
        Inherits Microsoft.AspNetCore.Mvc.Controller

        <Microsoft.AspNetCore.Mvc.HttpPost> _
        <System.Web.Mvc.ValidateAntiForgeryToken> _
        Public Function ControllerMethod(input As String) As Microsoft.AspNetCore.Mvc.ActionResult
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

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation(8, 54)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation(8, 25)).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task CsrfValidateWrongAntiForgeryTokenPresent2()
        {
            var cSharpTest = @"
namespace VulnerableApp
{
    public class TestController : System.Web.Mvc.Controller
    {
        [System.Web.Mvc.HttpPost]
        [Microsoft.AspNetCore.Mvc.ValidateAntiForgeryToken]
        public System.Web.Mvc.ActionResult ControllerMethod(string input)
        {
            return null;
        }
    }
}
";

            var visualBasicTest = @"
Namespace VulnerableApp
    Public Class TestController
        Inherits System.Web.Mvc.Controller

        <System.Web.Mvc.HttpPost> _
        <Microsoft.AspNetCore.Mvc.ValidateAntiForgeryToken> _
        Public Function ControllerMethod(input As String) As System.Web.Mvc.ActionResult
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

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation(8, 44)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation(8, 25)).ConfigureAwait(false);
        }

        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string _)
        {
            return new[] { new CsrfTokenDiagnosticAnalyzer() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.ValidateAntiForgeryTokenAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.HttpPostAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Web.Mvc.ValidateAntiForgeryTokenAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.Controller).Assembly.Location),
            MetadataReference.CreateFromFile(Assembly.Load("netstandard, Version=2.0.0.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51")
                                                     .Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;
    }

    [TestClass]
    public class CustomConditionalCsrfAttributeTests: DiagnosticVerifier
    {
        [TestCategory("Detect")]
        [TestMethod]
        public async Task ConditionalFailure()
        {
            var cSharpTest = @"
using System;

namespace VulnerableApp
{
    // this is lifted from the Stack Overflow source, descendent of https://kevinmontrose.com/2011/07/25/why-i-love-attribute-based-routing/
    public enum CustomRoutePriority
    {
        Lowest = 0,
        Low = 1,
        Default = 2,
        High = 3
    }

    public enum HttpVerbs
    {
        Get = 1,
        Post = 2,
        Put = 4,
        Delete = 8,
        Head = 16,
        Patch = 32,
        Options = 64
    }

    public abstract class CustomController
    {

    }

    public class ActionResult
    {

    }

    [AttributeUsage(AttributeTargets.Method, AllowMultiple = true)]
    public class CustomRouteAttribute : Attribute
    {
        public CustomRouteAttribute(string url) : this(url, """", null, CustomRoutePriority.Default) { }

        public CustomRouteAttribute(string url, HttpVerbs verbs) : this(url, """", verbs, CustomRoutePriority.Default) { }

        public CustomRouteAttribute(string url, HttpVerbs verbs, CustomRoutePriority priority) : this(url, """", verbs, priority) { }

        private CustomRouteAttribute(string url, string name, HttpVerbs? verbs, CustomRoutePriority priority)
        {
            Url = url;
            Name = name;
            AcceptVerbs = verbs;
            Priority = priority;
        }

        private const HttpVerbs FkeyOptionalVerbs = HttpVerbs.Get | HttpVerbs.Head;

        private bool? _ensureCsrfSafe;
        public bool EnsureCSRFSafe
        {
            get { return _ensureCsrfSafe ?? AcceptVerbs.HasValue && (AcceptVerbs.Value & FkeyOptionalVerbs) == 0; }
            set { _ensureCsrfSafe = value; }
        }

        public string Url { get; private set; }
        public string Name { get; private set; }
        public HttpVerbs? AcceptVerbs { get; private set; }
        public CustomRoutePriority Priority { get; private set; }
    }

    public class TestController : CustomController
    {
        [CustomRoute(""vulnerable/post"", HttpVerbs.Post, EnsureCSRFSafe = false)]
        public ActionResult VulnerablePost(string input)
        {
            return null;
        }

        [CustomRoute(""vulnerable/put"", HttpVerbs.Put, EnsureCSRFSafe = false)]
        public ActionResult VulnerablePut(string input)
        {
            return null;
        }

        [CustomRoute(""vulnerable/delete"", HttpVerbs.Delete, EnsureCSRFSafe = false)]
        public ActionResult VulnerableDelete(string input)
        {
            return null;
        }

        [CustomRoute(""vulnerable/patch"", HttpVerbs.Patch, EnsureCSRFSafe = false)]
        public ActionResult VulnerablePatch(string input)
        {
            return null;
        }

        [CustomRoute(""safe/post/implicit"", HttpVerbs.Post)]
        public ActionResult SafePostImplicit(string input)
        {
            return null;
        }

        [CustomRoute(""safe/post/explicit"", HttpVerbs.Post, EnsureCSRFSafe = true)]
        public ActionResult SafePostExplicit(string input)
        {
            return null;
        }

        [CustomRoute(""safe/get/implicit"")]
        public ActionResult SafeGetImplicit(string input)
        {
            return null;
        }

        [CustomRoute(""safe/get/explicit"", HttpVerbs.Get)]
        public ActionResult SafeGetExplicit(string input)
        {
            return null;
        }

        [CustomRoute(""safe/get/explicit/disabled"", HttpVerbs.Get, EnsureCSRFSafe = false)]
        public ActionResult SafeGetExplicitDisabled(string input)
        {
            return null;
        }

        [CustomRoute(""safe/head"", HttpVerbs.Head)]
        public ActionResult SafeHead(string input)
        {
            return null;
        }
    }
}
";

            var vBTest = @"
Imports System

Namespace VulnerableApp
    Public Enum CustomRoutePriority
        Lowest = 0
        Low = 1
        [Default] = 2
        High = 3
    End Enum

    Public Enum HttpVerbs
        [Get] = 1
        Post = 2
        Put = 4
        Delete = 8
        Head = 16
        Patch = 32
        Options = 64
    End Enum

    Public MustInherit Class CustomController
    End Class

    Public Class ActionResult
    End Class

    <AttributeUsage(AttributeTargets.Method, AllowMultiple:=True)>
    Public Class CustomRouteAttribute
        Inherits Attribute

        Public Sub New(ByVal url As String)
            Me.New(url, """", Nothing, CustomRoutePriority.[Default])
        End Sub

        Public Sub New(ByVal url As String, ByVal verbs As HttpVerbs)
            Me.New(url, """", verbs, CustomRoutePriority.[Default])
        End Sub

        Public Sub New(ByVal url As String, ByVal verbs As HttpVerbs, ByVal priority As CustomRoutePriority)
            Me.New(url, """", verbs, priority)
        End Sub

        Private Sub New(ByVal url As String, ByVal name As String, ByVal verbs As HttpVerbs?, ByVal priority As CustomRoutePriority)
            Url = url
            Name = name
            AcceptVerbs = verbs
            Priority = priority
        End Sub

        Private Const FkeyOptionalVerbs As HttpVerbs = HttpVerbs.[Get] Or HttpVerbs.Head
        Private _ensureCsrfSafe As Boolean?

        Public Property EnsureCSRFSafe As Boolean
            Get
                Return If(_ensureCsrfSafe, AcceptVerbs.HasValue AndAlso (AcceptVerbs.Value And FkeyOptionalVerbs) = 0)
            End Get
            Set(ByVal value As Boolean)
                _ensureCsrfSafe = value
            End Set
        End Property

        Public Property Url As String
        Public Property Name As String
        Public Property AcceptVerbs As HttpVerbs?
        Public Property Priority As CustomRoutePriority
    End Class

    Public Class TestController
        Inherits CustomController

        <CustomRoute(""vulnerable/post"", HttpVerbs.Post, EnsureCSRFSafe:=False)>
        Public Function VulnerablePost(ByVal input As String) As ActionResult
            Return Nothing
        End Function

        <CustomRoute(""vulnerable/put"", HttpVerbs.Put, EnsureCSRFSafe:=False)>
        Public Function VulnerablePut(ByVal input As String) As ActionResult
            Return Nothing
        End Function

        <CustomRoute(""vulnerable/delete"", HttpVerbs.Delete, EnsureCSRFSafe:=False)>
        Public Function VulnerableDelete(ByVal input As String) As ActionResult
            Return Nothing
        End Function

        <CustomRoute(""vulnerable/patch"", HttpVerbs.Patch, EnsureCSRFSafe:=False)>
        Public Function VulnerablePatch(ByVal input As String) As ActionResult
            Return Nothing
        End Function

        <CustomRoute(""safe/post/implicit"", HttpVerbs.Post)>
        Public Function SafePostImplicit(ByVal input As String) As ActionResult
            Return Nothing
        End Function

        <CustomRoute(""safe/post/explicit"", HttpVerbs.Post, EnsureCSRFSafe:=True)>
        Public Function SafePostExplicit(ByVal input As String) As ActionResult
            Return Nothing
        End Function

        <CustomRoute(""safe/get/implicit"")>
        Public Function SafeGetImplicit(ByVal input As String) As ActionResult
            Return Nothing
        End Function

        <CustomRoute(""safe/get/explicit"", HttpVerbs.[Get])>
        Public Function SafeGetExplicit(ByVal input As String) As ActionResult
            Return Nothing
        End Function

        <CustomRoute(""safe/get/explicit/disabled"", HttpVerbs.[Get], EnsureCSRFSafe:=False)>
        Public Function SafeGetExplicitDisabled(ByVal input As String) As ActionResult
            Return Nothing
        End Function

        <CustomRoute(""safe/head"", HttpVerbs.Head)>
        Public Function SafeHead(ByVal input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";

            var testConfig = @"
CsrfCheck:
  Test:
    Name: Stack Overflow Example Config
    RequiredAttributes:
      Include:
        - Type: VulnerableApp.CustomRouteAttribute
          Condition:
            - { 1: { Value:  2 }, EnsureCSRFSafe: { Value: true } }  # Post
            - { 1: { Value:  2 }, EnsureCSRFSafe: { Value: none } }  # Post
            - { 1: { Value:  4 }, EnsureCSRFSafe: { Value: true } }  # Put
            - { 1: { Value:  4 }, EnsureCSRFSafe: { Value: none } }  # Put
            - { 1: { Value:  8 }, EnsureCSRFSafe: { Value: true } }  # Delete
            - { 1: { Value:  8 }, EnsureCSRFSafe: { Value: none } }  # Delete
            - { 1: { Value: 32 }, EnsureCSRFSafe: { Value: true } }  # Patch
            - { 1: { Value: 32 }, EnsureCSRFSafe: { Value: none } }  # Patch
    Class:
      Accessibility:
        - public
      Parent: VulnerableApp.CustomController
    Method:
      Accessibility:
        - public
      IncludeConstructor: false
      Static: false
      Attributes:
        Include:
          - Type: VulnerableApp.CustomRouteAttribute
            Condition:
              - { 1: { Value:  2 } }   # Post
              - { 1: { Value:  4 } }   # Put
              - { 1: { Value:  8 } }   # Delete
              - { 1: { Value:  32 } }  # Patch
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            var expectedCs =
                new[]
                {
                    new DiagnosticResult
                    {
                        Id = CsrfTokenDiagnosticAnalyzer.DiagnosticId,
                        Severity = DiagnosticSeverity.Warning
                    }.WithLocation(71, 29),
                    new DiagnosticResult
                    {
                        Id = CsrfTokenDiagnosticAnalyzer.DiagnosticId,
                        Severity = DiagnosticSeverity.Warning
                    }.WithLocation(77, 29),
                    new DiagnosticResult
                    {
                        Id = CsrfTokenDiagnosticAnalyzer.DiagnosticId,
                        Severity = DiagnosticSeverity.Warning
                    }.WithLocation(83, 29),
                    new DiagnosticResult
                    {
                        Id = CsrfTokenDiagnosticAnalyzer.DiagnosticId,
                        Severity = DiagnosticSeverity.Warning
                    }.WithLocation(89, 29)
                };

            var expectedVb =
                new[]
                {
                    new DiagnosticResult
                    {
                        Id = CsrfTokenDiagnosticAnalyzer.DiagnosticId,
                        Severity = DiagnosticSeverity.Warning
                    }.WithLocation(73, 25),
                    new DiagnosticResult
                    {
                        Id = CsrfTokenDiagnosticAnalyzer.DiagnosticId,
                        Severity = DiagnosticSeverity.Warning
                    }.WithLocation(78, 25),
                    new DiagnosticResult
                    {
                        Id = CsrfTokenDiagnosticAnalyzer.DiagnosticId,
                        Severity = DiagnosticSeverity.Warning
                    }.WithLocation(83, 25),
                    new DiagnosticResult
                    {
                        Id = CsrfTokenDiagnosticAnalyzer.DiagnosticId,
                        Severity = DiagnosticSeverity.Warning
                    }.WithLocation(88, 25)
                };

            await VerifyCSharpDiagnostic(cSharpTest, expectedCs, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(vBTest, expectedVb, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task ActionAttributesOnly()
        {
            var cSharpTest = @"
using System;

namespace VulnerableApp
{
    public class ActionResult
    {

    }

    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    public class CustomRouteAttribute : Attribute
    {
    }

    public class TestController
    {
        [CustomRoute]
        public ActionResult VulnerablePublic(string input)
        {
            return null;
        }

        
        [CustomRoute]
        private ActionResult VulnerablePrivate(string input)
        {
            return null;
        }

        public ActionResult NotAnAction(string input)
        {
            return null;
        }
    }
}
";

            var vbTest = @"
Imports System

Namespace VulnerableApp
    Public Class ActionResult
    End Class

    <AttributeUsage(AttributeTargets.Method, AllowMultiple:=False)>
    Public Class CustomRouteAttribute
        Inherits Attribute
    End Class

    Public Class TestController
        <CustomRoute>
        Public Function VulnerablePublic(ByVal input As String) As ActionResult
            Return Nothing
        End Function

        <CustomRoute>
        Private Function VulnerablePrivate(ByVal input As String) As ActionResult
            Return Nothing
        End Function

        Public Function NotAnAction(ByVal input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";

            var testConfig = @"
CsrfCheck:
  Test:
    Name: Test
    Method:
      IncludeConstructor: false
      Static: false
      Attributes:
        Include:
          - Type: VulnerableApp.CustomRouteAttribute
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            var expectedCsharp =
                new[]
                {
                    new DiagnosticResult
                    {
                        Id = CsrfTokenDiagnosticAnalyzer.DiagnosticId,
                        Severity = DiagnosticSeverity.Warning
                    }.WithLocation(19, 29),
                    new DiagnosticResult
                    {
                        Id = CsrfTokenDiagnosticAnalyzer.DiagnosticId,
                        Severity = DiagnosticSeverity.Warning
                    }.WithLocation(26, 30)
                };

            var expectedVb =
                new[]
                {
                    new DiagnosticResult
                    {
                        Id = CsrfTokenDiagnosticAnalyzer.DiagnosticId,
                        Severity = DiagnosticSeverity.Warning
                    }.WithLocation(15, 25),
                    new DiagnosticResult
                    {
                        Id = CsrfTokenDiagnosticAnalyzer.DiagnosticId,
                        Severity = DiagnosticSeverity.Warning
                    }.WithLocation(20, 26)
                };

            await VerifyCSharpDiagnostic(cSharpTest, expectedCsharp, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(vbTest, expectedVb, optionsWithProjectConfig).ConfigureAwait(false);
        }

        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string _)
        {
            return new[] { new CsrfTokenDiagnosticAnalyzer() };
        }
    }
}
