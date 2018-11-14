using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
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

        <HttpPost> _
        Public Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";
            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(9, 29)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(9, 25)).ConfigureAwait(false);
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

        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            if (language == LanguageNames.CSharp)
                return new DiagnosticAnalyzer[] { new MvcCsrfTokenAnalyzerCSharp() };
            else
                return new DiagnosticAnalyzer[] { new MvcCsrfTokenAnalyzerVBasic() };
        }
    }

    public class CoreCsrfTokenAnalyzerBaseTest : CsrfTokenAnalyzerTest
    {
        protected override string Namespace => "Microsoft.AspNetCore.Mvc";

        protected override string AllowAnonymousNamespace => "Microsoft.AspNetCore.Authorization";

        protected override string AntiCsrfTokenName => "ValidateAntiForgeryToken";

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.ValidateAntiForgeryTokenAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.HttpPostAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Authorization.AllowAnonymousAttribute).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            if (language == LanguageNames.CSharp)
                return new DiagnosticAnalyzer[] { new CoreCsrfTokenAnalyzerCSharp() };
            else
                return new DiagnosticAnalyzer[] { new CoreCsrfTokenAnalyzerVBasic() };
        }
    }

    [TestClass]
    public class CoreCsrfTokenAnalyzerTest : CoreCsrfTokenAnalyzerBaseTest
    {
        private const string ExpectedMessage = "Controller method is vulnerable to CSRF";

        [TestMethod]
        public async Task CsrfValidateAntiForgeryTokenFromBody()
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
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
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
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Authorization.AllowAnonymousAttribute).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            if (language == LanguageNames.CSharp)
                return new DiagnosticAnalyzer[] { new CoreCsrfTokenAnalyzerCSharp() };
            else
                return new DiagnosticAnalyzer[] { new CoreCsrfTokenAnalyzerVBasic() };
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

        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            if (language == LanguageNames.CSharp)
                return new DiagnosticAnalyzer[] { new CoreCsrfTokenAnalyzerCSharp(), new MvcCsrfTokenAnalyzerCSharp() };
            else
                return new DiagnosticAnalyzer[] { new CoreCsrfTokenAnalyzerVBasic(), new MvcCsrfTokenAnalyzerVBasic() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.ValidateAntiForgeryTokenAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.HttpPostAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Web.Mvc.ValidateAntiForgeryTokenAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.Controller).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;
    }
}
