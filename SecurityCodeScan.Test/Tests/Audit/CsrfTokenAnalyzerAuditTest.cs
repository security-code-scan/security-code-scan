using System.Threading.Tasks;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Test.AntiCsrf;

namespace SecurityCodeScan.Test.Audit
{
    [TestClass]
    public class CoreCsrfTokenAnalyzerAuditTest : CoreCsrfTokenAnalyzerBaseTest
    {
        public CoreCsrfTokenAnalyzerAuditTest()
        {
            Expected.Message = "Controller method is potentially vulnerable to Cross Site Request Forgery (CSRF).";
        }

        [ClassInitialize]
        public static async Task InitOptions(TestContext testContext)
        {
            Options = await AuditTest.GetAuditModeConfigOptions();
        }

        private const string AuditMessage = "CSRF token validation is explicitly disabled, review if the controller method is vulnerable to CSRF";
        private const string ExpectedFromBodyMessage = "Review if the JSON endpoint doesn't accept text/plain";

        private static AnalyzerOptions Options;

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

            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(9, 29)
                                                             .WithMessage(ExpectedFromBodyMessage),
                                         Options)
                .ConfigureAwait(false);

            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(9, 32)
                                                                       .WithMessage(ExpectedFromBodyMessage),
                                              Options)
                .ConfigureAwait(false);
        }

        [TestMethod]
        public async Task CsrfValidateAntiForgeryTokenFromBodyApiController()
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

            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(10, 29)
                                                             .WithMessage(ExpectedFromBodyMessage),
                                         Options)
                .ConfigureAwait(false);

            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(10, 32)
                                                                       .WithMessage(ExpectedFromBodyMessage),
                                              Options)
                .ConfigureAwait(false);
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

            await VerifyCSharpDiagnostic(cSharpTest,
                                         new[]
                                         {
                                             Expected.WithLocation(10, 29).WithMessage(AuditMessage),
                                             Expected.WithLocation(17, 30).WithMessage(AuditMessage)
                                         },
                                         Options).ConfigureAwait(false);

            await VerifyVisualBasicDiagnostic(visualBasicTest,
                                              new[]
                                              {
                                                  Expected.WithLocation(10, 32).WithMessage(AuditMessage),
                                                  Expected.WithLocation(18, 30).WithMessage(AuditMessage)
                                              },
                                              Options).ConfigureAwait(false);
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

            await VerifyCSharpDiagnostic(cSharpTest,
                                         new[]
                                         {
                                             Expected.WithLocation(9, 29),
                                             Expected.WithLocation(17, 30).WithMessage(AuditMessage)
                                         },
                                         Options).ConfigureAwait(false);

            await VerifyVisualBasicDiagnostic(visualBasicTest,
                                              new[]
                                              {
                                                  Expected.WithLocation(9, 32),
                                                  Expected.WithLocation(18, 30).WithMessage(AuditMessage)
                                              },
                                              Options).ConfigureAwait(false);
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

            await VerifyCSharpDiagnostic(cSharpTest,
                                         new[]
                                         {
                                             Expected.WithLocation(10, 29).WithMessage(AuditMessage),
                                             Expected.WithLocation(17, 30).WithMessage(AuditMessage)
                                         },
                                         Options).ConfigureAwait(false);

            await VerifyVisualBasicDiagnostic(visualBasicTest,
                                              new[]
                                              {
                                                  Expected.WithLocation(10, 32).WithMessage(AuditMessage),
                                                  Expected.WithLocation(18, 30).WithMessage(AuditMessage)
                                              },
                                              Options).ConfigureAwait(false);
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

            await VerifyCSharpDiagnostic(cSharpTest,
                                         new[]
                                         {
                                             Expected.WithLocation(9, 29),
                                             Expected.WithLocation(17, 30).WithMessage(AuditMessage)
                                         },
                                         Options).ConfigureAwait(false);

            await VerifyVisualBasicDiagnostic(visualBasicTest,
                                              new[]
                                              {
                                                  Expected.WithLocation(9, 32),
                                                  Expected.WithLocation(18, 30).WithMessage(AuditMessage)
                                              },
                                              Options).ConfigureAwait(false);
        }
    }
}
