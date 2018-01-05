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

        [TestMethod]
        public async Task CsrfDetectMissingToken()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    public class TestController
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
        <HttpPost> _
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

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        [TestMethod]
        public async Task CsrfDetectFullNameToken()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    public class ValidateAntiForgeryTokenAttribute : System.Attribute
        {{
        }}

    public class TestController
    {{
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult ControllerMethod(string input) {{
            return null;
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports {Namespace}

Namespace VulnerableApp
    Public Class ValidateAntiForgeryToken
        Inherits System.Attribute
    End Class

    Public Class TestController
        <HttpPost> _
        <VulnerableApp.ValidateAntiForgeryToken> _
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

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        [TestMethod]
        public async Task CsrfMissingTokenOnGet()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    public class TestController
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
        <HttpGet> _
        Public Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [TestMethod]
        public async Task CsrfMissingTokenOnAnonymous()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    public class TestController
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
        <HttpPost> _
        <{AllowAnonymousNamespace}.AllowAnonymous> _
        Public Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [TestMethod]
        public async Task CsrfMissingTokenOnAnonymousClass()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    [{AllowAnonymousNamespace}.AllowAnonymous]
    public class TestController
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
        <HttpPost> _
        Public Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [TestMethod]
        public async Task CsrfValidateAntiForgeryTokenPresent()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    public class TestController
    {{
        [HttpPost]
        [ValidateAntiForgeryToken]
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
        <HttpPost> _
        <ValidateAntiForgeryToken> _
        Public Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [TestMethod]
        public async Task CsrfValidateAntiForgeryTokenControllerPresent()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    [ValidateAntiForgeryToken]
    public class TestController
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
    <ValidateAntiForgeryToken> _
    Public Class TestController
        <HttpPost> _
        Public Function ControllerMethod(input As String) As ActionResult
            Return Nothing
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [TestMethod]
        public async Task CsrfValidateAntiForgeryTokenPresentWithInlinedAttributes()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    public class TestController
    {{
        [HttpPost, ValidateAntiForgeryToken]
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
		<HttpPost, ValidateAntiForgeryToken> _
		Public Function ControllerMethod(input As String) As ActionResult
			Return Nothing
		End Function
	End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }
    }

    [TestClass]
    public class MvcCsrfTokenAnalyzerTest : CsrfTokenAnalyzerTest
    {
        protected override string Namespace => "System.Web.Mvc";

        protected override string AllowAnonymousNamespace => "System.Web.Mvc";

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[]
            {
                MetadataReference.CreateFromFile(typeof(System.Web.Mvc.ValidateAntiForgeryTokenAttribute).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Web.Mvc.HttpPostAttribute).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Web.Mvc.AllowAnonymousAttribute).Assembly.Location)
            };
        }

        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new[] { new MvcCsrfTokenAnalyzer() };
        }
    }

    [TestClass]
    public class CoreCsrfTokenAnalyzerTest : CsrfTokenAnalyzerTest
    {
        protected override string Namespace => "Microsoft.AspNetCore.Mvc";

        protected override string AllowAnonymousNamespace => "Microsoft.AspNetCore.Authorization";

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[]
            {
                MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.ValidateAntiForgeryTokenAttribute).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.HttpPostAttribute).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Authorization.AllowAnonymousAttribute).Assembly.Location)
            };
        }

        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new[] { new CoreCsrfTokenAnalyzer() };
        }
    }

    [TestClass]
    public class MixupCsrfTokenTest : DiagnosticVerifier
    {
        [TestMethod]
        public async Task CsrfValidateWrongAntiForgeryTokenPresent()
        {
            var cSharpTest = @"
namespace VulnerableApp
{
    public class TestController
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
                Id       = CsrfTokenAnalyzer.DiagnosticId,
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        [TestMethod]
        public async Task CsrfValidateWrongAntiForgeryTokenPresent2()
        {
            var cSharpTest = @"
namespace VulnerableApp
{
    public class TestController
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
                Id       = CsrfTokenAnalyzer.DiagnosticId,
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new CsrfTokenAnalyzer[]
            {
                new CoreCsrfTokenAnalyzer(),
                new MvcCsrfTokenAnalyzer()
            };
        }

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[]
            {
                MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.ValidateAntiForgeryTokenAttribute).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.HttpPostAttribute).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Web.Mvc.ValidateAntiForgeryTokenAttribute).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Web.Mvc.HttpPostAttribute).Assembly.Location)
            };
        }
    }
}
