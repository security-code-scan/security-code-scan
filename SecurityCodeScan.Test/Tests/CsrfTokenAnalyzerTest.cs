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

        private DiagnosticResult Expected = new DiagnosticResult
        {
            Id = CsrfTokenAnalyzer.DiagnosticId,
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
            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(9, 29)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(7, 25)).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
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

            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(14, 29)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(12, 25)).ConfigureAwait(false);
        }

        [TestCategory("Ignore")]
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

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Ignore")]
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

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Ignore")]
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

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Ignore")]
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

        [TestCategory("Ignore")]
        [TestMethod]
        public async Task CsrfValidateAntiForgeryTokenControllerPresent()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    [{AntiCsrfTokenName}]
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
    <{AntiCsrfTokenName}> _
    Public Class TestController
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

        [TestCategory("Ignore")]
        [TestMethod]
        public async Task CsrfValidateAntiForgeryTokenPresentWithInlinedAttributes()
        {
            var cSharpTest = $@"
using {Namespace};

namespace VulnerableApp
{{
    public class TestController
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
            return new[] { new MvcCsrfTokenAnalyzer() };
        }
    }

    [TestClass]
    public class CoreCsrfTokenAnalyzerTest : CsrfTokenAnalyzerTest
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
            return new[] { new CoreCsrfTokenAnalyzer() };
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
            return new[] { new CoreCsrfTokenAnalyzer() };
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

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation(8, 54)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation(6, 25)).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
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

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation(8, 44)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation(6, 25)).ConfigureAwait(false);
        }

        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            return new CsrfTokenAnalyzer[]
            {
                new CoreCsrfTokenAnalyzer(),
                new MvcCsrfTokenAnalyzer()
            };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.ValidateAntiForgeryTokenAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.HttpPostAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Web.Mvc.ValidateAntiForgeryTokenAttribute).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;
    }
}
