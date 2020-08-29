using System.Collections.Generic;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test.AuthorizationAttribute
{
    [TestClass]
    public class MvcAuthorizeAttributeAnalyzerTest : AuthorizationAttributeAnalyzerTest
    {
        protected override string Namespace => "System.Web.Mvc";

        protected override string[] Namespaces => new [] { "System.Web.Mvc" };

        protected override string AuthorizeAttributeName => "Authorize";

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(System.Web.Mvc.AuthorizeAttribute).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;
    }

    [TestClass]
    public class CoreAuthorizeAttributeAnalyzerTest : AuthorizationAttributeAnalyzerTest
    {
        protected override string Namespace => "Microsoft.AspNetCore.Mvc";

        protected override string[] Namespaces => new [] { "Microsoft.AspNetCore.Authorization", "Microsoft.AspNetCore.Mvc" };

        protected override string AuthorizeAttributeName => "Authorize";

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.Controller).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Authorization.AuthorizeAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.HttpPostAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Authorization.AllowAnonymousAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(Assembly.Load("netstandard, Version=2.0.0.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51")
                                                     .Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;
    }

    public abstract class AuthorizationAttributeAnalyzerTest : DiagnosticVerifier
    {
        protected abstract string Namespace { get; }

        protected abstract string[] Namespaces { get; }

        protected abstract string AuthorizeAttributeName { get; }

        protected DiagnosticResult Expected = new DiagnosticResult
        {
            Id = AthorizationAttributeDiagnosticAnalyzer.DiagnosticId,
            Severity = DiagnosticSeverity.Warning
        };

        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            if (language == LanguageNames.CSharp)
                return new DiagnosticAnalyzer[] { new CSharpAnalyzers(new AthorizationAttributeDiagnosticAnalyzer()) };
            else
                return new DiagnosticAnalyzer[] { new VBasicAnalyzers(new AthorizationAttributeDiagnosticAnalyzer()) };
        }

        private string InsertNamespacesCS()
        {
            var sb = new StringBuilder();
            sb.AppendLine("#pragma warning disable 8019");
            foreach (var n in Namespaces)
            {
                sb.AppendLine($"using {n};");
            }
            sb.AppendLine("#pragma warning restore 8019");
            return sb.ToString();
        }

        private string InsertNamespacesVB()
        {
            var sb = new StringBuilder();
            sb.AppendLine("#Disable Warning BC50001");
            foreach (var n in Namespaces)
            {
                sb.AppendLine($"Imports {n}");
            }
            sb.AppendLine("#Enable Warning BC50001");
            return sb.ToString();
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task HasAllowAnonymousAttribute()
        {
            var cSharpTest = $@"
{InsertNamespacesCS()}

namespace VulnerableApp
{{
    public class TestController : Controller
    {{
        [AllowAnonymous]
        [HttpPost]
        public ActionResult ControllerMethod(string input)
        {{
            return null;
        }}
    }}
}}
";

            var visualBasicTest = $@"
{InsertNamespacesVB()}

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller

        <AllowAnonymous>
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
        public async Task ClassHasAuthorizeAttribute()
        {
            var cSharpTest = $@"
{InsertNamespacesCS()}

namespace VulnerableApp
{{
    [{AuthorizeAttributeName}]
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
{InsertNamespacesVB()}

Namespace VulnerableApp
    <{AuthorizeAttributeName}>
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

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectMissingAttribute()
        {
            var cSharpTest = $@"
{InsertNamespacesCS()}

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
{InsertNamespacesVB()}

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
            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }
    }
}
