using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.CodeFixes;
using TestHelper;

namespace SecurityCodeScan.Test.AntiCsrf
{
    public abstract class CsrfTokenCodeFixProviderTest : CodeFixVerifier
    {
        protected abstract string Namespace { get; }

        protected override CodeFixProvider GetCSharpCodeFixProvider()
        {
            return new CsrfTokenCodeFixProvider();
        }

        [TestMethod]
        public async Task CsrfVerifyTokenAdded()
        {
            var before = $@"
using {Namespace};

public class TestController
{{

    //Test comment
    [HttpPost]
    public ActionResult ControllerMethod(string input) {{
        return null;
    }}
}}
";

            var after = $@"
using {Namespace};

public class TestController
{{

    //Test comment
    [HttpPost]
    [ValidateAntiForgeryToken]
    public ActionResult ControllerMethod(string input) {{
        return null;
    }}
}}
";

            await VerifyCSharpFix(before, after);
        }
    }

    [TestClass]
    public class MvcCsrfTokenCodeFixProviderTest : CsrfTokenCodeFixProviderTest
    {
        protected override string Namespace => "System.Web.Mvc";

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[]
            {
                MetadataReference.CreateFromFile(typeof(System.Web.Mvc.ValidateAntiForgeryTokenAttribute).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Web.Mvc.HttpPostAttribute).Assembly.Location)
            };
        }

        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new[] { new MvcCsrfTokenAnalyzer() };
        }
    }

    [TestClass]
    public class CoreCsrfTokenCodeFixProviderTest : CsrfTokenCodeFixProviderTest
    {
        protected override string Namespace => "Microsoft.AspNetCore.Mvc";

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[]
            {
                MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.ValidateAntiForgeryTokenAttribute).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.HttpPostAttribute).Assembly.Location)
            };
        }

        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new[] { new CoreCsrfTokenAnalyzer() };
        }
    }
}
