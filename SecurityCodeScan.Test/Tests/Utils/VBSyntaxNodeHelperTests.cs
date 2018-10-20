using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Helpers;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace SecurityCodeScan.Test.Tests.Utils
{
    [TestClass]
    public sealed class VBSyntaxNodeHelperTests : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            return new DiagnosticAnalyzer[]
            {
                new UnsafeDeserializationAnalyzerVisualBasic(),
                new TaintAnalyzerVisualBasic(),
            };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(JavaScriptSerializer).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(JsonSerializer).Assembly.Location),
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestMethod]
        public async Task GivenAliasDirective_DetectDiagnostic()
        {
            var visualBasicTest = @"
Imports System.Web.Script.Serialization
Imports JSS = System.Web.Script.Serialization.JavaScriptSerializer

Namespace VulnerableApp
    Class Test
        Private Dim serializer = new JSS(new SimpleTypeResolver())
    End Class
End Namespace
";
            var expected = new DiagnosticResult()
            {
                Id = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 7, 34)).ConfigureAwait(false);
        }
    }
}
