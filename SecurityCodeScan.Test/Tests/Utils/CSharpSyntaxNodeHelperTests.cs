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
    public sealed class CSharpSyntaxNodeHelperTests : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            return new DiagnosticAnalyzer[]
            {
                new UnsafeDeserializationAnalyzerCSharp(),
                new TaintAnalyzerCSharp(),
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
            var cSharpTest = @"
using System.Web.Script.Serialization;
using JSS = System.Web.Script.Serialization.JavaScriptSerializer;

namespace VulnerableApp
{
    class Test
    {
        private JSS serializer = new JSS(new SimpleTypeResolver());
    }
}
";
            var expected = new DiagnosticResult()
            {
                Id = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 9, 34)).ConfigureAwait(false);
        }
    }
}
