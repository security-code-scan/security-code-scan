using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test.Taint
{
    [TestClass]
    public class LdapInjectionAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            return new List<DiagnosticAnalyzer> { new TaintAnalyzerCSharp(), new TaintAnalyzerVisualBasic() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(System.DirectoryServices.DirectorySearcher).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [DataRow("new DirectorySearcher(input)", true)]
        [DataRow("new DirectorySearcher(\"constant\")", false)]
        
        [DataRow("new DirectorySearcher(input, propertiesToLoad)", true)]
        [DataRow("new DirectorySearcher(input, null)", true)]
        [DataRow("new DirectorySearcher(\"constant\", propertiesToLoad)", true)]
        [DataRow("new DirectorySearcher(\"constant\", null)", false)]
        
        [DataRow("new DirectorySearcher(entry, input)", true)]
        [DataRow("new DirectorySearcher(entry, \"constant\")", false)]

        [DataRow("new DirectorySearcher(entry, input, propertiesToLoad)", true)]
        [DataRow("new DirectorySearcher(entry, input, null)", true)]
        [DataRow("new DirectorySearcher(entry, \"constant\", propertiesToLoad)", true)]
        [DataRow("new DirectorySearcher(entry, \"constant\", null)", false)]
        
        [DataRow("new DirectorySearcher(input, propertiesToLoad, scope)", true)]
        [DataRow("new DirectorySearcher(input, null, scope)", true)]
        [DataRow("new DirectorySearcher(\"constant\", propertiesToLoad, scope)", true)]
        [DataRow("new DirectorySearcher(\"constant\", null, scope)", false)]

        [DataRow("new DirectorySearcher(entry, input, propertiesToLoad, scope)", true)]
        [DataRow("new DirectorySearcher(entry, input, null, scope)", true)]
        [DataRow("new DirectorySearcher(entry, \"constant\", propertiesToLoad, scope)", true)]
        [DataRow("new DirectorySearcher(entry, \"constant\", null, scope)", false)]
        
        [DataRow("new DirectorySearcher(); temp.Filter = input", true)]
        [DataRow("new DirectorySearcher(); temp.Filter = \"constant\"", false)]

        [DataTestMethod]
        public async Task LdapInjection(string sink, bool warn)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System.DirectoryServices;
#pragma warning restore 8019

namespace sample
{{
    class MyFoo
    {{
        public static void Run(string input, string[] propertiesToLoad, DirectoryEntry entry, SearchScope scope)
        {{
            var temp = {sink};
        }}
    }}
}}
";

            sink = sink.Replace("null", "Nothing")
                .Replace(";", "\r\n")
                .Replace("var ", "Dim ")
                .Replace("new ", "New ")
                .Replace("<Object>", "(Of Object)");

            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System.DirectoryServices
#Enable Warning BC50001

Namespace sample
    Class MyFoo
        Public Shared Sub Run(input As System.String, propertiesToLoad() As System.String, entry As DirectoryEntry, scope As SearchScope )
            Dim temp = {sink}
        End Sub
    End Class
End Namespace
";
            var expected = new DiagnosticResult
            {
                Id = "SCS0031",
                Severity = DiagnosticSeverity.Warning,
            };

            if (warn)
            {
                await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
            }
        }
    }
}
