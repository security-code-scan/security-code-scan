using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test.Taint
{
    [TestClass]
    public class LdapInjectionAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            if (language == LanguageNames.CSharp)
                return new DiagnosticAnalyzer[] { new CSharpAnalyzers(new TaintAnalyzerCSharp()) };
            else
                return new DiagnosticAnalyzer[] { new VBasicAnalyzers(new TaintAnalyzerVisualBasic()) };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(System.DirectoryServices.DirectorySearcher).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Web.Mvc.Controller).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [DataRow("new DirectorySearcher(input)", true)]
        [DataRow("new DirectorySearcher(\"constant\")", false)]
        [DataRow("new DirectorySearcher(input, null)", true)]
        [DataRow("new DirectorySearcher(\"constant\", propertiesToLoad)", true)]
        [DataRow("new DirectorySearcher(\"constant\", null)", false)]
        [DataRow("new DirectorySearcher(entry, input)", true)]
        [DataRow("new DirectorySearcher(entry, \"constant\")", false)]
        [DataRow("new DirectorySearcher(entry, input, null)", true)]
        [DataRow("new DirectorySearcher(entry, \"constant\", propertiesToLoad)", true)]
        [DataRow("new DirectorySearcher(entry, \"constant\", null)", false)]
        [DataRow("new DirectorySearcher(input, null, scope)", true)]
        [DataRow("new DirectorySearcher(\"constant\", propertiesToLoad, scope)", true)]
        [DataRow("new DirectorySearcher(\"constant\", null, scope)", false)]
        [DataRow("new DirectorySearcher(entry, input, null, scope)", true)]
        [DataRow("new DirectorySearcher(entry, \"constant\", propertiesToLoad, scope)", true)]
        [DataRow("new DirectorySearcher(entry, \"constant\", null, scope)", false)]
        [DataRow("new DirectorySearcher(); temp.Filter = input", true)]
        [DataRow("new DirectorySearcher(); temp.Filter = \"constant\"", false)]
        [DataRow("new DirectoryEntry(input)", true)]
        [DataRow("new DirectoryEntry(\"constant\")", false)]
        [DataRow("new DirectoryEntry(input, \"\", \"\")", true)]
        [DataRow("new DirectoryEntry(\"constant\", \"\", \"\")", false)]
        [DataRow("new DirectoryEntry(input, \"\", \"\", AuthenticationTypes.None)", true)]
        [DataRow("new DirectoryEntry(\"constant\", \"username\", \"password\", AuthenticationTypes.None)", false)]
        [DataRow("new DirectoryEntry(); temp.Path = input", true)]
        [DataRow("new DirectoryEntry(); temp.Path = \"constant\"", false)]
        [DataTestMethod]
        public async Task LdapInjection(string sink, bool warn)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System.DirectoryServices;
    using System.Web.Mvc;
#pragma warning restore 8019

namespace sample
{{
    class MyFoo : Controller
    {{
        public void Run(string input, string[] propertiesToLoad, DirectoryEntry entry, SearchScope scope)
        {{
            var temp = {sink};
        }}
    }}
}}
";

            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System.DirectoryServices
    Imports System.Web.Mvc
#Enable Warning BC50001

Namespace sample
    Class MyFoo
        Inherits Controller
        Public Sub Run(input As System.String, propertiesToLoad() As System.String, entry As DirectoryEntry, scope As SearchScope )
            Dim temp = {sink.CSharpReplaceToVBasic()}
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
