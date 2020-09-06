using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Audit;
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test.Taint
{
    [TestClass]
    public class LdapInjectionAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string _)
        {
            return new DiagnosticAnalyzer[] { new LdapPathTaintAnalyzer(), new LdapFilterTaintAnalyzer() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(System.DirectoryServices.DirectorySearcher).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Web.Mvc.Controller).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [DataRow("new DirectorySearcher(input)", "SCS0031")]
        [DataRow("new DirectorySearcher(\"constant\")")]
        [DataRow("new DirectorySearcher(input, null)", "SCS0031")]
        [DataRow("new DirectorySearcher(\"constant\", propertiesToLoad)")]
        [DataRow("new DirectorySearcher(input, propertiesToLoad)", "SCS0031")]
        [DataRow("new DirectorySearcher(\"constant\", null)")]
        [DataRow("new DirectorySearcher(entry, input)", "SCS0031")]
        [DataRow("new DirectorySearcher(entry, \"constant\")")]
        [DataRow("new DirectorySearcher(entry, input, null)", "SCS0031")]
        [DataRow("new DirectorySearcher(entry, \"constant\", propertiesToLoad)")]
        [DataRow("new DirectorySearcher(entry, \"constant\", null)")]
        [DataRow("new DirectorySearcher(input, null, scope)", "SCS0031")]
        [DataRow("new DirectorySearcher(\"constant\", propertiesToLoad, scope)")]
        [DataRow("new DirectorySearcher(\"constant\", null, scope)")]
        [DataRow("new DirectorySearcher(entry, input, null, scope)", "SCS0031")]
        [DataRow("new DirectorySearcher(entry, \"constant\", propertiesToLoad, scope)")]
        [DataRow("new DirectorySearcher(entry, \"constant\", null, scope)")]
        [DataRow("new DirectorySearcher(); temp.Filter = input", "SCS0031")]
        [DataRow("new DirectorySearcher(); temp.Filter = $\"{input}\"", "SCS0031")]
        [DataRow("new DirectorySearcher(); temp.Filter = \"constant\"")]
        [DataRow("new DirectoryEntry(input)", "SCS0026")]
        [DataRow("new DirectoryEntry(\"constant\")")]
        [DataRow("new DirectoryEntry(input, \"\", \"\")", "SCS0026")]
        [DataRow("new DirectoryEntry(\"constant\", \"\", \"\")")]
        [DataRow("new DirectoryEntry(input, \"\", \"\", AuthenticationTypes.None)", "SCS0026")]
        [DataRow("new DirectoryEntry(\"constant\", \"username\", \"password\", AuthenticationTypes.None)")]
        [DataRow("new DirectoryEntry(); temp.Path = input", "SCS0026")]
        [DataRow("new DirectoryEntry(); temp.Path = \"constant\"")]
        [DataTestMethod]
        public async Task LdapInjection(string sink, string warningId = null, int count = 1)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System.DirectoryServices;
    using System.Web.Mvc;
#pragma warning restore 8019

namespace sample
{{
    public class MyFooController : Controller
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
    Public Class MyFooController
        Inherits Controller
        Public Sub Run(input As System.String, propertiesToLoad() As System.String, entry As DirectoryEntry, scope As SearchScope )
            Dim temp = {sink.CSharpReplaceToVBasic()}
        End Sub
    End Class
End Namespace
";
            if (warningId != null)
            {
                var expected = new DiagnosticResult
                {
                    Id = warningId,
                    Severity = DiagnosticSeverity.Warning,
                };

                await VerifyCSharpDiagnostic(cSharpTest, Enumerable.Repeat(expected, count).ToArray()).ConfigureAwait(false);
                await VerifyCSharpDiagnostic(cSharpTest, Enumerable.Repeat(expected, count).ToArray(), await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false)).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, Enumerable.Repeat(expected, count).ToArray()).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
            }
        }
    }
}
