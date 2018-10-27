using System.Collections.Generic;
using System.Data.Linq;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Helpers;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test.Taint
{
    [TestClass]
    public class LinqSqlInjectionAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            return new DiagnosticAnalyzer[] { new TaintAnalyzerCSharp(), new TaintAnalyzerVisualBasic(), };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(DataContext).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [DataRow("ctx.ExecuteQuery<UserEntity>(input)", true)]
        [DataRow("ctx.ExecuteQuery<UserEntity>(\"select\")", false)]
        [DataRow("ctx.ExecuteQuery(typeof(UserEntity), input)", true)]
        [DataRow("ctx.ExecuteQuery(typeof(UserEntity), \"select\")", false)]
        [DataRow("ctx.ExecuteCommand(input)", true)]
        [DataRow("ctx.ExecuteCommand(\"select\")", false)]        
        [DataTestMethod]        
        public async Task LinqInjection(string sink, bool warn)
        {
            var cSharpTest = $@"
using System.Data.Linq;

namespace VulnerableApp
{{
    public class LyncInjectionTP
    {{
        public static int Run(DataContext ctx, string input) {{
            {sink};
            return 0;
        }}
    }}

    class UserEntity
    {{
    }}
}}";
            sink = sink.Replace("null", "Nothing")                
                .Replace("<UserEntity>", "(Of UserEntity)")
                .Replace("typeof", "GetType");

            var visualBasicTest = $@"
Imports System.Data.Linq

Namespace VulnerableApp
    Public Class LyncInjectionTP
        Public Shared Function Run(ctx As DataContext, input As String) As Integer
            {sink}
            Return 0
        End Function
    End Class

    Class UserEntity
    End Class
End Namespace
        ";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0002",
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
