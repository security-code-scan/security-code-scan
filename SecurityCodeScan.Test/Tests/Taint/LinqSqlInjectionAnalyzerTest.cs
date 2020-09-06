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
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string _)
        {
            return new[] { new SqlInjectionTaintAnalyzer() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(DataContext).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Web.Mvc.Controller).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [DataRow("ctx.ExecuteQuery<Object>(input)",              true)]
        [DataRow("ctx.ExecuteQuery<Object>(\"select\")",         false)]
        [DataRow("ctx.ExecuteQuery(typeof(Object), input)",      true)]
        [DataRow("ctx.ExecuteQuery(typeof(Object), \"select\")", false)]
        [DataRow("ctx.ExecuteCommand(input)",                        true)]
        [DataRow("ctx.ExecuteCommand(\"select\")",                   false)]
        [DataTestMethod]
        public async Task LinqInjection(string sink, bool warn)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System.Data.Linq;
    using System;
    using System.Web.Mvc;
#pragma warning restore 8019

namespace VulnerableApp
{{
    public class LyncInjectionTPController : Controller
    {{
        public int Run(DataContext ctx, string input) {{
            {sink};
            return 0;
        }}
    }}
}}";
            sink = sink.CSharpReplaceToVBasic();

            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System.Data.Linq
    Imports System
    Imports System.Web.Mvc
#Enable Warning BC50001

Namespace VulnerableApp
    Public Class LyncInjectionTPController
        Inherits Controller

        Public Function Run(ctx As DataContext, input As String) As Integer
            {sink}
            Return 0
        End Function
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
