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
    public class CommandTextAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string _)
        {
            return new[] { new SqlInjectionTaintAnalyzer() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(System.Data.SQLite.SQLiteCommand).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.Data.Sqlite.SqliteCommand).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Web.Mvc.Controller).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("SqliteCommand", "Microsoft.Data.Sqlite")]
        [DataRow("SQLiteCommand", "System.Data.SQLite")]
        [DataRow("SqlCommand",    "System.Data.SqlClient")]
        public async Task SqlInjectionCommandText(string type, string ns)
        {
            var options = new[]
            {
                new { value = "sql", warn        = true },
                new { value = "\"select\"", warn = false },
            };

            foreach (var option in options)
            {
                foreach (var row in new[] { type, "DbCommand", "IDbCommand" })
                {
                    await CommandTextUnsafeCSharpWorker(row, $"new {type} {{ CommandText = {option.value} }}",         option.warn, ns);
                    await CommandTextUnsafeCSharpWorker(row, $"new {type}(); sqlCommand.CommandText = {option.value}", option.warn, ns);
                    await CommandTextUnsafeCSharpWorker(row, $"Create(); sqlCommand.CommandText = {option.value}",     option.warn, ns);

                    await CommandTextUnsafeVBasicWorker(row, $"New {type} With \r\n{{ .CommandText = {option.value} }}", option.warn, ns);
                    await CommandTextUnsafeVBasicWorker(row, $"New {type}\r\nsqlCommand.CommandText =  {option.value}",  option.warn, ns);
                    await CommandTextUnsafeVBasicWorker(row, $"Create\r\nsqlCommand.CommandText =  {option.value}",      option.warn, ns);
                }
            }
        }

        public async Task CommandTextUnsafeCSharpWorker(string type, string factory, bool warn, string ns)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System.Data.Common;
    using System.Data;
    using System.Web.Mvc;
    using {ns};
#pragma warning restore 8019

namespace sample
{{
    public class MyFooController : Controller
    {{
        public void Run(string sql)
        {{
            {type} sqlCommand = {factory};
        }}

        {type} Create()
        {{
            return null;
        }}
    }}
}}
";

            if (warn)
            {
                await VerifyCSharpDiagnostic(cSharpTest,
                                             new DiagnosticResult { Id = "SCS0002" }.WithLocation(15))
                    .ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            }
        }

        public async Task CommandTextUnsafeVBasicWorker(string type, string factory, bool warn, string ns)
        {
            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System.Data.Common
    Imports System.Data
    Imports System.Web.Mvc
    Imports {ns}
#Enable Warning BC50001

Namespace sample
    Public Class MyFooController
        Inherits Controller

        Public Sub Run(sql As System.String)
            Dim sqlCommand = {factory}
        End Sub

        Private Function Create() As {type}
            Return Nothing
        End Function
    End Class
End Namespace
";

            if (warn)
            {
                await VerifyVisualBasicDiagnostic(visualBasicTest,
                                                  new DiagnosticResult { Id = "SCS0002" }.WithLocation(15))
                    .ConfigureAwait(false);
            }
            else
            {
                await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
            }
        }
    }
}
