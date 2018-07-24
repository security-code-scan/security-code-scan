using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test.Taint
{
    [TestClass]
    public class CommandTextAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            return new List<DiagnosticAnalyzer> { new TaintAnalyzerCSharp(), new TaintAnalyzerVisualBasic() };
        }

        [DataTestMethod]
        [DataRow("SqlCommand", "new SqlCommand { CommandText = sql }",           new[] { "SCS0026" })]
        [DataRow("DbCommand",  "new SqlCommand { CommandText = sql }",           new[] { "SCS0026" })]
        [DataRow("IDbCommand", "new SqlCommand { CommandText = sql }",           new[] { "SCS0026" })]
        [DataRow("SqlCommand", "new SqlCommand(); sqlCommand.CommandText = sql", new[] { "SCS0026" })]
        [DataRow("DbCommand",  "new SqlCommand(); sqlCommand.CommandText = sql", new[] { "SCS0026" })]
        [DataRow("IDbCommand", "new SqlCommand(); sqlCommand.CommandText = sql", new[] { "SCS0026" })]
        [DataRow("SqlCommand", "Create(); sqlCommand.CommandText = sql",         new[] { "SCS0026" })]
        [DataRow("DbCommand",  "Create(); sqlCommand.CommandText = sql",         new[] { "SCS0026" })]
        [DataRow("IDbCommand", "Create(); sqlCommand.CommandText = sql",         new[] { "SCS0026" })]
        public async Task CommandTextUnSafeCSharp(string type, string factory, string[] csErrors)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System.Data.SqlClient;
    using System.Data.Common;
    using System.Data;
#pragma warning restore 8019

namespace sample
{{
    class MyFoo
    {{
        public static void Run(string sql)
        {{
            {type} sqlCommand = {factory};
        }}

        static {type} Create()
        {{
            return null;
        }}
    }}
}}
";

            await VerifyCSharpDiagnostic(cSharpTest,
                                         csErrors.Select(x => new DiagnosticResult { Id = x }.WithLocation("Test0.cs", 14)).ToArray())
                .ConfigureAwait(false);
        }

        [DataTestMethod]
        [DataRow("SqlCommand", "New SqlCommand With \r\n{ .CommandText = sql }", new[] { "SCS0026" })]
        [DataRow("DbCommand",  "New SqlCommand With \r\n{ .CommandText = sql }", new[] { "SCS0026" })]
        [DataRow("IDbCommand", "New SqlCommand With \r\n{ .CommandText = sql }", new[] { "SCS0026" })]
        [DataRow("SqlCommand", "New SqlCommand\r\nsqlCommand.CommandText = sql", new[] { "SCS0026" })]
        [DataRow("DbCommand",  "New SqlCommand\r\nsqlCommand.CommandText = sql", new[] { "SCS0026" })]
        [DataRow("IDbCommand", "New SqlCommand\r\nsqlCommand.CommandText = sql", new[] { "SCS0026" })]
        [DataRow("SqlCommand", "Create()\r\nsqlCommand.CommandText = sql",       new[] { "SCS0026" })]
        [DataRow("DbCommand",  "Create()\r\nsqlCommand.CommandText = sql",       new[] { "SCS0026" })]
        [DataRow("IDbCommand", "Create()\r\nsqlCommand.CommandText = sql",       new[] { "SCS0026" })]
        public async Task CommandTextUnSafeVBasic(string type, string factory, string[] vbErrors)
        {
            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System.Data.SqlClient
    Imports System.Data.Common
    Imports System.Data
#Enable Warning BC50001

Namespace sample
    Class MyFoo
        Public Shared Sub Run(sql As System.String)
            Dim sqlCommand = {factory}
        End Sub

        Private Shared Function Create() As {type}
            Return Nothing
        End Function
    End Class
End Namespace
";

            await VerifyVisualBasicDiagnostic(visualBasicTest,
                                              vbErrors.Select(x => new DiagnosticResult { Id = x }.WithLocation("Test0.vb", 12)).ToArray())
                .ConfigureAwait(false);
        }
    }
}
