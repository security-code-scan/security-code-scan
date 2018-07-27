using System.Collections.Generic;
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
        [DataRow("SqlCommand", "new SqlCommand { CommandText = sql }")]
        [DataRow("DbCommand",  "new SqlCommand { CommandText = sql }")]
        [DataRow("IDbCommand", "new SqlCommand { CommandText = sql }")]
        [DataRow("SqlCommand", "new SqlCommand(); sqlCommand.CommandText = sql")]
        [DataRow("DbCommand",  "new SqlCommand(); sqlCommand.CommandText = sql")]
        [DataRow("IDbCommand", "new SqlCommand(); sqlCommand.CommandText = sql")]
        [DataRow("SqlCommand", "Create(); sqlCommand.CommandText = sql")]
        [DataRow("DbCommand",  "Create(); sqlCommand.CommandText = sql")]
        [DataRow("IDbCommand", "Create(); sqlCommand.CommandText = sql")]
        public async Task CommandTextUnSafeCSharp(string type, string factory)
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
                                         new DiagnosticResult { Id = "SCS0026" }.WithLocation("Test0.cs", 14))
                .ConfigureAwait(false);
        }

        [DataTestMethod]
        [DataRow("SqlCommand", "New SqlCommand With \r\n{ .CommandText = sql }")]
        [DataRow("DbCommand",  "New SqlCommand With \r\n{ .CommandText = sql }")]
        [DataRow("IDbCommand", "New SqlCommand With \r\n{ .CommandText = sql }")]
        [DataRow("SqlCommand", "New SqlCommand\r\nsqlCommand.CommandText = sql")]
        [DataRow("DbCommand",  "New SqlCommand\r\nsqlCommand.CommandText = sql")]
        [DataRow("IDbCommand", "New SqlCommand\r\nsqlCommand.CommandText = sql")]
        [DataRow("SqlCommand", "Create()\r\nsqlCommand.CommandText = sql")]
        [DataRow("DbCommand",  "Create()\r\nsqlCommand.CommandText = sql")]
        [DataRow("IDbCommand", "Create()\r\nsqlCommand.CommandText = sql")]
        public async Task CommandTextUnSafeVBasic(string type, string factory)
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
                                              new DiagnosticResult { Id = "SCS0026" }.WithLocation("Test0.vb", 12))
                .ConfigureAwait(false);
        }
    }
}
