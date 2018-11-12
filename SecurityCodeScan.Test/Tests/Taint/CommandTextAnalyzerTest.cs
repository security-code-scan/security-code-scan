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
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            return new List<DiagnosticAnalyzer> { new TaintAnalyzerCSharp(), new TaintAnalyzerVisualBasic() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(System.Data.SQLite.SQLiteCommand).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("SQLiteCommand", "new SQLiteCommand { CommandText = sql }", true)]
        [DataRow("DbCommand",     "new SQLiteCommand { CommandText = sql }", true)]
        [DataRow("IDbCommand",    "new SQLiteCommand { CommandText = sql }", true)]
        [DataRow("SQLiteCommand", "new SQLiteCommand(); sqlCommand.CommandText = sql", true)]
        [DataRow("DbCommand",     "new SQLiteCommand(); sqlCommand.CommandText = sql", true)]
        [DataRow("IDbCommand",    "new SQLiteCommand(); sqlCommand.CommandText = sql", true)]
        [DataRow("SQLiteCommand", "Create(); sqlCommand.CommandText = sql", true)]

        [DataRow("SqlCommand",    "new SqlCommand { CommandText = sql }", true)]
        [DataRow("DbCommand",     "new SqlCommand { CommandText = sql }", true)]
        [DataRow("IDbCommand",    "new SqlCommand { CommandText = sql }", true)]
        [DataRow("SqlCommand",    "new SqlCommand(); sqlCommand.CommandText = sql", true)]
        [DataRow("DbCommand",     "new SqlCommand(); sqlCommand.CommandText = sql", true)]
        [DataRow("IDbCommand",    "new SqlCommand(); sqlCommand.CommandText = sql", true)]
        [DataRow("SqlCommand",    "Create(); sqlCommand.CommandText = sql", true)]
        [DataRow("DbCommand",     "Create(); sqlCommand.CommandText = sql", true)]
        [DataRow("IDbCommand",    "Create(); sqlCommand.CommandText = sql", true)]

        [DataRow("SQLiteCommand", "new SQLiteCommand { CommandText = \"select\" }",           false)]
        [DataRow("DbCommand",     "new SQLiteCommand { CommandText = \"select\" }",           false)]
        [DataRow("IDbCommand",    "new SQLiteCommand { CommandText = \"select\" }",           false)]
        [DataRow("SQLiteCommand", "new SQLiteCommand(); sqlCommand.CommandText = \"select\"", false)]
        [DataRow("DbCommand",     "new SQLiteCommand(); sqlCommand.CommandText = \"select\"", false)]
        [DataRow("IDbCommand",    "new SQLiteCommand(); sqlCommand.CommandText = \"select\"", false)]
        [DataRow("SQLiteCommand", "Create(); sqlCommand.CommandText = \"select\"",            false)]

        [DataRow("SqlCommand", "new SqlCommand { CommandText = \"select\" }",           false)]
        [DataRow("DbCommand",  "new SqlCommand { CommandText = \"select\" }",           false)]
        [DataRow("IDbCommand", "new SqlCommand { CommandText = \"select\" }",           false)]
        [DataRow("SqlCommand", "new SqlCommand(); sqlCommand.CommandText = \"select\"", false)]
        [DataRow("DbCommand",  "new SqlCommand(); sqlCommand.CommandText = \"select\"", false)]
        [DataRow("IDbCommand", "new SqlCommand(); sqlCommand.CommandText = \"select\"", false)]
        [DataRow("SqlCommand", "Create(); sqlCommand.CommandText = \"select\"",         false)]
        [DataRow("DbCommand",  "Create(); sqlCommand.CommandText = \"select\"",         false)]
        [DataRow("IDbCommand", "Create(); sqlCommand.CommandText = \"select\"",         false)]
        public async Task CommandTextUnsafeCSharp(string type, string factory, bool warn)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System.Data.SqlClient;
    using System.Data.Common;
    using System.Data;
    using System.Data.SQLite;
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

            if (warn)
            {
                await VerifyCSharpDiagnostic(cSharpTest,
                                             new DiagnosticResult { Id = "SCS0026" }.WithLocation(15))
                    .ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            }
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("SQLiteCommand", "New SQLiteCommand With \r\n{ .CommandText = sql }", true)]
        [DataRow("DbCommand",     "New SQLiteCommand With \r\n{ .CommandText = sql }", true)]
        [DataRow("IDbCommand",    "New SQLiteCommand With \r\n{ .CommandText = sql }", true)]
        [DataRow("SQLiteCommand", "New SQLiteCommand\r\nsqlCommand.CommandText = sql", true)]
        [DataRow("DbCommand",     "New SQLiteCommand\r\nsqlCommand.CommandText = sql", true)]
        [DataRow("IDbCommand",    "New SQLiteCommand\r\nsqlCommand.CommandText = sql", true)]
        [DataRow("SQLiteCommand", "Create\r\nsqlCommand.CommandText = sql", true)]

        [DataRow("SqlCommand", "New SqlCommand With \r\n{ .CommandText = sql }", true)]
        [DataRow("DbCommand",  "New SqlCommand With \r\n{ .CommandText = sql }", true)]
        [DataRow("IDbCommand", "New SqlCommand With \r\n{ .CommandText = sql }", true)]
        [DataRow("SqlCommand", "New SqlCommand\r\nsqlCommand.CommandText = sql", true)]
        [DataRow("DbCommand",  "New SqlCommand\r\nsqlCommand.CommandText = sql", true)]
        [DataRow("IDbCommand", "New SqlCommand\r\nsqlCommand.CommandText = sql", true)]
        [DataRow("SqlCommand", "Create()\r\nsqlCommand.CommandText = sql", true)]
        [DataRow("DbCommand",  "Create()\r\nsqlCommand.CommandText = sql", true)]
        [DataRow("IDbCommand", "Create()\r\nsqlCommand.CommandText = sql", true)]

        [DataRow("SQLiteCommand", "New SQLiteCommand With \r\n{ .CommandText = \"select\" }", false)]
        [DataRow("DbCommand",     "New SQLiteCommand With \r\n{ .CommandText = \"select\" }", false)]
        [DataRow("IDbCommand",    "New SQLiteCommand With \r\n{ .CommandText = \"select\" }", false)]
        [DataRow("SQLiteCommand", "New SQLiteCommand\r\nsqlCommand.CommandText = \"select\"", false)]
        [DataRow("DbCommand",     "New SQLiteCommand\r\nsqlCommand.CommandText = \"select\"", false)]
        [DataRow("IDbCommand",    "New SQLiteCommand\r\nsqlCommand.CommandText = \"select\"", false)]
        [DataRow("SQLiteCommand", "Create\r\nsqlCommand.CommandText = \"select\"",            false)]

        [DataRow("SqlCommand", "New SqlCommand With \r\n{ .CommandText = \"select\" }", false)]
        [DataRow("DbCommand",  "New SqlCommand With \r\n{ .CommandText = \"select\" }", false)]
        [DataRow("IDbCommand", "New SqlCommand With \r\n{ .CommandText = \"select\" }", false)]
        [DataRow("SqlCommand", "New SqlCommand\r\nsqlCommand.CommandText = \"select\"", false)]
        [DataRow("DbCommand",  "New SqlCommand\r\nsqlCommand.CommandText = \"select\"", false)]
        [DataRow("IDbCommand", "New SqlCommand\r\nsqlCommand.CommandText = \"select\"", false)]
        [DataRow("SqlCommand", "Create()\r\nsqlCommand.CommandText = \"select\"",       false)]
        [DataRow("DbCommand",  "Create()\r\nsqlCommand.CommandText = \"select\"",       false)]
        [DataRow("IDbCommand", "Create()\r\nsqlCommand.CommandText = \"select\"",       false)]
        public async Task CommandTextUnsafeVBasic(string type, string factory, bool warn)
        {
            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System.Data.SqlClient
    Imports System.Data.Common
    Imports System.Data
    Imports System.Data.SQLite
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

            if (warn)
            {
                await VerifyVisualBasicDiagnostic(visualBasicTest,
                                                  new DiagnosticResult { Id = "SCS0026" }.WithLocation(13))
                    .ConfigureAwait(false);
            }
            else
            {
                await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
            }
        }
    }
}
