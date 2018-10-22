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
    public class SqlInjectionAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            return new List<DiagnosticAnalyzer> { new TaintAnalyzerCSharp(), new TaintAnalyzerVisualBasic() };
        }

        private static readonly PortableExecutableReference[] References =
        {            
            MetadataReference.CreateFromFile(typeof(System.Web.UI.WebControls.SqlDataSource).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Data.Entity.DbContext).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.Practices.EnterpriseLibrary.Data.Sql.SqlDatabase).Assembly.Location)
        };       

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;


        [DataRow("var temp = new SqlDataAdapter(sqlQuery, new SqlConnection())")]
        [DataRow("var temp = new SqlDataSource(\"connectionString\", sqlQuery)")]
        [DataRow("var temp = new SqlDataSource(\"providerName\",\"connectionString\", sqlQuery)")]
        [DataRow("var temp = new DbContext(\"connectionString\").Database.SqlQuery(null, sqlQuery, null)")]
        [DataRow("var temp = new DbContext(\"connectionString\").Database.ExecuteSqlCommand(sqlQuery, parameters)")]
        [DataRow("var temp = new DbContext(\"connectionString\").Database.ExecuteSqlCommand(TransactionalBehavior.DoNotEnsureTransaction, sqlQuery, parameters)")]
        [DataRow("var temp = new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(sqlQuery, parameters)")]
        [DataRow("var temp = new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(TransactionalBehavior.DoNotEnsureTransaction, sqlQuery, parameters)")]
        [DataRow("var temp = new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(sqlQuery, new CancellationToken(), parameters)")]
        [DataRow("var temp = new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(TransactionalBehavior.DoNotEnsureTransaction, sqlQuery, new CancellationToken(), parameters)")]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteDataSet(CommandType.Text, sqlQuery)")]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteReader(CommandType.Text, sqlQuery)")]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteNonQuery(CommandType.Text, sqlQuery)")]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteScalar(CommandType.Text, sqlQuery)")]
        [DataTestMethod]
        public async Task SqlInjectionVulnerable(string sink)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System.Data.SqlClient;
    using System.Data.Common;
    using System.Data;
    using System.Web.UI.WebControls;
    using System.Data.Entity;
    using System.Threading;
    using Microsoft.Practices.EnterpriseLibrary.Data.Sql;
#pragma warning restore 8019

namespace sample
{{
    class MyFoo
    {{
        public static void Run(string sqlQuery, params object[] parameters)
        {{
            {sink};
        }}       
    }}
}}
";

            sink = sink.Replace("null", "Nothing")
                .Replace("var ", "Dim ")
                .Replace("new ", "New ");
            
            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System.Data.SqlClient
    Imports System.Data.Common
    Imports System.Data
    Imports System.Web.UI.WebControls
    Imports System.Data.Entity
    Imports System.Threading
    Imports Microsoft.Practices.EnterpriseLibrary.Data.Sql
#Enable Warning BC50001

Namespace sample
    Class MyFoo
        Public Shared Sub Run(sqlQuery As System.String, ParamArray parameters() As Object)
            {sink}
        End Sub
    End Class
End Namespace
";
            var expected = new DiagnosticResult
            {
                Id = "SCS0014",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

    }
}
