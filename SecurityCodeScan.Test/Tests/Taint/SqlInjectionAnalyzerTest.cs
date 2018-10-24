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


        [DataRow("var temp = new SqlDataSource()", false)]
        [DataRow("var temp = new SqlDataSource(\"connectionString\", input)", true)]
        [DataRow("var temp = new SqlDataSource(\"connectionString\", \"select\")", false)]
        [DataRow("var temp = new SqlDataSource(input, input)", true)]
        [DataRow("var temp = new SqlDataSource(input, \"select\")", false)]        
        [DataRow("var temp = new SqlDataSource(\"providerName\",\"connectionString\", input)", true)]
        [DataRow("var temp = new SqlDataSource(input, \"connectionString\", \"select\")", false)]
        [DataRow("var temp = new SqlDataSource(input, input, \"select\")", false)]
        [DataRow("var temp = new SqlDataSource(\"providerName\", input, \"select\")", false)]
        [DataRow("var temp = new SqlDataAdapter()", false)]
        [DataRow("var temp = new SqlDataAdapter(input, new SqlConnection())", true)]
        [DataRow("var temp = new SqlDataAdapter(\"select\", new SqlConnection())", false)]
        [DataRow("var temp = new SqlDataAdapter(input, \"connectionString\")", true)]
        [DataRow("var temp = new SqlDataAdapter(\"select\", input)", false)]
        [DataRow("var temp = new DbContext(\"connectionString\").Database.SqlQuery(null, input, null)", true)]
        [DataRow("var temp = new DbContext(\"connectionString\").Database.SqlQuery(null, \"select\", null)", false)]
        //[DataRow("var temp = new DbContext(\"connectionString\").Database.SqlQuery<Object>(input)", true)]
        //[DataRow("var temp = new DbContext(\"connectionString\").Database.SqlQuery<Object>(\"select\", input)", false)]
        [DataRow("var temp = new DbContext(\"connectionString\").Database.ExecuteSqlCommand(input, parameters)", true)]
        [DataRow("var temp = new DbContext(\"connectionString\").Database.ExecuteSqlCommand(\"select\", parameters)", false)]
        [DataRow("var temp = new DbContext(\"connectionString\").Database.ExecuteSqlCommand(TransactionalBehavior.DoNotEnsureTransaction, input, parameters)", true)]
        [DataRow("var temp = new DbContext(\"connectionString\").Database.ExecuteSqlCommand(TransactionalBehavior.DoNotEnsureTransaction, \"select\", parameters)", false)]
        [DataRow("var temp = new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(input, parameters)", true)]
        [DataRow("var temp = new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(\"select\", parameters)", false)]
        [DataRow("var temp = new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(TransactionalBehavior.DoNotEnsureTransaction, input, parameters)", true)]
        [DataRow("var temp = new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(TransactionalBehavior.DoNotEnsureTransaction, \"select\", parameters)", false)]
        [DataRow("var temp = new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(input, new CancellationToken(), parameters)", true)]
        [DataRow("var temp = new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(\"select\", new CancellationToken(), parameters)", false)]
        [DataRow("var temp = new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(TransactionalBehavior.DoNotEnsureTransaction, input, new CancellationToken(), parameters)", true)]
        [DataRow("var temp = new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(TransactionalBehavior.DoNotEnsureTransaction, \"select\", new CancellationToken(), parameters)", false)]       

        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteDataSet(CommandType.Text, input)", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteDataSet(CommandType.Text, \"select\")", false)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteDataSet(input)", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteDataSet(\"select\")", false)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteDataSet(input, parameters)", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteDataSet(\"select\", parameters)", false)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteDataSet(new SqlConnection(\"\").BeginTransaction(), CommandType.Text, input)", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteDataSet(new SqlConnection(\"\").BeginTransaction(), CommandType.Text, \"select\")", false)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteDataSet(new SqlConnection(\"\").BeginTransaction(),  input, parameters)", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteDataSet(new SqlConnection(\"\").BeginTransaction(),  \"select\", parameters)", false)]

        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteReader(CommandType.Text, input)", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteReader(CommandType.Text, \"select\")", false)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteReader(input)", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteReader(\"select\")", false)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteReader(input, parameters)", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteReader(\"select\", parameters)", false)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteReader(new SqlConnection(\"\").BeginTransaction(), CommandType.Text, input)", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteReader(new SqlConnection(\"\").BeginTransaction(), CommandType.Text, \"select\")", false)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteReader(new SqlConnection(\"\").BeginTransaction(),  input, parameters)", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteReader(new SqlConnection(\"\").BeginTransaction(),  \"select\", parameters)", false)]

        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteNonQuery(CommandType.Text, input)", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteNonQuery(CommandType.Text, \"select\")", false)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteNonQuery(input)", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteNonQuery(\"select\")", false)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteNonQuery(input, parameters)", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteNonQuery(\"select\", parameters)", false)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteNonQuery(new SqlConnection(\"\").BeginTransaction(), CommandType.Text, input)", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteNonQuery(new SqlConnection(\"\").BeginTransaction(), CommandType.Text, \"select\")", false)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteNonQuery(new SqlConnection(\"\").BeginTransaction(),  input, parameters)", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteNonQuery(new SqlConnection(\"\").BeginTransaction(),  \"select\", parameters)", false)]

        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteScalar(CommandType.Text, input)", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteScalar(CommandType.Text, \"select\")", false)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteScalar(input)", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteScalar(\"select\")", false)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteScalar(input, parameters)", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteScalar(\"select\", parameters)", false)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteScalar(new SqlConnection(\"\").BeginTransaction(), CommandType.Text, input)", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteScalar(new SqlConnection(\"\").BeginTransaction(), CommandType.Text, \"select\")", false)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteScalar(new SqlConnection(\"\").BeginTransaction(),  input, parameters)", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteScalar(new SqlConnection(\"\").BeginTransaction(),  \"select\", parameters)", false)]

        /* Tests is conflicted with rule SCS0026
         * 
        [DataRow("var temp = new SqlDataAdapter(new SqlCommand(input))", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteDataSet(new SqlCommand(input))", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteDataSet(new SqlCommand(input), new SqlConnection(\"\").BeginTransaction())", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteReader(new SqlCommand(input))", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteReader(new SqlCommand(input), new SqlConnection(\"\").BeginTransaction())", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteNonQuery(new SqlCommand(input))", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteNonQuery(new SqlCommand(input), new SqlConnection(\"\").BeginTransaction())", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteScalar(new SqlCommand(input))", true)]
        [DataRow("var temp = new SqlDatabase(\"connectionString\").ExecuteScalar(new SqlCommand(input), new SqlConnection(\"\").BeginTransaction())", true)]
        */
        [DataTestMethod]
        public async Task SqlInjectionVulnerable(string sink, bool warn)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System;
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
        public static void Run(string input, params object[] parameters)
        {{
            {sink};
        }}       
    }}
}}
";

            sink = sink.Replace("null", "Nothing")
                .Replace("var ", "Dim ")
                .Replace("new ", "New ")
                .Replace("<Object>", "(Of Object)");

            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System
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
        Public Shared Sub Run(input As System.String, ParamArray parameters() As Object)
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
