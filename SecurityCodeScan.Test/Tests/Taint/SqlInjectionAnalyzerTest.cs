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
            MetadataReference.CreateFromFile(typeof(System.Web.UI.WebControls.SqlDataSource).Assembly.Location)
        };

        //private static readonly PortableExecutableReference[] References =
        //{
        //    MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.ValidateAntiForgeryTokenAttribute).Assembly.Location),
        //    MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.HttpPostAttribute).Assembly.Location),
        //    MetadataReference.CreateFromFile(typeof(System.Web.Mvc.ValidateAntiForgeryTokenAttribute).Assembly.Location)
        //};

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;


        [DataRow("var sda = new SqlDataAdapter(sqlQuery, new SqlConnection());")]
        [DataRow("var sds = new SqlDataSource(\"connectionString\", sqlQuery);")]
        [DataRow("var sds = new SqlDataSource(\"providerName\",\"connectionString\", sqlQuery);")]
        [DataTestMethod]
        public async Task SqlInjectionVulnerableCSharp(string sink)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System.Data.SqlClient;
    using System.Data.Common;
    using System.Data;
    using System.Web.UI.WebControls;
#pragma warning restore 8019

namespace sample
{{
    class MyFoo
    {{
        public static void Run(string sqlQuery)
        {{
            {sink}
        }}       
    }}
}}
";
            var expected = new DiagnosticResult
            {
                Id = "SCS0014",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);            
        }



        [DataRow("Dim sda = New SqlDataAdapter(sqlQuery, New SqlConnection())")]
        [DataRow("Dim sds = New SqlDataSource(\"connectionString\", sqlQuery)")]
        [DataRow("Dim sds = New SqlDataSource(\"providerName\",\"connectionString\", sqlQuery)")]
        [DataTestMethod]
        public async Task SqlInjectionVulnerableVBasic(string sink)
        {
            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System.Data.SqlClient
    Imports System.Data.Common
    Imports System.Data
    Imports System.Web.UI.WebControls
#Enable Warning BC50001

Namespace sample
    Class MyFoo
        Public Shared Sub Run(sqlQuery As System.String)
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

            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);           
        }
    }
}
