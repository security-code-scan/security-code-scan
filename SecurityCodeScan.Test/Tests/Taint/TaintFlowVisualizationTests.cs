using System;
using System.Collections.Generic;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Config;
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test.Taint
{
    [TestClass]
    public class TaintFlowVisualizationTests : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string _)
        {
            return new[] { new SqlInjectionTaintAnalyzer() };
        }

        private static readonly PortableExecutableReference[] References =
        {            
            MetadataReference.CreateFromFile(typeof(System.Web.UI.WebControls.SqlDataSource).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Data.Entity.DbContext).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.Practices.EnterpriseLibrary.Data.Sql.SqlDatabase).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.EntityFrameworkCore.DbContext).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.EntityFrameworkCore.RelationalQueryableExtensions).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Data.SQLite.SQLiteCommand).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.Data.Sqlite.SqliteCommand).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Web.Mvc.Controller).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(NHibernate.ISession).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Cassandra.ISession).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Npgsql.NpgsqlCommand).Assembly.Location),
            MetadataReference.CreateFromFile(Assembly.Load("netstandard, Version=2.0.0.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51")
                                                     .Location),
            MetadataReference.CreateFromFile(Assembly.Load("Microsoft.Bcl.AsyncInterfaces, Version=1.0.0.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51")
                                                     .Location),
        };


        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestMethod]
        public async Task TaintedVizSimpleTest()
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
    using System.Data.SQLite;
    using System.Web.Mvc;
#pragma warning restore 8019

namespace sample
{{
    public class MyFooController : Controller
    {{
        public void Run(string input, params object[] parameters)
        {{
            DoStuff(input);
        }}

        private void DoStuff(string stuffInput)
        {{
            new SQLiteCommand(stuffInput);
        }}
    }}
}}
";
            var expected = new DiagnosticResult
            {
                Id = "SCS0002",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);

        }

        [TestMethod]
        public async Task TaintedVizOpsNotLeadingToSinkTest()
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
    using System.Data.SQLite;
    using System.Web.Mvc;
#pragma warning restore 8019

namespace sample
{{
    public class MyFooController : Controller
    {{
        public void Run(string input)
        {{
            var doNotStuff = input + ""tainted"";
            DoNotStuff(doNotStuff);
            DoStuff(input);
        }}

        private void DoStuff(string stuffInput)
        {{
            new SQLiteCommand(stuffInput);
        }}

        private void DoNotStuff(string stuffNotInput)
        {{
            return;
        }}


    }}
}}
";
            var expected = new DiagnosticResult
            {
                Id = "SCS0002",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);

        }


        [DataRow("var sql = new NpgsqlCommand(\"SELECT * FROM users WHERE username = '\" + username + \"';\");",                  true)]
        [DataTestMethod]
        public async Task NpgsqlInjection(string sink, bool warn)
        {
            var testConfig = @"
TaintEntryPoints:
  sample.MyFoo:
    Method:
      Name: Execute
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            var cSharpTest = $@"
using Npgsql;

namespace sample
{{
    public class MyFoo
    {{
        public void Execute(string username)
        {{
            {sink}
        }}
    }}
}}
";

            sink = sink.Replace("var ", "Dim ");
            sink = sink.Replace(";", "\r\n");
            sink = sink.Replace("null", "Nothing");

            var visualBasicTest = $@"
Imports Npgsql

Namespace sample
    Public Class MyFoo
        Public Sub Execute(ByVal username As String)
            {sink}
        End Sub
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
                await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest, options: optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, options: optionsWithProjectConfig).ConfigureAwait(false);
            }
        }
    }
}
