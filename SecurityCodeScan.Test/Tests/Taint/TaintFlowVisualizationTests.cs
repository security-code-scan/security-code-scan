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

        private DiagnosticResult Expected = new DiagnosticResult
        {
            Id       = "SCS0002",
            Severity = DiagnosticSeverity.Warning,
        };

        [TestMethod]
        public async Task TaintedVizSimpleTest()
        {
            var testConfig = @"
TaintFlowVisualizationEnabled: true";

            var cSharpTest = $@"
using System.Data.Common;
using Microsoft.Practices.EnterpriseLibrary.Data.Sql;
using System.Web.Mvc;

namespace sample
{{
    public class MyFooController : Controller
    {{
        public MyFooController()
        {{
            m_db = new SqlDatabase("""");
        }}

        private SqlDatabase m_db;

        private SqlDatabase GetDataBase() {{ return m_db; }}

        public void Run(string input)
        {{
            DoStuff(input);
        }}

        private void DoStuff(string stuffInput)
        {{
            var db = GetDataBase();
            DbCommand cmd = db.GetSqlStringCommand(""SELECT * FROM Users WHERE username = '"" + stuffInput + ""' and role='user'"");
            db.ExecuteDataSet(cmd);
        }}
    }}
}}
";

            var visualBasicTest = @"
Imports System.Data.Common
Imports Microsoft.Practices.EnterpriseLibrary.Data.Sql
Imports System.Web.Mvc

Namespace sample
    Public Class MyFooController
        Inherits Controller

        Public Sub New()
            m_db = New SqlDatabase("""")
        End Sub

        Private m_db As SqlDatabase

        Private Function GetDataBase() As SqlDatabase
            Return m_db
        End Function

        Public Sub Run(input As System.String)
            DoStuff(input)
        End Sub

         Private Sub DoStuff(stuffInput As System.String)
            Dim db = GetDataBase()
            Dim cmd As DbCommand = db.GetSqlStringCommand(""SELECT * FROM Users WHERE username = '"" + stuffInput + ""' and role='user'"")
            db.ExecuteDataSet(cmd)
         End Sub
    End Class
End Namespace
";
            var expectedCSharp =
                new[]
                {
                    Expected.WithLocation(27,52)
                        .WithAdditionalLocations(new List<ResultAdditionalLocation>()
                        {
                            new ResultAdditionalLocation(19, 25),
                            new ResultAdditionalLocation(21, 13),
                            new ResultAdditionalLocation(27, 23),
                            new ResultAdditionalLocation(28, 13),
                        })
                };

            var expectedVB =
                new[]
                {
                    Expected.WithLocation(26, 59)
                        .WithAdditionalLocations(new List<ResultAdditionalLocation>()
                        {
                            new ResultAdditionalLocation(20, 24),
                            new ResultAdditionalLocation(21, 13),
                            new ResultAdditionalLocation(26, 17),
                            new ResultAdditionalLocation(27, 13),
                        })
                };

            var config = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, expectedCSharp, options: config).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expectedVB, options: config).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task TaintedVizOpsNotLeadingToSinkTest()
        {
            var testConfig = @"
TaintFlowVisualizationEnabled: true";

            var cSharpTest = $@"
using System.Data.Common;
using Microsoft.Practices.EnterpriseLibrary.Data.Sql;
using System.Web.Mvc;

namespace sample
{{
    public class MyFooController : Controller
    {{
        public MyFooController()
        {{
            m_db = new SqlDatabase("""");
        }}

        private SqlDatabase m_db;

        private SqlDatabase GetDataBase() {{ return m_db; }}

        public void Run(string input)
        {{
            var doNotStuff = input + ""tainted"";
            DoNotStuff(doNotStuff);
            DoStuff(input);
        }}

        private void DoStuff(string stuffInput)
        {{
            var db = GetDataBase();
            DbCommand cmd = db.GetSqlStringCommand(""SELECT * FROM Users WHERE username = '"" + stuffInput + ""' and role='user'"");
            db.ExecuteDataSet(cmd);
        }}

        private void DoNotStuff(string stuffNotInput)
        {{
            return;
        }}
    }}
}}
";

            var visualBasicTest = @"
Imports System.Data.Common
Imports Microsoft.Practices.EnterpriseLibrary.Data.Sql
Imports System.Web.Mvc

Namespace sample
    Public Class MyFooController
        Inherits Controller

        Public Sub New()
            m_db = New SqlDatabase("""")
        End Sub

        Private m_db As SqlDatabase

        Private Function GetDataBase() As SqlDatabase
            Return m_db
        End Function

        Public Sub Run(input As System.String)
            Dim doNotStuff = input & ""tainted""
            DontStuff(doNotStuff)
            DoStuff(input)
        End Sub

         Private Sub DoStuff(stuffInput As System.String)
            Dim db = GetDataBase()
            Dim cmd As DbCommand = db.GetSqlStringCommand(""SELECT * FROM Users WHERE username = '"" + stuffInput + ""' and role='user'"")
            db.ExecuteDataSet(cmd)
         End Sub
 
         Private Sub DontStuff(stuffNotInput As System.String)
         End Sub

    End Class
End Namespace
";
            var expectedCSharp =
                new[]
                {
                    Expected.WithLocation(29,52)
                        .WithAdditionalLocations(new List<ResultAdditionalLocation>()
                        {
                            new ResultAdditionalLocation(19, 25),
                            new ResultAdditionalLocation(23, 13),
                            new ResultAdditionalLocation(29, 23),
                            new ResultAdditionalLocation(30, 13),
                        })
                };

            var expectedVB =
                new[]
                {
                    Expected.WithLocation(28, 59)
                        .WithAdditionalLocations(new List<ResultAdditionalLocation>()
                        {
                            new ResultAdditionalLocation(20, 24),
                            new ResultAdditionalLocation(23, 13),
                            new ResultAdditionalLocation(28, 17),
                            new ResultAdditionalLocation(29, 13),
                        })
                };

            var config = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, expectedCSharp, options: config).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expectedVB, options: config).ConfigureAwait(false);

        }        
    }
}
