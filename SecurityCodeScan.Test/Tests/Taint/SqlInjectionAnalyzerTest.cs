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
    public class SqlInjectionAnalyzerTest : DiagnosticVerifier
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

        private DiagnosticResult CSharpDeprecated = new DiagnosticResult
        {
            Id = "CS0619",
            Severity = DiagnosticSeverity.Error,
        };

        private DiagnosticResult VBasicDeprecated = new DiagnosticResult
        {
            Id = "BC30668",
            Severity = DiagnosticSeverity.Error,
        };

    protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestMethod]
        public async Task SqlInjectionEnterpriseLibraryDataParametrized()
        {
            var cSharpTest = @"
using System.Data;
using System.Data.Common;
using Microsoft.Practices.EnterpriseLibrary.Data.Sql;
using System.Web.Mvc;

namespace sample
{
    public class MyFooController : Controller
    {
        public MyFooController()
        {
            m_db = new SqlDatabase("""");
        }

        private SqlDatabase m_db;

        private SqlDatabase GetDataBase() { return m_db; }

        public void Run(string input)
        {
            var db = GetDataBase();
            DbCommand cmd = db.GetSqlStringCommand(""SELECT * FROM Users WHERE username = @username and role='user'"");
            db.AddInParameter(cmd, ""@username"", DbType.String, input);
            db.ExecuteDataSet(cmd);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Data
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
            Dim db = GetDataBase()
            Dim cmd As DbCommand = db.GetSqlStringCommand(""SELECT * FROM Users WHERE username = @username and role='user'"")
            db.AddInParameter(cmd, ""@username"", DbType.String, input)
            db.ExecuteDataSet(cmd)
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task SqlInjectionEnterpriseLibraryDataGetSqlStringCommandUnsafe()
        {
            var cSharpTest = @"
using System.Data.Common;
using Microsoft.Practices.EnterpriseLibrary.Data.Sql;
using System.Web.Mvc;

namespace sample
{
    public class MyFooController : Controller
    {
        public MyFooController()
        {
            m_db = new SqlDatabase("""");
        }

        private SqlDatabase m_db;

        private SqlDatabase GetDataBase() { return m_db; }

        public void Run(string input)
        {
            var db = GetDataBase();
            DbCommand cmd = db.GetSqlStringCommand(""SELECT * FROM Users WHERE username = '"" + input + ""' and role='user'"");
            db.ExecuteDataSet(cmd);
        }
    }
}
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
            Dim db = GetDataBase()
            Dim cmd As DbCommand = db.GetSqlStringCommand(""SELECT * FROM Users WHERE username = '"" + input + ""' and role='user'"")
            db.ExecuteDataSet(cmd)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0002",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [DataRow("new SqlDataSource()", false, null)]
        [DataRow("new SqlDataSource(\"connectionString\", input)", true, "SCS0002")]
        [DataRow("new SqlDataSource(\"connectionString\", \"select\")", false, null)]
        [DataRow("new SqlDataSource(input, input)", true, "SCS0002")]
        [DataRow("new SqlDataSource(input, \"select\")", false, null)]
        [DataRow("new SqlDataSource(\"providerName\",\"connectionString\", input)", true, "SCS0002")]
        [DataRow("new SqlDataSource(input, \"connectionString\", \"select\")", false, null)]
        [DataRow("new SqlDataSource(input, input, \"select\")", false, null)]
        [DataRow("new SqlDataSource(\"providerName\", input, \"select\")", false, null)]
        [DataRow("new SqlDataAdapter()", false, null)]
        [DataRow("new SqlDataAdapter(input, new SqlConnection())", true, "SCS0002")]
        [DataRow("new SqlDataAdapter(\"select\", new SqlConnection())", false, null)]
        [DataRow("new SqlDataAdapter(input, \"connectionString\")", true, "SCS0002")]
        //[DataRow("new SqlDataAdapter(\"select\", input)", false, null)] //todo - isAnyStringParameterInConstructorASink

        [DataRow("new DbContext(\"connectionString\").Set(null).SqlQuery(input, null)",          true,  "SCS0002")]
        [DataRow("new DbContext(\"connectionString\").Set(null).SqlQuery(\"select\", null)",     false, null)]
        [DataRow("new DbContext(\"connectionString\").Set<Object>().SqlQuery(input, null)",      true,  "SCS0002")]
        [DataRow("new DbContext(\"connectionString\").Set<Object>().SqlQuery(\"select\", null)", false, null)]

        [DataRow("new DbContext(\"connectionString\").Database.SqlQuery(null, input, null)",         true,  "SCS0002")]
        [DataRow("new DbContext(\"connectionString\").Database.SqlQuery(null, \"select\", null)",    false, null)]
        [DataRow("new DbContext(\"connectionString\").Database.SqlQuery<Object>(input)",             true,  "SCS0002")]
        [DataRow("new DbContext(\"connectionString\").Database.SqlQuery<Object>(\"select\", input)", false, null)]

        [DataRow("new DbContext(\"connectionString\").Database.ExecuteSqlCommand(input, parameters)", true, "SCS0002")]
        [DataRow("new DbContext(\"connectionString\").Database.ExecuteSqlCommand(\"select\", parameters)", false, null)]
        [DataRow("new DbContext(\"connectionString\").Database.ExecuteSqlCommand(TransactionalBehavior.DoNotEnsureTransaction, input, parameters)", true, "SCS0002")]
        [DataRow("new DbContext(\"connectionString\").Database.ExecuteSqlCommand(TransactionalBehavior.DoNotEnsureTransaction, \"select\", parameters)", false, null)]

        [DataRow("new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(input, parameters)", true, "SCS0002")]
        [DataRow("new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(\"select\", parameters)", false, null)]
        [DataRow("new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(TransactionalBehavior.DoNotEnsureTransaction, input, parameters)", true, "SCS0002")]
        [DataRow("new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(TransactionalBehavior.DoNotEnsureTransaction, \"select\", parameters)", false, null)]
        [DataRow("new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(input, new CancellationToken(), parameters)", true, "SCS0002")]
        [DataRow("new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(\"select\", new CancellationToken(), parameters)", false, null)]
        [DataRow("new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(TransactionalBehavior.DoNotEnsureTransaction, input, new CancellationToken(), parameters)", true, "SCS0002")]
        [DataRow("new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(TransactionalBehavior.DoNotEnsureTransaction, \"select\", new CancellationToken(), parameters)", false, null)]

        [DataRow("new SqlDatabase(\"connectionString\").ExecuteDataSet(CommandType.Text, input)", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteDataSet(CommandType.Text, \"select\")", false, null)]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteDataSet(input)", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteDataSet(\"select\")", false, null)]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteDataSet(input, parameters)", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteDataSet(\"select\", parameters)", false, null)]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteDataSet(new SqlConnection(\"\").BeginTransaction(), CommandType.Text, input)", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteDataSet(new SqlConnection(\"\").BeginTransaction(), CommandType.Text, \"select\")", false, null)]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteDataSet(new SqlConnection(\"\").BeginTransaction(), input, parameters)", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteDataSet(new SqlConnection(\"\").BeginTransaction(), \"select\", parameters)", false, null)]

        [DataRow("new SqlDatabase(\"connectionString\").ExecuteReader(CommandType.Text, input)", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteReader(CommandType.Text, \"select\")", false, null)]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteReader(input)", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteReader(\"select\")", false, null)]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteReader(input, parameters)", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteReader(\"select\", parameters)", false, null)]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteReader(new SqlConnection(\"\").BeginTransaction(), CommandType.Text, input)", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteReader(new SqlConnection(\"\").BeginTransaction(), CommandType.Text, \"select\")", false, null)]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteReader(new SqlConnection(\"\").BeginTransaction(), input, parameters)", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteReader(new SqlConnection(\"\").BeginTransaction(), \"select\", parameters)", false, null)]

        [DataRow("new SqlDatabase(\"connectionString\").ExecuteNonQuery(CommandType.Text, input)", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteNonQuery(CommandType.Text, \"select\")", false, null)]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteNonQuery(input)", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteNonQuery(\"select\")", false, null)]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteNonQuery(input, parameters)", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteNonQuery(\"select\", parameters)", false, null)]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteNonQuery(new SqlConnection(\"\").BeginTransaction(), CommandType.Text, input)", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteNonQuery(new SqlConnection(\"\").BeginTransaction(), CommandType.Text, \"select\")", false, null)]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteNonQuery(new SqlConnection(\"\").BeginTransaction(), input, parameters)", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteNonQuery(new SqlConnection(\"\").BeginTransaction(), \"select\", parameters)", false, null)]

        [DataRow("new SqlDatabase(\"connectionString\").ExecuteScalar(CommandType.Text, input)", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteScalar(CommandType.Text, \"select\")", false, null)]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteScalar(input)", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteScalar(\"select\")", false, null)]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteScalar(input, parameters)", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteScalar(\"select\", parameters)", false, null)]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteScalar(new SqlConnection(\"\").BeginTransaction(), CommandType.Text, input)", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteScalar(new SqlConnection(\"\").BeginTransaction(), CommandType.Text, \"select\")", false, null)]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteScalar(new SqlConnection(\"\").BeginTransaction(), input, parameters)", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteScalar(new SqlConnection(\"\").BeginTransaction(), \"select\", parameters)", false, null)]

        [DataRow("new SQLiteCommand()",                                                                              false, null)]
        [DataRow("new SQLiteCommand(new SQLiteConnection())",                                                        false, null)]
        [DataRow("new SQLiteCommand(input)",                                                                         true,  "SCS0002")]
        [DataRow("new SQLiteCommand(\"select\")",                                                                    false, null)]
        [DataRow("new SQLiteCommand(input, new SQLiteConnection())",                                                 true,  "SCS0002")]
        [DataRow("new SQLiteCommand(\"select\", new SQLiteConnection())",                                            false, null)]
        [DataRow("new SQLiteCommand(input, new SQLiteConnection(), new SQLiteConnection().BeginTransaction())",      true,  "SCS0002")]
        [DataRow("new SQLiteCommand(\"select\", new SQLiteConnection(), new SQLiteConnection().BeginTransaction())", false, null)]
        [DataRow("SQLiteCommand.Execute(input, SQLiteExecuteType.Reader, CommandBehavior.Default, null)",            true,  "SCS0002")]
        [DataRow("SQLiteCommand.Execute(\"select\", SQLiteExecuteType.Reader, CommandBehavior.Default, null)",       false, null)]
        [DataRow("SQLiteCommand.Execute(input, SQLiteExecuteType.Reader, null)",                                     true,  "SCS0002")]
        [DataRow("SQLiteCommand.Execute(\"select\", SQLiteExecuteType.Reader, null)",                                false, null)]
        [DataRow("new SQLiteDataAdapter(\"\", \"\")",                                                                false, null)]
        [DataRow("new SQLiteDataAdapter(input, \"\")",                                                               true,  "SCS0002")]

        // Tests below are covered by SCS0002
        [DataRow("new SqlDataAdapter(new SqlCommand(input))", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteDataSet(new SqlCommand(input))", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteDataSet(new SqlCommand(input), new SqlConnection(\"\").BeginTransaction())", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteReader(new SqlCommand(input))", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteReader(new SqlCommand(input), new SqlConnection(\"\").BeginTransaction())", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteNonQuery(new SqlCommand(input))", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteNonQuery(new SqlCommand(input), new SqlConnection(\"\").BeginTransaction())", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteScalar(new SqlCommand(input))", true, "SCS0002")]
        [DataRow("new SqlDatabase(\"connectionString\").ExecuteScalar(new SqlCommand(input), new SqlConnection(\"\").BeginTransaction())", true, "SCS0002")]

        [DataTestMethod]
        public async Task SqlInjection(string sink, bool warn, string warningId)
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
            {sink};
        }}
    }}
}}
";

            sink = sink.CSharpReplaceToVBasic();

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
    Imports System.Data.SQLite
    Imports System.Web.Mvc
#Enable Warning BC50001

Namespace sample
    Public Class MyFooController
        Inherits Controller

        Public Sub Run(input As System.String, ParamArray parameters() As Object)
            Dim temp = {sink}
        End Sub
    End Class
End Namespace
";
            var expected = new DiagnosticResult
            {
                Id = warningId,
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

        [DataRow("new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(input, parameters)", true, "SCS0002")]
        [DataRow("new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(\"select\", parameters)", false, null)]
        [DataRow("new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(TransactionalBehavior.DoNotEnsureTransaction, input, parameters)", true, "SCS0002")]
        [DataRow("new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(TransactionalBehavior.DoNotEnsureTransaction, \"select\", parameters)", false, null)]
        [DataRow("new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(input, new CancellationToken(), parameters)", true, "SCS0002")]
        [DataRow("new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(\"select\", new CancellationToken(), parameters)", false, null)]
        [DataRow("new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(TransactionalBehavior.DoNotEnsureTransaction, input, new CancellationToken(), parameters)", true, "SCS0002")]
        [DataRow("new DbContext(\"connectionString\").Database.ExecuteSqlCommandAsync(TransactionalBehavior.DoNotEnsureTransaction, \"select\", new CancellationToken(), parameters)", false, null)]
        [DataTestMethod]
        public async Task AwaitedSqlInjection(string sink, bool warn, string warningId)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System;
    using System.Threading.Tasks;
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
        public async Task Run(string input, params object[] parameters)
        {{
            await {sink};
        }}
    }}
}}
";

            sink = sink.CSharpReplaceToVBasic();

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
    Imports System.Data.SQLite
    Imports System.Web.Mvc
#Enable Warning BC50001

Namespace sample
    Public Class MyFooController
        Inherits Controller

        Public Async Sub Run(input As System.String, ParamArray parameters() As Object)
            Dim temp = Await {sink}
        End Sub
    End Class
End Namespace
";
            var expected = new DiagnosticResult
            {
                Id = warningId,
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

        [DataRow("new SampleContext().Test.FromSqlInterpolated($\"select {input}\")", false)]
        [DataRow("new SampleContext().Database.ExecuteSqlInterpolated($\"select {input}\")", false)]
        [DataRow("new SampleContext().Database.ExecuteSqlInterpolatedAsync($\"select {input}\")", false)]
        [DataRow("new SampleContext().Test.FromSql(input)", true, true)]
        [DataRow("new SampleContext().Test.FromSql(input, null)", true, true)]
        [DataRow("new SampleContext().Test.FromSql(\"select\")", false, true)]
        [DataRow("new SampleContext().Test.FromSql(\"select\", null)", false, true)]
        [DataRow("new SampleContext().Test.FromSql(\"select {0}\", input)", false, true)]
        [DataRow("new SampleContext().Database.ExecuteSqlCommand(input)", true)]
        [DataRow("new SampleContext().Database.ExecuteSqlCommand(input, null)", true)]
        [DataRow("new SampleContext().Database.ExecuteSqlCommand(\"select\")", false)]
        [DataRow("new SampleContext().Database.ExecuteSqlCommand(\"select\", null)", false)]
        [DataRow("new SampleContext().Database.ExecuteSqlCommand(\"select {0}\", input)", false)]
        [DataTestMethod]
        public async Task SqlInjectionEntityFrameworkCore(string sink, bool warn, bool obsolete = false)
        {
            var cSharpTest = $@"
using Microsoft.EntityFrameworkCore;
using System.Web.Mvc;

namespace sample
{{
    public class SampleContext : DbContext
    {{
        public DbSet<string> Test {{ get; set; }}
    }}

    public class MyFooController : Controller
    {{
        public void Run(string input, params object[] parameters)
        {{
#pragma warning disable CS0618
            {sink};
#pragma warning restore CS0618
        }}
    }}
}}
";

            sink = sink.CSharpReplaceToVBasic();

            var visualBasicTest = $@"
Imports Microsoft.EntityFrameworkCore
Imports System.Web.Mvc

Namespace sample
    Public Class SampleContext
        Inherits DbContext

        Public Property Test As DbSet(Of String)
    End Class

    Public Class MyFooController
        Inherits Controller

        Public Sub Run(input As System.String, ParamArray parameters() As Object)
#Disable Warning BC40000
            Dim temp = {sink}
#Enable Warning BC40000
        End Sub
    End Class
End Namespace
";
            var csDeprecated = CSharpDeprecated.WithLocation(17, 13);
            var vbDeprecated = VBasicDeprecated.WithLocation(17, 24);

            var expected = new DiagnosticResult
            {
                Id = "SCS0002",
                Severity = DiagnosticSeverity.Warning,
            };

            if (warn)
            {
                await VerifyCSharpDiagnostic(cSharpTest, obsolete ? new [] { csDeprecated, expected } : new[] { expected }, dotNetVersion: new Version(4, 6, 1)).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, obsolete ? new[] { vbDeprecated, expected } : new[] { expected }, dotNetVersion: new Version(4, 6, 1)).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest, obsolete ? new[] { csDeprecated } : null,  dotNetVersion: new Version(4, 6, 1)).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, obsolete ? new[] { vbDeprecated } : null, dotNetVersion: new Version(4, 6, 1)).ConfigureAwait(false);
            }
        }

        // todo: 2.0
        [DataRow("new SqliteCommand()",                                                                              false)]
        [DataRow("new SqliteCommand(input)",                                                                         true)]
        [DataRow("new SqliteCommand(\"select\")",                                                                    false)]
        [DataRow("new SqliteCommand(input, null)",                                                                   true)]
        [DataRow("new SqliteCommand(\"select\", new SqliteConnection())",                                            false)]
        [DataRow("new SqliteCommand(input, null, null)",                                                             true)]
        [DataRow("new SqliteCommand(\"select\", new SqliteConnection(), new SqliteConnection().BeginTransaction())", false)]
        [DataTestMethod]
        public async Task MicrosoftSqlite(string sink, bool warn)
        {
            var cSharpTest = $@"
using Microsoft.Data.Sqlite;
using System.Web.Mvc;

namespace sample
{{
    public class MyFooController : Controller
    {{
        public void Run(string input, params object[] parameters)
        {{
            {sink};
        }}
    }}
}}
";

            sink = sink.CSharpReplaceToVBasic();

            var visualBasicTest = $@"
Imports Microsoft.Data.Sqlite
Imports System.Web.Mvc

Namespace sample
    Public Class MyFooController
        Inherits Controller

        Public Sub Run(input As System.String, ParamArray parameters() As Object)
            Dim temp = {sink}
        End Sub
    End Class
End Namespace
";
            var expected = new DiagnosticResult
            {
                Id = "SCS0002",
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

        [DataRow("\"SELECT * FROM Users WHERE username = '\" + username + \"';\"", true)]
        [DataRow("\"SELECT * FROM Users WHERE username = 'indy@email.com';\"", false)]
        [DataTestMethod]
        public async Task NHibernateSqlInjection(string sink, bool warn)
        {
            var testConfig = @"
TaintEntryPoints:
  sample.MyFoo:
    Method:
      Name: Execute
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            var cSharpTest = $@"
using NHibernate;

namespace sample
{{
    public class MyFoo
    {{
        private ISession session = null;

        public void Execute(string username)
        {{
            session.CreateSQLQuery({sink});
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports NHibernate

Namespace sample
    Public Class MyFoo
        Private session As ISession = Nothing

        Public Sub Execute(ByVal username As String)
            session.CreateSQLQuery({sink})
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

        [DataRow("\"SELECT * FROM Users WHERE username = '\" + username + \"';\"",                           true)]
        [DataRow("\"SELECT * FROM Users WHERE username = '\" + username + \"';\", 1",                        true)]
        [DataRow("\"SELECT * FROM Users WHERE username = '\" + username + \"';\", ConsistencyLevel.All",     true)]

        [DataRow("\"SELECT * FROM Users WHERE username = 'indy@email.com';\"",                           false)]
        [DataRow("\"SELECT * FROM Users WHERE username = 'indy@email.com';\", 1",                        false)]
        [DataRow("\"SELECT * FROM Users WHERE username = 'indy@email.com';\", ConsistencyLevel.All",     false)]
        [DataTestMethod]
        public async Task CassandraCqlInjection(string sink, bool warn)
        {
            var testConfig = @"
TaintEntryPoints:
  sample.MyFoo:
    Method:
      Name: Execute
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            var cSharpTest = $@"
using Cassandra;

namespace sample
{{
    public class MyFoo
    {{
        private ISession session = null;

        public void Execute(string username)
        {{
            session.Execute({sink});
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports Cassandra

Namespace sample
    Public Class MyFoo
        Private session As ISession = Nothing

        Public Sub Execute(ByVal username As String)
            session.Execute({sink})
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

        [DataRow("var sql = new NpgsqlCommand(\"SELECT * FROM users WHERE username = '\" + username + \"';\");",                  true)]
        [DataRow("var sql = new NpgsqlCommand(\"SELECT * FROM users WHERE username = '\" + username + \"';\", null);",            true)]
        [DataRow("var sql = new NpgsqlCommand(\"SELECT * FROM users WHERE username = '\" + username + \"';\", null, null);",      true)]
        [DataRow("var sql = new NpgsqlCommand(); sql.CommandText = \"SELECT * FROM users WHERE username = '\" + username + \"';\";", true)]

        [DataRow("var sql = new NpgsqlCommand(\"SELECT * FROM users WHERE username = 'indy@email.com';\");",                  false)]
        [DataRow("var sql = new NpgsqlCommand(\"SELECT * FROM users WHERE username = 'indy@email.com';\", null);",            false)]
        [DataRow("var sql = new NpgsqlCommand(\"SELECT * FROM users WHERE username = 'indy@email.com';\", null, null);",      false)]
        [DataRow("var sql = new NpgsqlCommand(); sql.CommandText = \"SELECT * FROM users WHERE username = 'indy@email.com';\";", false)]
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
