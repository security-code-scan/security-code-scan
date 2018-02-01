using System.Collections.Generic;
using System.Data.Linq;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Helpers;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test.Taint
{
    [TestClass]
    public class LinqSqlInjectionAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new[] { new TaintAnalyzer() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(DataContext).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Linq.Enumerable).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestMethod]
        public async Task LinqInjectionFalsePositiveWithGeneric()
        {
            var cSharpTest = @"
using System.Data.Linq;

namespace VulnerableApp
{

    public class LyncInjectionFP
    {
        public static int Run(DataContext ctx,string city) {
            var users = ctx.ExecuteQuery<UserEntity>(@""SELECT CustomerID, CompanyName, ContactName, ContactTitle,
                Address, City, Region, PostalCode, Country, Phone, Fax
                FROM dbo.Users"");

            return 0;
        }
    }

    class UserEntity
    {
    }
}
";

            var visualBasicTest = @"
Imports System.Data.Linq

Namespace VulnerableApp
	Public Class LyncInjectionFP
		Public Shared Function Run(ctx As DataContext, city As String) As Integer
			Dim users = ctx.ExecuteQuery(Of UserEntity)(""SELECT CustomerID, CompanyName, ContactName, ContactTitle,
                                                          Address, City, Region, PostalCode, Country, Phone, Fax
                                                          FROM dbo.Users"")
            Return 0
        End Function
    End Class

    Class UserEntity
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [TestMethod]
        public async Task LinqInjectionVulnerableWithGeneric()
        {
            var cSharpTest = @"
using System.Data.Linq;

namespace VulnerableApp
{

    public class LyncInjectionTP
    {
        public static int Run(DataContext ctx,string city) {
            var users = ctx.ExecuteQuery<UserEntity>(@""SELECT CustomerID, CompanyName, ContactName, ContactTitle,
                Address, City, Region, PostalCode, Country, Phone, Fax
                FROM dbo.Users
                WHERE  City = '"" + city+ ""'"");

            return 0;
        }
    }

    class UserEntity
    {
    }
}
        ";

            var visualBasicTest = @"
Imports System.Data.Linq

Namespace VulnerableApp
	Public Class LyncInjectionTP
		Public Shared Function Run(ctx As DataContext, city As String) As Integer
			Dim users = ctx.ExecuteQuery(Of UserEntity)(""SELECT CustomerID, CompanyName, ContactName, ContactTitle,
                                                          Address, City, Region, PostalCode, Country, Phone, Fax
                                                          FROM dbo.Users
                                                          WHERE City = '"" & city & ""'"")
            Return 0
        End Function
    End Class

    Class UserEntity
    End Class
End Namespace
        ";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0002",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        [TestMethod]
        public async Task LinqInjectionFalsePositiveWithoutGeneric()
        {
            var cSharpTest = @"
using System;
using System.Data.Linq;

namespace VulnerableApp
{
    public class LyncInjectionTP
    {
        public static int Run(DataContext ctx,string city) {
            var users = ctx.ExecuteQuery(typeof(String),@""SELECT CustomerID, CompanyName, ContactName, ContactTitle,
                Address, City, Region, PostalCode, Country, Phone, Fax
                FROM dbo.Users
                WHERE  City = 'Montreal'"");

            return 0;
        }
    }
}
        ";

            var visualBasicTest = @"
Imports System.Data.Linq

Namespace VulnerableApp
	Public Class LyncInjectionTP
		Public Shared Function Run(ctx As DataContext, city As String) As Integer
			Dim users = ctx.ExecuteQuery(GetType(String), ""SELECT CustomerID, CompanyName, ContactName, ContactTitle,
                                                            Address, City, Region, PostalCode, Country, Phone, Fax
                                                            FROM dbo.Users
                                                            WHERE City = 'Montreal'"")
            Return 0
        End Function
    End Class
End Namespace
        ";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [TestMethod]
        public async Task LinqInjectionVulnerableWithoutGeneric()
        {
            var cSharpTest = @"
using System;
using System.Data.Linq;

namespace VulnerableApp
{
    public class LyncInjectionTP
    {
        public static int Run(DataContext ctx,string city) {
            var users = ctx.ExecuteQuery(typeof(String),@""SELECT CustomerID, CompanyName, ContactName, ContactTitle,
                Address, City, Region, PostalCode, Country, Phone, Fax
                FROM dbo.Users
                WHERE  City = '"" + city+ ""'"");

            return 0;
        }
    }
}
        ";

            var visualBasicTest = @"
Imports System.Data.Linq

Namespace VulnerableApp
	Public Class LyncInjectionTP
		Public Shared Function Run(ctx As DataContext, city As String) As Integer
			Dim users = ctx.ExecuteQuery(GetType(String), ""SELECT CustomerID, CompanyName, ContactName, ContactTitle,
                                                            Address, City, Region, PostalCode, Country, Phone, Fax
                                                            FROM dbo.Users
                                                            WHERE City = '"" & city & ""'"")
            Return 0
        End Function
    End Class
End Namespace
        ";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0002",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }
    }
}
