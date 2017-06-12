using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers;
using RoslynSecurityGuard.Analyzers.Taint;
using System.Collections.Generic;
using System.Data.Linq;
using System.Threading.Tasks;
using TestHelper;

namespace RoslynSecurityGuard.Tests
{
    [TestClass]
    public class LinqSqlInjectionAnalyzerTest : DiagnosticVerifier
    {

        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new[] { new TaintAnalyzer() };
        }

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[] { MetadataReference.CreateFromFile(typeof(DataContext).Assembly.Location), //Main assembly for Linq
                MetadataReference.CreateFromFile(typeof(System.Linq.Enumerable).Assembly.Location) }; //Seems to be needed so that invoke symbol gets build
        }

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
			Dim users = ctx.ExecuteQuery(Of UserEntity)(""SELECT CustomerID, CompanyName, ContactName, ContactTitle, Address, City, Region, PostalCode, Country, Phone, Fax
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
			Dim users = ctx.ExecuteQuery(Of UserEntity)(""SELECT CustomerID, CompanyName, ContactName, ContactTitle, Address, City, Region, PostalCode, Country, Phone, Fax
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
                Id = "SG0002",
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
			Dim users = ctx.ExecuteQuery(GetType(String), ""SELECT CustomerID, CompanyName, ContactName, ContactTitle, Address, City, Region, PostalCode, Country, Phone, Fax
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
			Dim users = ctx.ExecuteQuery(GetType(String), ""SELECT CustomerID, CompanyName, ContactName, ContactTitle, Address, City, Region, PostalCode, Country, Phone, Fax
                                                            FROM dbo.Users
                                                            WHERE City = '"" & city & ""'"")
            Return 0
        End Function
    End Class
End Namespace
        ";
            var expected = new DiagnosticResult
            {
                Id = "SG0002",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }
    }
}
