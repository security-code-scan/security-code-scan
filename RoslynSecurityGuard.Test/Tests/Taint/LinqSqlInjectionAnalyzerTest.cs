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

        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
        {
            return new[] { new TaintAnalyzer() };
        }

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new [] { MetadataReference.CreateFromFile(typeof(DataContext).Assembly.Location), //Main assembly for Linq
                MetadataReference.CreateFromFile(typeof(System.Linq.Enumerable).Assembly.Location) }; //Seems to be needed so that invoke symbol gets build
        }

        [TestMethod]
        public async Task LinqInjectionFalsePositiveWithGeneric()
        {
            var test = @"
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
            await VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public async Task LinqInjectionVulnerableWithGeneric()
        {
            var test = @"
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

            var expected = new DiagnosticResult
            {
                Id = "SG0002",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(test, expected);
        }

        [TestMethod]
        public async Task LinqInjectionFalsePositiveWithoutGeneric()
        {
            var test = @"
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

            var expected = new DiagnosticResult
            {
                Id = "SG0002",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(test);
        }


        [TestMethod]
        public async Task LinqInjectionVulnerableWithoutGeneric()
        {
            var test = @"
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

            var expected = new DiagnosticResult
            {
                Id = "SG0002",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(test, expected);
        }
    }
}
