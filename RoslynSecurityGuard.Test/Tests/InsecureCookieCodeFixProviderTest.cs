using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis.Diagnostics;
using TestHelper;
using Microsoft.CodeAnalysis.CodeFixes;
using RoslynSecurityGuard.Analyzers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.CodeAnalysis;
using System.Web;
using RoslynSecurityGuard.Analyzers.Taint;

namespace RoslynSecurityGuard.Test.Tests
{
    [TestClass]
    public class InsecureCookieCodeFixProviderTest : CodeFixVerifier
    {

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[] { MetadataReference.CreateFromFile(typeof(HttpCookie).Assembly.Location) };
        }

        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
        {
            return new DiagnosticAnalyzer[] { new TaintAnalyzer(), new InsecureCookieAnalyzer() };
        }

        protected override CodeFixProvider GetCSharpCodeFixProvider()
        {
            return new InsecureCookieCodeFixProvider();
        }

        [TestMethod]
        public async Task VerifyBothFlagAdded()
        {
            var before = @"
using System;
using System.Web;

namespace VulnerableApp
{
    class CookieCreation
    {
        static void TestCookie()
        {
            var cookie = new HttpCookie(""test"");
        }
    }
}
";
            var after = @"
using System;
using System.Web;

namespace VulnerableApp
{
    class CookieCreation
    {
        static void TestCookie()
        {
            var cookie = new HttpCookie(""test"");
            cookie.HttpOnly = true;
            cookie.Secure = true;
        }
    }
}
";
            await VerifyCSharpFix(before, after);
        }

        [TestMethod]
        public async Task VerifySecureFlagAdded()
        {
            var before = @"
using System;
using System.Web;

namespace VulnerableApp
{
    class CookieCreation
    {
        static void TestCookie()
        {
            var cookie = new HttpCookie(""test"");
            cookie.HttpOnly = true;
        }
    }
}
";
            var after = @"
using System;
using System.Web;

namespace VulnerableApp
{
    class CookieCreation
    {
        static void TestCookie()
        {
            var cookie = new HttpCookie(""test"");
            cookie.Secure = true;
            cookie.HttpOnly = true;
        }
    }
}
";
            await VerifyCSharpFix(before, after);
        }

        [TestMethod]
        public async Task VerifyHttpOnlyFlagAdded()
        {
            var before = @"
using System;
using System.Web;

namespace VulnerableApp
{
    class CookieCreation
    {
        static void TestCookie()
        {
            var cookie = new HttpCookie(""test"");
            cookie.Secure = true;
        }
    }
}
";
            var after = @"
using System;
using System.Web;

namespace VulnerableApp
{
    class CookieCreation
    {
        static void TestCookie()
        {
            var cookie = new HttpCookie(""test"");
            cookie.HttpOnly = true;
            cookie.Secure = true;
        }
    }
}
";
            await VerifyCSharpFix(before, after);
        }
    }
}
