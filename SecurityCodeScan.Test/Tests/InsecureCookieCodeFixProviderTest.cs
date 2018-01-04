using System.Collections.Generic;
using System.Threading.Tasks;
using System.Web;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Analyzers.Taint;
using TestHelper;

namespace SecurityCodeScan.Test.Tests
{
    [TestClass]
    public class InsecureCookieCodeFixProviderTest : CodeFixVerifier
    {
        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[] { MetadataReference.CreateFromFile(typeof(HttpCookie).Assembly.Location) };
        }

        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
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
