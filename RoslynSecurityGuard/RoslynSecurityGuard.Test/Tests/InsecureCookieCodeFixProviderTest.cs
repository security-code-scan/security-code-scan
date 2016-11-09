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

namespace RoslynSecurityGuard.Test.Tests
{
    //FIXME: The test is working locally but not on AppVeyor..
    //[TestClass]
    public class InsecureCookieCodeFixProviderTest : CodeFixVerifier
    {

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[] { MetadataReference.CreateFromFile(typeof(HttpCookie).Assembly.Location) };
        }

        protected override DiagnosticAnalyzer GetCSharpDiagnosticAnalyzers()
        {
            return new InsecureCookieAnalyzer();
        }

        protected override CodeFixProvider GetCSharpCodeFixProvider()
        {
            return new InsecureCookieCodeFixProvider();
        }

        [TestMethod]
        public void VerifyBothFlagAdded()
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
            VerifyCSharpFix(before, after);
        }

        [TestMethod]
        public void VerifySecureFlagAdded()
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
            VerifyCSharpFix(before, after);
        }

        [TestMethod]
        public void VerifyHttpOnlyFlagAdded()
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
            VerifyCSharpFix(before, after);
        }
    }
}
