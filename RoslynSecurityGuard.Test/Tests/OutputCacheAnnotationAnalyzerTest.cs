using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Web.Mvc;
using TestHelper;

namespace RoslynSecurityGuard.Test.Tests
{
    [TestClass]
    public class OutputCacheAnnotationAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
        {
            return new[] { new OutputCacheAnnotationAnalyzer() };
        }

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[] { MetadataReference.CreateFromFile(typeof(OutputCacheAttribute).Assembly.Location) };
        }

        [TestMethod]
        public async Task DetectAnnotation1()
        {
            var test = @"
using System.Web.Mvc;

[Authorize]
public class HomeController : Controller
{
    [OutputCache]
    public ActionResult Index()
    {
        return View();
    }
}
";
            var expected = new DiagnosticResult
            {
                Id = OutputCacheAnnotationAnalyzer.DiagnosticId,
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(test, expected);
        }

        [TestMethod]
        public async Task DetectAnnotation2()
        {
            var test = @"
using System.Web.Mvc;

public class HomeController : Controller
{
    [Authorize]
    [OutputCache]
    public ActionResult Index()
    {
        return View();
    }
}
";
            var expected = new DiagnosticResult
            {
                Id = OutputCacheAnnotationAnalyzer.DiagnosticId,
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(test, expected);
        }

        [TestMethod]
        public async Task DetectAnnotation3()
        {
            var test = @"
using System.Web.Mvc;

[Authorize]
[OutputCache]
public class HomeController : Controller
{
    public ActionResult Index()
    {
        return View();
    }
}
";
            var expected = new DiagnosticResult
            {
                Id = OutputCacheAnnotationAnalyzer.DiagnosticId,
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(test, expected);
        }

        [TestMethod]
        public async Task DetectAnnotation4()
        {
            var test = @"
using System.Web.Mvc;

[Authorize]
public class MyController : Controller
{
}

[OutputCache]
public class HomeController : MyController
{
    public ActionResult Index()
    {
        return View();
    }
}
";
            var expected = new DiagnosticResult
            {
                Id = OutputCacheAnnotationAnalyzer.DiagnosticId,
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(test, expected);
        }

        [TestMethod]
        public async Task DetectAnnotation5()
        {
            var test = @"
using System.Web.Mvc;

public class MyController : Controller
{
    [Authorize]
    public virtual ActionResult Index()
    {
        return null;
    }
}

[OutputCache]
public class HomeController : MyController
{
    public override ActionResult Index()
    {
        return View();
    }
}
";
            var expected = new DiagnosticResult
            {
                Id = OutputCacheAnnotationAnalyzer.DiagnosticId,
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(test, expected);
        }

        [TestMethod]
        public async Task DetectAnnotation6()
        {
            var test = @"
using System.Web.Mvc;

public abstract class MyController : Controller
{
    [Authorize]
    public abstract ActionResult Index();
}

[OutputCache]
public class HomeController : MyController
{
    public override ActionResult Index()
    {
        return View();
    }
}
";
            var expected = new DiagnosticResult
            {
                Id = OutputCacheAnnotationAnalyzer.DiagnosticId,
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(test, expected);
        }

        [TestMethod]
        public async Task DetectAnnotation7()
        {
            var test = @"
using System.Web.Mvc;

public class MyController : Controller
{
    [Authorize]
    public virtual ActionResult Index()
    {
        return null;
    }
}

public class HomeController : MyController
{
    [OutputCache]
    public override ActionResult Index()
    {
        return View();
    }
}
";
            var expected = new DiagnosticResult
            {
                Id = OutputCacheAnnotationAnalyzer.DiagnosticId,
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(test, expected);
        }

        [TestMethod]
        public async Task DetectAnnotation8()
        {
            var test = @"
using System.Web.Mvc;

[OutputCache(NoStore = true, Duration = 0, VaryByParam = ""*"")]
public class MyController : Controller
{
}

[OutputCache(NoStore = true, Duration = int.MaxValue, VaryByParam = ""*"")]
public class HomeController : MyController
{
    [Authorize]
    public ActionResult Index()
    {
        return View();
    }
}
";
            var expected = new DiagnosticResult
            {
                Id = OutputCacheAnnotationAnalyzer.DiagnosticId,
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(test, expected);
        }

// The question is if we want to go so far and detect a derived attribute since the caching logic can be altered

//        [TestMethod]
//        public void DetectAnnotation9()
//        {
//            var test = @"
//using System;
//using System.Web.Mvc;

//class MyAuthorizeAttribute : AuthorizeAttribute
//{
//}

//[MyAuthorizeAttribute]
//[OutputCache]
//public class HomeController : Controller
//{
//    public ActionResult Index()
//    {
//        return View();
//    }
//}
//";
//            var expected = new DiagnosticResult
//            {
//                Id = OutputCacheAnnotationAnalyzer.DiagnosticId,
//                Severity = DiagnosticSeverity.Warning
//            };

//            VerifyCSharpDiagnostic(test, expected);
//        }
//
//        [TestMethod]
//        public void DetectAnnotation10()
//        {
//            var test = @"
//using System;
//using System.Web.Mvc;

//class MyOutputCacheAttribute : OutputCacheAttribute
//{
//}

//[AuthorizeAttribute]
//[MyOutputCache]
//public class HomeController : Controller
//{
//    public ActionResult Index()
//    {
//        return View();
//    }
//}
//";
//            var expected = new DiagnosticResult
//            {
//                Id = OutputCacheAnnotationAnalyzer.DiagnosticId,
//                Severity = DiagnosticSeverity.Warning
//            };

//            VerifyCSharpDiagnostic(test, expected);
//        }

        [TestMethod]
        public async Task FalsePositive1()
        {
            var test = @"
using System.Web.Mvc;

public class HomeController : Controller
{
    [OutputCache]
    public ActionResult Index()
    {
        return View();
    }
}
";

            await VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public async Task FalsePositive2()
        {
            var test = @"
using System.Web.Mvc;

[OutputCache(NoStore = true, Duration = 0, VaryByParam = ""*"")]
public class HomeController : Controller
{
    [Authorize]
    public ActionResult Index()
    {
        return View();
    }
}
";

            await VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public async Task FalsePositive3()
        {
            var test = @"
using System.Web.Mvc;

[OutputCache(NoStore = true, Duration = int.MaxValue, VaryByParam = ""*"")]
public class MyController : Controller
{
}

[OutputCache(NoStore = true, Duration = 0, VaryByParam = ""*"")]
public class HomeController : MyController
{
    [Authorize]
    public ActionResult Index()
    {
        return View();
    }
}
";

            await VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public async Task FalsePositive4()
        {
            var test = @"
using System.Web.Mvc;

[OutputCache(NoStore = true, Duration = 3600, VaryByParam = ""*"")]
public class MyController : Controller
{
}

public class HomeController : MyController
{
    [Authorize]
    [OutputCache(NoStore = true, Duration = 0, VaryByParam = ""*"")]
    public ActionResult Index()
    {
        return View();
    }
}
";

            await VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public async Task FalsePositive5()
        {
            var test = @"
using System.Web.Mvc;

[Authorize]
[OutputCache]
public class HomeController : Controller
{
    protected ActionResult Index()
    {
        return View();
    }
}
";

            await VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public async Task FalsePositive6()
        {
            var test = @"
using System;
using System.Web.Mvc;

class AuthorizeAttribute : Attribute
{
}

class OutputCacheAttribute : Attribute
{
}

[Authorize]
[OutputCache]
public class HomeController : Controller
{
    public ActionResult Index()
    {
        return View();
    }
}
";

            await VerifyCSharpDiagnostic(test);
        }
    }
}
