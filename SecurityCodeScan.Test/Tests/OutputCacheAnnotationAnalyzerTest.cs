using System.Collections.Generic;
using System.Threading.Tasks;
using System.Web.Mvc;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Test.Helpers;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test
{
    [TestClass]
    public class OutputCacheAnnotationAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string _)
        {
            return new[]{ new OutputCacheAnnotationAnalyzer() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(OutputCacheAttribute).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        private DiagnosticResult Expected = new DiagnosticResult
        {
            Id       = OutputCacheAnnotationAnalyzer.DiagnosticId,
            Severity = DiagnosticSeverity.Warning
        };

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectAnnotation1()
        {
            var cSharpTest = @"
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

            var visualBasicTest = @"
Imports System.Web.Mvc

<Authorize> _
Public Class HomeController
    Inherits Controller
    <OutputCache> _
    Public Function Index() As ActionResult
        Return View()
    End Function
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("System.Web.Mvc",                           "Nope = System.Web.Mvc.AuthorizeAttribute", "Authorize", "OutputCache")]
        [DataRow("OC = System.Web.Mvc.OutputCacheAttribute", "Auth = System.Web.Mvc.AuthorizeAttribute", "Auth",      "OC")]
        public async Task DetectAnnotation2(string alias1, string alias2, string authorizeAttribute, string outputCacheAttribute)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using {alias1};
    using {alias2};
#pragma warning restore 8019

public class HomeController : System.Web.Mvc.Controller
{{
    [{authorizeAttribute}]
    [{outputCacheAttribute}]
    public System.Web.Mvc.ActionResult Index()
    {{
        return View();
    }}
}}
";

            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports {alias1}
    Imports {alias2}
#Enable Warning BC50001

Public Class HomeController
    Inherits System.Web.Mvc.Controller
    <{authorizeAttribute}> _
    <{outputCacheAttribute}> _
    Public Function Index() As System.Web.Mvc.ActionResult
        Return View()
    End Function
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectAnnotation3()
        {
            var cSharpTest = @"
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

            var visualBasicTest = @"
Imports System.Web.Mvc

<Authorize> _
<OutputCache> _
Public Class HomeController
    Inherits Controller
    Public Function Index() As ActionResult
        Return View()
    End Function
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectAnnotation4()
        {
            var cSharpTest = @"
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

            var visualBasicTest = @"
Imports System.Web.Mvc

<Authorize> _
Public Class MyController
    Inherits Controller
End Class

<OutputCache> _
Public Class HomeController
    Inherits MyController
    Public Function Index() As ActionResult
        Return View()
    End Function
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectAnnotation5()
        {
            var cSharpTest = @"
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

            var visualBasicTest = @"
Imports System.Web.Mvc

Public Class MyController
    Inherits Controller
    <Authorize> _
    Public Overridable Function Index() As ActionResult
        Return Nothing
    End Function
End Class

<OutputCache> _
Public Class HomeController
    Inherits MyController
    Public Overrides Function Index() As ActionResult
        Return View()
    End Function
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectAnnotation6()
        {
            var cSharpTest = @"
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

            var visualBasicTest = @"
Imports System.Web.Mvc

Public MustInherit Class MyController
    Inherits Controller
    <Authorize> _
    Public MustOverride Function Index() As ActionResult
End Class

<OutputCache> _
Public Class HomeController
    Inherits MyController
    Public Overrides Function Index() As ActionResult
        Return View()
    End Function
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectAnnotation7()
        {
            var cSharpTest = @"
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

            var visualBasicTest = @"
Imports System.Web.Mvc

Public Class MyController
    Inherits Controller
    <Authorize> _
    Public Overridable Function Index() As ActionResult
        Return Nothing
    End Function
End Class

Public Class HomeController
    Inherits MyController
    <OutputCache> _
    Public Overrides Function Index() As ActionResult
        Return View()
    End Function
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectAnnotation8()
        {
            var cSharpTest = @"
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

            var visualBasicTest = @"
Imports System.Web.Mvc

<OutputCache(NoStore := True, Duration := 0, VaryByParam := "" * "")> _
Public Class MyController
    Inherits Controller
End Class

<OutputCache(NoStore := True, Duration := Integer.MaxValue, VaryByParam := "" * "")> _
Public Class HomeController
    Inherits MyController
    <Authorize> _
    Public Function Index() As ActionResult
        Return View()
    End Function
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        // The question is if we want to go so far and detect a derived attribute since the caching logic can be altered

        //        [TestMethod]
        //        public void DetectAnnotation9()
        //        {
        //            var cSharpTest = @"
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
        //            var cSharpTest = @"
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

        [TestCategory("Detect")]
        [TestMethod]
        public async Task FalsePositiveInvalidDuration()
        {
            var cSharpTest = @"
using System.Web.Mvc;

[OutputCache(Duration = hmm)]
public class HomeController : Controller
{
    [Authorize]
    public ActionResult Index()
    {
        return View();
    }
}
";

            var vbTest = @"
Imports System.Web.Mvc

<OutputCache(Duration := hmm)> _
Public Class HomeController
    Inherits Controller
    <Authorize> _
    Public Function Index() As ActionResult
        Return View()
    End Function
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest, new DiagnosticResult { Id = "CS0103" }.WithLocation(4, 25)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(vbTest, new DiagnosticResult { Id = "BC30451" }.WithLocation(4, 26)).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task FalsePositive1()
        {
            var cSharpTest = @"
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

            var visualBasicTest = @"
Imports System.Web.Mvc

Public Class HomeController
    Inherits Controller
    <OutputCache> _
    Public Function Index() As ActionResult
        Return View()
    End Function
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task FalsePositive2()
        {
            var cSharpTest = @"
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

            var visualBasicTest = @"
Imports System.Web.Mvc

<OutputCache(NoStore := True, Duration := 0, VaryByParam := "" * "")> _
Public Class HomeController
    Inherits Controller
    <Authorize> _
    Public Function Index() As ActionResult
        Return View()
    End Function
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task FalsePositive3()
        {
            var cSharpTest = @"
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

            var visualBasicTest = @"
Imports System.Web.Mvc

<OutputCache(NoStore := True, Duration := Integer.MaxValue, VaryByParam := "" * "")> _
Public Class MyController
    Inherits Controller
End Class

<OutputCache(NoStore := True, Duration := 0, VaryByParam := "" * "")> _
Public Class HomeController
    Inherits MyController
    <Authorize> _
    Public Function Index() As ActionResult
        Return View()
    End Function
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task FalsePositive4()
        {
            var cSharpTest = @"
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

            var visualBasicTest = @"
Imports System.Web.Mvc

<OutputCache(NoStore := True, Duration := 3600, VaryByParam := "" * "")> _
Public Class MyController
    Inherits Controller
End Class

Public Class HomeController
    Inherits MyController
    <Authorize> _
    <OutputCache(NoStore := True, Duration := 0, VaryByParam := "" * "")> _
    Public Function Index() As ActionResult
        Return View()
    End Function
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task FalsePositive5()
        {
            var cSharpTest = @"
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

            var visualBasicTest = @"
Imports System.Web.Mvc

<Authorize> _
<OutputCache> _
Public Class HomeController
    Inherits Controller
    Protected Function Index() As ActionResult
        Return View()
    End Function
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task FalsePositive6()
        {
            var cSharpTest = @"
using System;
using System.Web.Mvc;

public class AuthorizeAttribute : Attribute
{
}

public class OutputCacheAttribute : Attribute
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

            var visualBasicTest = @"
Imports System
Imports System.Web.Mvc

Public Class AuthorizeAttribute
    Inherits Attribute
End Class

Public Class OutputCacheAttribute
    Inherits Attribute
End Class

<Authorize> _
<OutputCache> _
Public Class HomeController
    Inherits Controller
    Public Function Index() As ActionResult
        Return View()
    End Function
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }
    }
}
