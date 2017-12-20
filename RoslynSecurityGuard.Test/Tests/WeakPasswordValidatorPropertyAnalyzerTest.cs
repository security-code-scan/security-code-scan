using Microsoft.AspNet.Identity;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers;
using RoslynSecurityGuard.Analyzers.Taint;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Mvc;
using TestHelper;

namespace RoslynSecurityGuard.Test.Tests
{
    [TestClass]
    public class WeakPasswordValidatorPropertyAnalyzerTest : DiagnosticVerifier
    {

        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new DiagnosticAnalyzer[] { new WeakPasswordValidatorPropertyAnalyzer(), new TaintAnalyzer() };
        }

        /// <summary>
        /// Indicates which references are needed for the code segments to compile
        /// </summary>
        /// <returns>An array containing the different references required for the code segments to compile</returns>
        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[] { MetadataReference.CreateFromFile(typeof(Controller).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Linq.Enumerable).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(PasswordValidator).Assembly.Location) };
        }

        /// <summary>
        /// Test case where the RequiredLength field has an accepted value.
        /// </summary>
        [TestMethod]
        public async Task PasswordValidatorDeclarationOK()
        {
            var cSharpTest = @"
using Microsoft.AspNet.Identity;
using System.Web.Mvc;

namespace WebApplicationSandbox.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            PasswordValidator pwdv = new PasswordValidator
            {
                RequiredLength = " + (Constants.PasswordValidatorRequiredLength + 1) + @",
                RequireNonLetterOrDigit = true,
                RequireDigit = true,
                RequireLowercase = true,
                RequireUppercase = true,
            };
            pwdv.RequireNonLetterOrDigit = true;
            pwdv.RequireDigit = true;

            return View();
        }
    }
}
";
            var visualBasicTest = @"
Imports Microsoft.AspNet.Identity
Imports System.Web.Mvc

Namespace WebApplicationSandbox.Controllers
    Public Class HomeController
        Inherits Controller
        Public Function Index() As ActionResult
            Dim pwdv As New PasswordValidator() With { _
                .RequiredLength = " + (Constants.PasswordValidatorRequiredLength + 1) + @", _
                .RequireNonLetterOrDigit = True, _
                .RequireDigit = True, _
                .RequireLowercase = True, _
                .RequireUppercase = True _
            }
            pwdv.RequireNonLetterOrDigit = True
            pwdv.RequireDigit = True

            Return View()
        End Function
    End Class
End Namespace
";
            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        /// <summary>
        /// Test case where the RequiredLength field is too small inside the declaration.
        /// </summary>
        [TestMethod]
        public async Task PasswordValidatorDeclarationTooSmall()
        {
            var cSharpTest = @"
using Microsoft.AspNet.Identity;
using System.Web.Mvc;

namespace WebApplicationSandbox.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            PasswordValidator pwdv = new PasswordValidator
            {
                RequiredLength = " + (Constants.PasswordValidatorRequiredLength - 1) + @",
                RequireNonLetterOrDigit = true,
                RequireDigit = true,
                RequireLowercase = true,
                RequireUppercase = true,
            };

            return View();
        }
    }
}
";
            var visualBasicTest = @"
Imports Microsoft.AspNet.Identity
Imports System.Web.Mvc

Namespace WebApplicationSandbox.Controllers
    Public Class HomeController
        Inherits Controller
        Public Function Index() As ActionResult
            Dim pwdv As New PasswordValidator() With { _
                .RequiredLength = " + (Constants.PasswordValidatorRequiredLength - 1) + @", _
                .RequireNonLetterOrDigit = True, _
                .RequireDigit = True, _
                .RequireLowercase = True, _
                .RequireUppercase = True _
            }

            Return View()
        End Function
    End Class
End Namespace
";
            var expected = new DiagnosticResult
            {
                Id = "SG0032",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        /// <summary>
        /// Test case where the RequiredLength field is too small but the value is affected outside of the declaration.
        /// </summary>
        [TestMethod]
        public async Task PasswordValidatorTooShort()
        {
            var cSharpTest = @"
using Microsoft.AspNet.Identity;
using System.Web.Mvc;

namespace WebApplicationSandbox.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            PasswordValidator pwdv = new PasswordValidator
            {
                RequireNonLetterOrDigit = true,
                RequireDigit = true,
            };

            pwdv.RequiredLength = " + (Constants.PasswordValidatorRequiredLength - 1) + @";

            return View();
        }
    }
}
";
            var visualBasicTest = @"
Imports Microsoft.AspNet.Identity
Imports System.Web.Mvc

Namespace WebApplicationSandbox.Controllers
    Public Class HomeController
        Inherits Controller
        Public Function Index() As ActionResult
            Dim pwdv As New PasswordValidator() With { _
                .RequireNonLetterOrDigit = True, _
                .RequireDigit = True _
            }

            pwdv.RequiredLength = " + (Constants.PasswordValidatorRequiredLength - 1) + @"

            Return View()
        End Function
    End Class
End Namespace
";
            var expected = new DiagnosticResult
            {
                Id = "SG0032",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        /// <summary>
        /// Test case where the RequiredLength field's value is set by a variable.
        /// However the value of the variable is not tested.
        /// </summary>
        [TestMethod]
        public async Task PasswordValidatorDeclarationWithVariable()
        {
            var cSharpTest = @"
using Microsoft.AspNet.Identity;
using System.Web.Mvc;

namespace WebApplicationSandbox.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            int reqLen = " + Constants.PasswordValidatorRequiredLength + @";

            PasswordValidator pwdv = new PasswordValidator
            {
                RequiredLength = reqLen,
                RequireNonLetterOrDigit = true,
                RequireDigit = true,
                RequireLowercase = true,
                RequireUppercase = true,
            };

            return View();
        }
    }
}
";
            var visualBasicTest = @"
Imports Microsoft.AspNet.Identity
Imports System.Web.Mvc

Namespace WebApplicationSandbox.Controllers
    Public Class HomeController
        Inherits Controller
        Public Function Index() As ActionResult
            Dim reqLen As Integer = " + Constants.PasswordValidatorRequiredLength + @"

            Dim pwdv As New PasswordValidator() With { _
                .RequiredLength = reqLen, _
                .RequireNonLetterOrDigit = True, _
                .RequireDigit = True, _
                .RequireLowercase = True, _
                .RequireUppercase = True _
            }

            Return View()
        End Function
    End Class
End Namespace
";
            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        /// <summary>
        /// Test case where some properties are set outside of the constructor
        /// </summary>
        [TestMethod]
        public async Task PasswordValidatorOutOfDeclarationOK()
        {
            var cSharpTest = @"
using Microsoft.AspNet.Identity;
using System.Web.Mvc;

namespace WebApplicationSandbox.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            PasswordValidator pwdv = new PasswordValidator
            {
                RequiredLength = " + (Constants.PasswordValidatorRequiredLength + 1) + @",
            };
            pwdv.RequireNonLetterOrDigit = true;
            pwdv.RequireDigit = true;

            return View();
        }
    }
}
";
            var visualBasicTest = @"
Imports Microsoft.AspNet.Identity
Imports System.Web.Mvc

Namespace WebApplicationSandbox.Controllers
    Public Class HomeController
        Inherits Controller
        Public Function Index() As ActionResult
            Dim pwdv As New PasswordValidator() With { _
                .RequiredLength = " + (Constants.PasswordValidatorRequiredLength + 1) + @" _
            }
            pwdv.RequireNonLetterOrDigit = True
            pwdv.RequireDigit = True

            Return View()
        End Function
    End Class
End Namespace
";
            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        /// <summary>
        /// Test case where the PasswordValidator doesn't have enough properties set
        /// </summary>
        [TestMethod]
        public async Task PasswordValidatorNotEnoughProperties()
        {
            var cSharpTest = @"
using Microsoft.AspNet.Identity;
using System.Web.Mvc;

namespace WebApplicationSandbox.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            PasswordValidator pwdv = new PasswordValidator
            {
                RequiredLength = " + (Constants.PasswordValidatorRequiredLength + 1) + @",
            };
            pwdv.RequireDigit = true;

            return View();
        }
    }
}
";
            var visualBasicTest = @"
Imports Microsoft.AspNet.Identity
Imports System.Web.Mvc

Namespace WebApplicationSandbox.Controllers
    Public Class HomeController
        Inherits Controller
        Public Function Index() As ActionResult
            Dim pwdv As New PasswordValidator() With { _
                .RequiredLength = " + (Constants.PasswordValidatorRequiredLength + 1) + @" _
            }
            pwdv.RequireDigit = True

            Return View()
        End Function
    End Class
End Namespace
";
            var expected = new DiagnosticResult
            {
                Id = WeakPasswordValidatorPropertyAnalyzer.RulePasswordDiagnosticId,
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        /// <summary>
        /// Test case where the RequiredLength isn't set
        /// </summary>
        [TestMethod]
        public async Task PasswordValidatorNoRequiredLengthProperty()
        {
            var cSharpTest = @"
using Microsoft.AspNet.Identity;
using System.Web.Mvc;

namespace WebApplicationSandbox.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            PasswordValidator pwdv = new PasswordValidator
        {
                RequireNonLetterOrDigit = true,
                RequireDigit = true,
                RequireLowercase = true,
                RequireUppercase = true,
            };
            return View();
        }
    }
}
";
            var visualBasicTest = @"
Imports Microsoft.AspNet.Identity
Imports System.Web.Mvc

Namespace WebApplicationSandbox.Controllers
    Public Class HomeController
        Inherits Controller
        Public Function Index() As ActionResult
            Dim pwdv As New PasswordValidator() With { _
                .RequireNonLetterOrDigit = True, _
                .RequireDigit = True, _
                .RequireLowercase = True, _
                .RequireUppercase = True _
            }
            Return View()
        End Function
    End Class
End Namespace
";
            var expected = new DiagnosticResult
            {
                Id = "SG0034",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }
    }
}
