using System.Collections.Generic;
using System.Threading.Tasks;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Helpers;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test
{
    [TestClass]
    public class WeakPasswordValidatorPropertyAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            if (language == LanguageNames.CSharp)
                return new DiagnosticAnalyzer[] { new WeakPasswordValidatorPropertyAnalyzerCSharp(), new TaintAnalyzerCSharp() };

            return new DiagnosticAnalyzer[] { new WeakPasswordValidatorPropertyAnalyzerVisualBasic(), new TaintAnalyzerVisualBasic(), };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(Controller).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(PasswordValidator).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        private const int DefaultPasswordValidatorRequiredLenght = 8;


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
                RequiredLength = " + (DefaultPasswordValidatorRequiredLenght + 1) + @",
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
                .RequiredLength = " + (DefaultPasswordValidatorRequiredLenght + 1) + @", _
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

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
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
                RequiredLength = " + (DefaultPasswordValidatorRequiredLenght - 1) + @",
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
                .RequiredLength = " + (DefaultPasswordValidatorRequiredLenght - 1) + @", _
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
                Id       = "SCS0032",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
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

            pwdv.RequiredLength = " + (DefaultPasswordValidatorRequiredLenght - 1) + @";

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

            pwdv.RequiredLength = " + (DefaultPasswordValidatorRequiredLenght - 1) + @"

            Return View()
        End Function
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0032",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
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
            int reqLen = " + DefaultPasswordValidatorRequiredLenght + @";

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
            Dim reqLen As Integer = " + DefaultPasswordValidatorRequiredLenght + @"

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

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
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
                RequiredLength = " + (DefaultPasswordValidatorRequiredLenght + 1) + @",
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
                .RequiredLength = " + (DefaultPasswordValidatorRequiredLenght + 1) + @" _
            }
            pwdv.RequireNonLetterOrDigit = True
            pwdv.RequireDigit = True

            Return View()
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
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
                RequiredLength = " + (DefaultPasswordValidatorRequiredLenght + 1) + @",
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
                .RequiredLength = " + (DefaultPasswordValidatorRequiredLenght + 1) + @" _
            }
            pwdv.RequireDigit = True

            Return View()
        End Function
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0033",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
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
                Id       = "SCS0034",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task PasswordValidatorDeclarationAssignFalse()
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
                RequiredLength = " + (DefaultPasswordValidatorRequiredLenght + 1) + @",
                RequireNonLetterOrDigit = false,
                RequireDigit = false,
                RequireLowercase = false,
                RequireUppercase = false,
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
                .RequiredLength = " + (DefaultPasswordValidatorRequiredLenght + 1) + @", _
                .RequireNonLetterOrDigit = False, _
                .RequireDigit = False, _
                .RequireLowercase = False, _
                .RequireUppercase = False _
            }

            Return View()
        End Function
    End Class
End Namespace
";
            var expected = new DiagnosticResult
            {
                Id       = "SCS0033",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task PasswordValidatorDeclarationReAssignOK()
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
                RequiredLength = " + (DefaultPasswordValidatorRequiredLenght + 1) + @",
                RequireNonLetterOrDigit = false,
                RequireDigit = false,
                RequireLowercase = false,
                RequireUppercase = false,
            };

            pwdv.RequireNonLetterOrDigit = true;
            pwdv.RequireDigit = true;
            pwdv.RequireLowercase = true;
            pwdv.RequireUppercase = true;

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
                .RequiredLength = " + (DefaultPasswordValidatorRequiredLenght + 1) + @", _
                .RequireNonLetterOrDigit = False, _
                .RequireDigit = False, _
                .RequireLowercase = False, _
                .RequireUppercase = False _
            }

            pwdv.RequireNonLetterOrDigit = True
            pwdv.RequireDigit = True
            pwdv.RequireLowercase = True
            pwdv.RequireUppercase = True

            Return View()
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task PasswordValidatorDeclarationReAssignFalse()
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
                RequiredLength = " + (DefaultPasswordValidatorRequiredLenght + 1) + @",
                RequireNonLetterOrDigit = true,
                RequireDigit = true,
                RequireLowercase = true,
                RequireUppercase = true,
            };

            pwdv.RequireNonLetterOrDigit = false;
            pwdv.RequireDigit = false;
            pwdv.RequireLowercase = false;
            pwdv.RequireUppercase = false;

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
                .RequiredLength = " + (DefaultPasswordValidatorRequiredLenght + 1) + @", _
                .RequireNonLetterOrDigit = True, _
                .RequireDigit = True, _
                .RequireLowercase = True, _
                .RequireUppercase = True _
            }

            pwdv.RequireNonLetterOrDigit = False
            pwdv.RequireDigit = False
            pwdv.RequireLowercase = False
            pwdv.RequireUppercase = False

            Return View()
        End Function
    End Class
End Namespace
";
            var expected = new DiagnosticResult
            {
                Id       = "SCS0033",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task PasswordValidatorDeclarationReAssignRequiredLenght()
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
                RequiredLength = " + (DefaultPasswordValidatorRequiredLenght - 1) + @",
                RequireNonLetterOrDigit = true,
                RequireDigit = true,
                RequireLowercase = true,
                RequireUppercase = true,
            };

            pwdv.RequiredLength = " + (DefaultPasswordValidatorRequiredLenght + 1) + @";

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
                .RequiredLength = " + (DefaultPasswordValidatorRequiredLenght - 1) + @", _
                .RequireNonLetterOrDigit = True, _
                .RequireDigit = True, _
                .RequireLowercase = True, _
                .RequireUppercase = True _
            }

            pwdv.RequiredLength = " + (DefaultPasswordValidatorRequiredLenght + 1) + @"

            Return View()
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }
    }
}
