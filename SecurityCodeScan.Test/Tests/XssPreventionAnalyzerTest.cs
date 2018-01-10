using System.Collections.Generic;
using System.Reflection;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Test.Helpers;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test
{
    [TestClass]
    public class XssPreventionAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new[] { new XssPreventionAnalyzer() };
        }

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[]
            {
                MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.HttpGetAttribute).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Web.Mvc.HttpGetAttribute).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(HtmlEncoder).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.Controller).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Web.Mvc.Controller).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(AllowAnonymousAttribute).Assembly.Location),
                MetadataReference.CreateFromFile(Assembly.Load("System.Runtime, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")
                                                         .Location),
            };
        }

        #region Tests that are producing diagnostics

        [TestMethod]
        public async Task UnencodedInputDataSystemWebMvc()
        {
            var cSharpTest = @"
using System.Web.Mvc;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [HttpGet]
        public string Get(int sensibleData)
        {
            return ""value "" + sensibleData;
        }
    }
}
            ";

            var visualBasicTest = @"
Imports System.Web.Mvc

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller
        <HttpGet> _
        Public Function [Get](sensibleData As Integer) As String
            Return ""value "" & sensibleData.ToString()
        End Function
    End Class
End Namespace
            ";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0029",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        [TestMethod]
        public async Task UnencodedInputData()
        {
            var cSharpTest = @"
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [HttpGet(""{sensibleData}"")]
        public string Get(int sensibleData)
        {
            return ""value "" + sensibleData;
        }
    }
}
            ";

            var visualBasicTest = @"
Imports Microsoft.AspNetCore.Mvc

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller
        <HttpGet(""{sensibleData}"")> _
        Public Function [Get](sensibleData As Integer) As String
            Return ""value "" & sensibleData.ToString()
        End Function
    End Class
End Namespace
            ";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0029",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        [TestMethod]
        public async Task UnencodedInputData2()
        {
            var cSharpTest = @"
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [HttpGet(""{sensibleData}"")]
        // using 'virtual' to make 'public' not the only modifier
        // using 'System.String' instead of 'string' to see if it is handled
        public virtual System.String Get(int sensibleData)
        {
            return ""value "" + sensibleData;
        }
    }
}
            ";

            var visualBasicTest = @"
Imports Microsoft.AspNetCore.Mvc

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller
        ' using Overridable to make Public not the only modifier
        ' using System.String instead of String to see if it is handled
        <HttpGet(""{sensibleData}"")> _
        Public Overridable Function [Get](sensibleData As Integer) As System.String
            Return ""value "" & sensibleData.ToString()
        End Function
    End Class
End Namespace
            ";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0029",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        #endregion

        #region Tests that are not producing diagnostics

        [TestMethod]
        public async Task BaseNotController()
        {
            var cSharpTest = @"
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp
{
    public class Controller
    {
    }

    public class TestController : Controller
    {
        [HttpGet(""{sensibleData}"")]
        public string Get(int sensibleData)
        {
            return ""value "" + sensibleData;
        }
    }
}
            ";

            var visualBasicTest = @"
Imports Microsoft.AspNetCore.Mvc

Namespace VulnerableApp
    Public Class Controller
    End Class

    Public Class TestController
        Inherits Controller
        <HttpGet(""{sensibleData}"")> _
        Public Function [Get](sensibleData As Integer) As String
            Return ""value "" & sensibleData.ToString()
        End Function
    End Class
End Namespace
            ";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [TestMethod]
        public async Task NoSymbolReturnType()
        {
            var cSharpTest = @"
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [HttpGet(""{sensibleData}"")]
        public xxx Get(int sensibleData)
        {
        }
    }
}
            ";

            var visualBasicTest = @"
Imports Microsoft.AspNetCore.Mvc

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller
        <HttpGet(""{sensibleData}"")> _
        Public Function [Get](sensibleData As Integer) As XXX
        End Function
    End Class
End Namespace
            ";

            await VerifyCSharpDiagnostic(cSharpTest, new[]
                                                        {
                                                            new DiagnosticResult { Id = "CS0246" },
                                                            new DiagnosticResult { Id = "CS0161" }
                                                        });
            await VerifyVisualBasicDiagnostic(visualBasicTest, new[]
                                                        {
                                                            new DiagnosticResult { Id = "BC30002" },
                                                            new DiagnosticResult { Id = "BC42105" }
                                                        });
        }

        [TestMethod]
        public async Task Void()
        {
            var cSharpTest = @"
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        // see if 'void' is handled
        [HttpGet(""{sensibleData}"")]
        public void Get(int sensibleData)
        {
        }
    }
}
            ";

            var visualBasicTest = @"
Imports Microsoft.AspNetCore.Mvc

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller
        ' see if Void is handled
        <HttpGet(""{sensibleData}"")> _
        Public Function [Get](sensibleData As Integer)
        End Function
    End Class
End Namespace
            ";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new DiagnosticResult { Id = "BC42105" });
        }

        [TestMethod]
        public async Task EncodedSensibleDataWithTemporaryVariable()
        {
            var cSharpTest = @"
using Microsoft.AspNetCore.Mvc;
using System.Text.Encodings.Web;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [HttpGet(""{sensibleData}"")]
        public string Get(string sensibleData)
        {
            string temporary_variable = HtmlEncoder.Default.Encode(sensibleData);
            return ""value "" + temporary_variable;
        }
    }
}
            ";

            var visualBasicTest = @"
Imports Microsoft.AspNetCore.Mvc
Imports System.Text.Encodings.Web

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller
        <HttpGet(""{ sensibleData}"")> _
        Public Function [Get](sensibleData As String) As String
            Dim temporary_variable As String = HtmlEncoder.[Default].Encode(sensibleData)
            Return ""value "" & temporary_variable
        End Function
    End Class
End Namespace
            ";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [TestMethod]
        public async Task EncodedSensibleDataOnReturn()
        {
            var cSharpTest = @"
using Microsoft.AspNetCore.Mvc;
using System.Text.Encodings.Web;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [HttpGet(""{sensibleData}"")]
        public string Get(string sensibleData)
        {
            return ""value "" + HtmlEncoder.Default.Encode(sensibleData);
        }
    }
}
            ";

            var visualBasicTest = @"
Imports System.Text.Encodings.Web
Imports Microsoft.AspNetCore.Mvc

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller
        <HttpGet(""{ sensibleData}"")> _
        Public Function [Get](sensibleData As String) As String
            Return ""value "" & HtmlEncoder.[Default].Encode(sensibleData)
        End Function
    End Class
End Namespace
            ";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [TestMethod]
        public async Task ReturnEncodedData()
        {
            var cSharpTest = @"
using Microsoft.AspNetCore.Mvc;
using System.Text.Encodings.Web;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [HttpGet(""{sensibleData}"")]
        public string Get(string sensibleData)
        {
            return HtmlEncoder.Default.Encode(""value "" + sensibleData);
        }
    }
}
            ";

            var visualBasicTest = @"
Imports System.Text.Encodings.Web
Imports Microsoft.AspNetCore.Mvc

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller
        <HttpGet(""{ sensibleData}"")> _
        Public Function [Get](sensibleData As String) As String
            Return HtmlEncoder.[Default].Encode(""value "" & sensibleData)
        End Function
    End Class
End Namespace
            ";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [TestMethod]
        public async Task EncodedDataWithSameVariableUsage()
        {
            var cSharpTest = @"
using Microsoft.AspNetCore.Mvc;
using System.Text.Encodings.Web;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [HttpGet(""{sensibleData}"")]
        public string Get(string sensibleData)
        {
            sensibleData = HtmlEncoder.Default.Encode(""value "" + sensibleData);
            return ""value "" + HtmlEncoder.Default.Encode(sensibleData);
        }
    }
}
            ";

            var visualBasicTest = @"
Imports System.Text.Encodings.Web
Imports Microsoft.AspNetCore.Mvc

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller
        <HttpGet(""{ sensibleData}"")> _
        Public Function [Get](sensibleData As String) As String
            sensibleData = HtmlEncoder.[Default].Encode(""value "" & sensibleData)
            Return ""value "" & HtmlEncoder.[Default].Encode(sensibleData)
        End Function
    End Class
End Namespace
            ";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [TestMethod]
        public async Task MethodWithOtherReturningTypeThanString()
        {
            var cSharpTest = @"
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }
    }
}
            ";

            var visualBasicTest = @"
Imports Microsoft.AspNetCore.Mvc
Imports Microsoft.AspNetCore.Authorization

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller
        <AllowAnonymous> _
        Public Function Login(returnUrl As String) As ActionResult
            ViewBag.ReturnUrl = returnUrl
            Return View()
        End Function
    End Class
End Namespace
            ";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [TestMethod]
        public async Task PrivateMethod()
        {
            var cSharpTest = @"
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [HttpGet(""{sensibleData}"")]
        private string Get(int sensibleData)
        {
            return ""value "" + sensibleData;
        }
    }
}
            ";

            var visualBasicTest = @"
Imports Microsoft.AspNetCore.Mvc

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller
        <HttpGet(""{sensibleData}"")> _
        Private Function[Get](sensibleData As Integer) As String
            Return ""value "" + sensibleData
        End Function
    End Class
End Namespace
            ";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        #endregion
    }
}
