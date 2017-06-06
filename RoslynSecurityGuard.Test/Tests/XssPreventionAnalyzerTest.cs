using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers;
using System.Collections.Generic;
using System.Reflection;
using TestHelper;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace RoslynSecurityGuard.Test.Tests
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
                MetadataReference.CreateFromFile(typeof(HttpGetAttribute).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(HtmlEncoder).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(Controller).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(AllowAnonymousAttribute).Assembly.Location),
                MetadataReference.CreateFromFile(Assembly.Load("System.Runtime, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a").Location),
            };
        }

        #region Tests that are producing diagnostics

        [TestMethod]
        public async Task unencodedSensibleData()
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
                Id = "SG0029",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        #endregion

        #region Tests that are not producing diagnostics

        [TestMethod]
        public async Task encodedSensibleDataWithTemporaryVariable()
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
        public async Task encodedSensibleDataOnReturn()
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
        public async Task returnEncodedData()
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
        public async Task encodedDataWithSameVariableUsage()
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
        public async Task methodWithOtherReturningTypeThanString()
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
        public async Task privateMethod()
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
