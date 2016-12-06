using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers;
using System.Collections.Generic;
using TestHelper;

namespace RoslynSecurityGuard.Test.Tests
{
    [TestClass]
    public class XssPreventionAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
        {
            return new[] { new XssPreventionAnalyzer() };
        }

        #region Tests that are producing diagnostics

        [TestMethod]
        public void unencodedSensibleData()
        {
            var test = @"
            using Microsoft.AspNetCore.Mvc;
            using System.Text.Encodings.Web;

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
            var expected = new DiagnosticResult
            {
                Id = "SG0029",
                Severity = DiagnosticSeverity.Warning
            };

            VerifyCSharpDiagnostic(test, expected);
        }

        #endregion

        #region Tests that are not producing diagnostics

        [TestMethod]
        public void encodedSensibleDataWithTemporaryVariable()
        {
            var test = @"
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

            VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public void encodedSensibleDataOnReturn()
        {
            var test = @"
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

            VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public void returnEncodedData()
        {
            var test = @"
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

            VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public void encodedDataWithSameVariableUsage()
        {
            var test = @"
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

            VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public void methodWithOtherReturningTypeThanString()
        {
            var test = @"
            using Microsoft.AspNetCore.Mvc;
            using System.Text.Encodings.Web;

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

            VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public void privateMethod()
        {
            var test = @"
            using Microsoft.AspNetCore.Mvc;
            using System.Text.Encodings.Web;

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

            VerifyCSharpDiagnostic(test);
        }

        #endregion
    }
}
