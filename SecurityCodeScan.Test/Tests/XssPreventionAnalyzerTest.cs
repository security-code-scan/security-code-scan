using System.Collections.Generic;
using System.Reflection;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNetCore.Authorization;
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
    public class XssPreventionAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            return new DiagnosticAnalyzer[]
            {
                new TaintAnalyzerCSharp(),
                new TaintAnalyzerVisualBasic(),
                new XssPreventionAnalyzerCSharp(),
                new XssPreventionAnalyzerVisualBasic()
            };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.HttpGetAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.Controller).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(AllowAnonymousAttribute).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Web.Mvc.Controller).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(HtmlEncoder).Assembly.Location),
            MetadataReference.CreateFromFile(Assembly.Load("System.Runtime, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")
                                                     .Location),
            MetadataReference.CreateFromFile(typeof(HttpResponse).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        /// <summary> Potential XSS vulnerability </summary>
        private DiagnosticResult Expected = new DiagnosticResult
        {
            Id       = "SCS0029",
            Severity = DiagnosticSeverity.Warning
        };

        #region Tests that are producing diagnostics

        [TestCategory("Detect")]
        [DataRow("System.Web", "System.String", "Response.Write(userInput)")]
        [DataRow("System.Web", "System.Char[]", "Response.Write(userInput, x, y)")]
        [DataTestMethod]
        public async Task HttpResponseWrite(string @namespace, string inputType, string sink)
        {
            var cSharpTest = $@"
using {@namespace};

class Vulnerable
{{
    public static HttpResponse Response = null;

    public static void Run({inputType} userInput, int x, int y)
    {{
        {sink};
    }}
}}
            ";

            inputType = inputType.CSharpReplaceToVBasic();

            var visualBasicTest = $@"
Imports {@namespace}

Class Vulnerable
    Public Shared Response As HttpResponse

    Public Shared Sub Run(userinput As {inputType}, x As System.Int32, y As System.Int32)
        {sink}
    End Sub
End Class
            ";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("System.Web.Mvc",                       "HttpGet")]
        [DataRow("HG = System.Web.Mvc.HttpGetAttribute", "HG")]
        public async Task UnencodedInputDataSystemWebMvc(string alias, string attributeName)
        {
            string cSharpTest = $@"
using {alias};

namespace VulnerableApp
{{
    public class TestController : System.Web.Mvc.Controller
    {{
        [{attributeName}]
        public string Get(int inputData)
        {{
            return ""value "" + inputData;
        }}
    }}
}}
            ";

            string visualBasicTest = $@"
Imports {alias}

Namespace VulnerableApp
    Public Class TestController
        Inherits System.Web.Mvc.Controller
        <{attributeName}> _
        Public Function [Get](inputData As Integer) As String
            Return ""value "" & inputData.ToString()
        End Function
    End Class
End Namespace
            ";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task UnencodedInputData()
        {
            const string cSharpTest = @"
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [HttpGet(""{inputData}"")]
        public string Get(int inputData)
        {
            return ""value "" + inputData;
        }
    }
}
            ";

            const string visualBasicTest = @"
Imports Microsoft.AspNetCore.Mvc

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller
        <HttpGet(""{inputData}"")> _
        Public Function [Get](inputData As Integer) As String
            Return ""value "" & inputData.ToString()
        End Function
    End Class
End Namespace
            ";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task UnencodedInputData2()
        {
            const string cSharpTest = @"
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [HttpGet(""{inputData}"")]
        // using 'virtual' to make 'public' not the only modifier
        // using 'System.String' instead of 'string' to see if it is handled
        public virtual System.String Get(int inputData)
        {
            return ""value "" + inputData;
        }
    }
}
            ";

            const string visualBasicTest = @"
Imports Microsoft.AspNetCore.Mvc

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller
        ' using Overridable to make Public not the only modifier
        ' using System.String instead of String to see if it is handled
        <HttpGet(""{inputData}"")> _
        Public Overridable Function [Get](inputData As Integer) As System.String
            Return ""value "" & inputData.ToString()
        End Function
    End Class
End Namespace
            ";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        #endregion

        #region Tests that are not producing diagnostics

        [TestCategory("Safe")]
        [TestMethod]
        public async Task BaseNotController()
        {
            const string cSharpTest = @"
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp
{
    public class Controller
    {
    }

    public class TestController : Controller
    {
        [HttpGet(""{inputData}"")]
        public string Get(int inputData)
        {
            return ""value "" + inputData;
        }
    }
}
            ";

            const string visualBasicTest = @"
Imports Microsoft.AspNetCore.Mvc

Namespace VulnerableApp
    Public Class Controller
    End Class

    Public Class TestController
        Inherits Controller
        <HttpGet(""{inputData}"")> _
        Public Function [Get](inputData As Integer) As String
            Return ""value "" & inputData.ToString()
        End Function
    End Class
End Namespace
            ";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task NoSymbolReturnType()
        {
            const string cSharpTest = @"
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [HttpGet(""{inputData}"")]
        public xxx Get(int inputData)
        {
        }
    }
}
            ";

            const string visualBasicTest = @"
Imports Microsoft.AspNetCore.Mvc

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller
        <HttpGet(""{inputData}"")> _
        Public Function [Get](inputData As Integer) As XXX
        End Function
    End Class
End Namespace
            ";

            await VerifyCSharpDiagnostic(cSharpTest, new[]
                                                        {
                                                            new DiagnosticResult { Id = "CS0246" },
                                                            new DiagnosticResult { Id = "CS0161" }
                                                        }).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new[]
                                                        {
                                                            new DiagnosticResult { Id = "BC30002" },
                                                            new DiagnosticResult { Id = "BC42105" }
                                                        }).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task Void()
        {
            const string cSharpTest = @"
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        // see if 'void' is handled
        [HttpGet(""{inputData}"")]
        public void Get(int inputData)
        {
        }
    }
}
            ";

            const string visualBasicTest = @"
Imports Microsoft.AspNetCore.Mvc

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller
        ' see if Void is handled
        <HttpGet(""{inputData}"")> _
        Public Function [Get](inputData As Integer)
        End Function
    End Class
End Namespace
            ";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new DiagnosticResult { Id = "BC42105" }).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task EncodedInputDataWithTemporaryVariable()
        {
            const string cSharpTest = @"
using Microsoft.AspNetCore.Mvc;
using System.Text.Encodings.Web;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [HttpGet(""{inputData}"")]
        public string Get(string inputData)
        {
            string temporary_variable = HtmlEncoder.Default.Encode(inputData);
            return ""value "" + temporary_variable;
        }
    }
}
            ";

            const string visualBasicTest = @"
Imports Microsoft.AspNetCore.Mvc
Imports System.Text.Encodings.Web

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller
        <HttpGet(""{ inputData}"")> _
        Public Function [Get](inputData As String) As String
            Dim temporary_variable As String = HtmlEncoder.[Default].Encode(inputData)
            Return ""value "" & temporary_variable
        End Function
    End Class
End Namespace
            ";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task EncodedInputDataOnReturn()
        {
            const string cSharpTest = @"
using Microsoft.AspNetCore.Mvc;
using System.Text.Encodings.Web;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [HttpGet(""{inputData}"")]
        public string Get(string inputData)
        {
            return ""value "" + HtmlEncoder.Default.Encode(inputData);
        }
    }
}
            ";

            const string visualBasicTest = @"
Imports System.Text.Encodings.Web
Imports Microsoft.AspNetCore.Mvc

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller
        <HttpGet(""{ inputData}"")> _
        Public Function [Get](inputData As String) As String
            Return ""value "" & HtmlEncoder.[Default].Encode(inputData)
        End Function
    End Class
End Namespace
            ";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task ReturnEncodedData()
        {
            const string cSharpTest = @"
using Microsoft.AspNetCore.Mvc;
using System.Text.Encodings.Web;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [HttpGet(""{inputData}"")]
        public string Get(string inputData)
        {
            return HtmlEncoder.Default.Encode(""value "" + inputData);
        }
    }
}
            ";

            const string visualBasicTest = @"
Imports System.Text.Encodings.Web
Imports Microsoft.AspNetCore.Mvc

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller
        <HttpGet(""{ inputData}"")> _
        Public Function [Get](inputData As String) As String
            Return HtmlEncoder.[Default].Encode(""value "" & inputData)
        End Function
    End Class
End Namespace
            ";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task EncodedDataWithSameVariableUsage()
        {
            const string cSharpTest = @"
using Microsoft.AspNetCore.Mvc;
using System.Text.Encodings.Web;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [HttpGet(""{inputData}"")]
        public string Get(string inputData)
        {
            inputData = HtmlEncoder.Default.Encode(""value "" + inputData);
            return ""value "" + HtmlEncoder.Default.Encode(inputData);
        }
    }
}
            ";

            const string visualBasicTest = @"
Imports System.Text.Encodings.Web
Imports Microsoft.AspNetCore.Mvc

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller
        <HttpGet(""{ inputData}"")> _
        Public Function [Get](inputData As String) As String
            inputData = HtmlEncoder.[Default].Encode(""value "" & inputData)
            Return ""value "" & HtmlEncoder.[Default].Encode(inputData)
        End Function
    End Class
End Namespace
            ";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task MethodWithOtherReturningTypeThanString()
        {
            const string cSharpTest = @"
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

            const string visualBasicTest = @"
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

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task PrivateMethod()
        {
            const string cSharpTest = @"
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [HttpGet(""{inputData}"")]
        private string Get(int inputData)
        {
            return ""value "" + inputData;
        }
    }
}
            ";

            const string visualBasicTest = @"
Imports Microsoft.AspNetCore.Mvc

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller
        <HttpGet(""{inputData}"")> _
        Private Function[Get](inputData As Integer) As String
            Return ""value "" + inputData
        End Function
    End Class
End Namespace
            ";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        #endregion
    }
}
