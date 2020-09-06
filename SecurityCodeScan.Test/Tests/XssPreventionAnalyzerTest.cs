using System.Collections.Generic;
using System.Reflection;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNetCore.Authorization;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Config;
using SecurityCodeScan.Test.Helpers;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test
{
    [TestClass]
    public class XssPreventionAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string _)
        {
            return new[] { new XssTaintAnalyzer() };
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
            MetadataReference.CreateFromFile(Assembly.Load("netstandard, Version=2.0.0.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51")
                                                     .Location),
            MetadataReference.CreateFromFile(typeof(HttpResponse).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.Security.Application.Encoder).Assembly.Location),
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        /// <summary> Potential XSS vulnerability </summary>
        private DiagnosticResult Expected = new DiagnosticResult
        {
            Id       = "SCS0029",
            Severity = DiagnosticSeverity.Warning
        };

        [TestCategory("Detect")]
        [TestMethod]
        public async Task XssFromCSharpExpressionBody()
        {
            const string cSharpTest = @"
using System.Web;

public class Vulnerable
{
    public static HttpResponse Response = null;
    public static HttpRequest  Request  = null;

    public static void Run()
    => Response.Write(Request.Params[0]);
}
";
            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(10, 23)).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataRow("System.Web", "Request.Params[0]",               "",              "Response.ContentType = userInput")]
        [DataRow("System.Web", "Request.ContentType",             "",              "Response.ContentType = userInput")]
        [DataRow("System.Web", "Request.Params[0]",               "",              "Response.Write(userInput)")]
        [DataRow("System.Web", "Request.Params[0]",               "System.String", "Response.Write(userInput)")]
        [DataRow("System.Web", "Request.Params[0].ToString()",    "System.String", "Response.Write(userInput)")]
        [DataRow("System.Web", "Request.Params[0].ToCharArray()", "",              "Response.Write(userInput, 1, 1)")]
        [DataTestMethod]
        public async Task HttpResponseWrite(string @namespace, string inputType, string cast, string sink)
        {
            var csInput = string.IsNullOrEmpty(cast) ? inputType : $"({cast}){inputType}";
            var cSharpTest = $@"
using {@namespace};

public class Vulnerable
{{
    public static HttpResponse Response = null;
    public static HttpRequest  Request  = null;

    public static void Run()
    {{
        var userInput = {csInput};
        {sink};
    }}
}}
";

            inputType = inputType.CSharpReplaceToVBasic();
            var vbInput = string.IsNullOrEmpty(cast) ? inputType : $"DirectCast({inputType}, {cast})";

            var visualBasicTest = $@"
Imports {@namespace}

Public Class Vulnerable
    Public Shared Response As HttpResponse
    Public Shared Request  As HttpRequest

    Public Shared Sub Run()
        Dim userInput = {vbInput}
        {sink}
    End Sub
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("System.Web.Mvc",                                 "System.Web.Mvc.Controller",               "HttpGet")]
        [DataRow("HG = System.Web.Mvc.HttpGetAttribute",           "System.Web.Mvc.Controller",               "HG")]
        [DataRow("Microsoft.AspNetCore.Mvc",                       "Microsoft.AspNetCore.Mvc.Controller",     "HttpGet")]
        [DataRow("HG = Microsoft.AspNetCore.Mvc.HttpGetAttribute", "Microsoft.AspNetCore.Mvc.Controller",     "HG")]
        [DataRow("Microsoft.AspNetCore.Mvc",                       "Microsoft.AspNetCore.Mvc.ControllerBase", "HttpGet")]
        [Ignore("todo: sink on return")]
        // todo: how to define sink on return?
        // maybe isInterface: true and special handling for return
        public async Task UnencodedInputData(string alias, string controller, string attributeName)
        {
            string cSharpTest = $@"
using {alias};

namespace VulnerableApp
{{
    public class TestController : {controller}
    {{
        [{attributeName}]
        public string Get(string inputData)
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
        Inherits {controller}
        <{attributeName}> _
        Public Function [Get](inputData As String) As String
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
        [Ignore("todo: sink on return")]
        public async Task UnencodedInputDataExpression()
        {
            const string cSharpTest = @"
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [HttpGet(""{inputData}"")]
        public string Get(string inputData) => ""value "" + inputData;
    }
}
            ";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        [Ignore("todo: sink on return")]
        public async Task UnencodedInputData2()
        {
            const string cSharpTest = @"
using Microsoft.AspNetCore.Mvc;
using System;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [HttpGet(""{inputData}"")]
        // using 'virtual' to make 'public' not the only modifier
        // using 'System.String' instead of 'string' to see if it is handled
        public virtual System.String Get(string inputData)
        {
            if (inputData == null)
                throw new ArgumentNullException(nameof(inputData));

            return ""value "" + inputData;
        }
    }
}
";

            const string visualBasicTest = @"
Imports Microsoft.AspNetCore.Mvc
Imports System

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller
        ' using Overridable to make Public not the only modifier
        ' using System.String instead of String to see if it is handled
        <HttpGet(""{inputData}"")> _
        Public Overridable Function [Get](inputData As String) As System.String
            If inputData Is Nothing Then Throw New ArgumentNullException(NameOf(inputData))
            Return ""value "" & inputData
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task NotAnInputParameter()
        {
            const string cSharpTest = @"
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        private string Test()
        {
            return ""something"";
        }

        [HttpGet]
        public string Get(string inputData)
        {
            return Test();
        }
    }
}
";

            const string visualBasicTest = @"
Imports Microsoft.AspNetCore.Mvc

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller

        Private Function Test() As String
            Return ""something""
        End Function

        <HttpGet(""{inputData}"")> _
        Public Function [Get](inputData As String) As String
            Return Test()
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task NotAnInputParameter2()
        {
            const string cSharpTest = @"
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [HttpGet]
        public string Get(string inputData)
        {
            var x = inputData;
            return ""constant"";
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
        Public Function [Get](inputData As String) As String
            Dim x = inputData
            Return ""constant""
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task UnencodedInputDataInt()
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

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task UnencodedInputDataInt2()
        {
            const string cSharpTest = @"
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [HttpGet(""{inputData}"")]
        public string Get(int inputDataInt, string inputDataString)
        {
            return ""value "" + inputDataInt;
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
        Public Function [Get](inputDataInt As Integer, inputDataString As String) As String
            Return ""value "" & inputDataInt.ToString()
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        [Ignore("todo: sink on return")]
        public async Task UnencodedInputDataCorrectReturnLine()
        {
            const string cSharpTest = @"
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [HttpGet(""{inputData}"")]
        public string Get(int inputDataInt, string inputDataString)
        {
            if (inputDataString != null)
                return inputDataString;

            return ""value "" + inputDataInt;
        }
    }
}
";

            const string visualBasicTest = @"
Imports Microsoft.AspNetCore.Mvc

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller

        <HttpGet(""{inputData}"")>
        Public Function [Get](ByVal inputDataInt As Integer, ByVal inputDataString As String) As String
            If inputDataString IsNot Nothing Then Return inputDataString
            Return ""value "" & inputDataInt
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(12)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(10)).ConfigureAwait(false);
        }

        [DataRow("AddAttribute(stringInput, \"const\")", true)]
        [DataRow("AddAttribute(\"const\", stringInput)", true)]
        [DataRow("AddAttribute(stringInput, \"const\", true)", true)]
        [DataRow("AddAttribute(\"const\", stringInput, true)", true)]
        [DataRow("AddStyleAttribute(stringInput, \"const\")", true)]
        [DataRow("AddStyleAttribute(\"const\", stringInput)", true)]
        [DataRow("RenderBeginTag(stringInput)", true)]
        [DataRow("Write(stringInput)", true)]
        [DataRow("Write(stringInput, \"const\")", true)]
        [DataRow("Write(\"{0}\", objectInput)", true)]
        [DataRow("Write(\"{0}{1}\", \"const\", objectInput)", true)]
        // todo: roslyn params array handling
        //[DataRow("Write(\"{0}{1}{2}\", \"const\", \"const\", objectInput)", true)]
        [DataRow("Write(\"{0}\", objectArray)", true)]
        [DataRow("Write(charInput)", true)]
        [DataRow("Write(charArray)", true)]
        [DataRow("Write(objectInput)", true)]
        [DataRow("WriteAttribute(stringInput, \"const\")", true)]
        [DataRow("WriteAttribute(\"const\", stringInput)", true)]
        [DataRow("WriteAttribute(stringInput, \"const\", true)", true)]
        [DataRow("WriteAttribute(\"const\", stringInput, true)", true)]
        [DataRow("WriteBeginTag(stringInput)", true)]
        [DataRow("WriteEndTag(stringInput)", true)]
        [DataRow("WriteFullBeginTag(stringInput)", true)]
        [DataRow("WriteStyleAttribute(stringInput, \"const\")", true)]
        [DataRow("WriteStyleAttribute(\"const\", stringInput)", true)]
        [DataRow("WriteStyleAttribute(stringInput, \"const\", true)", true)]
        [DataRow("WriteStyleAttribute(\"const\", stringInput, true)", true)]
        [DataTestMethod]
        public async Task XssHtmlTextWriter(string sink, bool warn)
        {
            var cSharpTest = $@"
using System.Web.UI;
using System.IO;
using System.Text;

public class Vulnerable
{{
    public static void Run(string stringInput, char charInput, char[] charArray, object objectInput, object[] objectArray)
    {{
        var sb = new StringBuilder();
        var writer = new HtmlTextWriter(new StringWriter(sb));
        writer.{sink};
    }}
}}
";

            sink = sink.CSharpReplaceToVBasic();

            var visualBasicTest = $@"
Imports System.Web.UI
Imports System.IO
Imports System.Text

Public Class Vulnerable
    Public Shared Sub Run(ByVal stringInput As String, ByVal charInput As Char, ByVal charArray As Char(), ByVal objectInput As Object, ByVal objectArray As Object())
        Dim sb = New StringBuilder()
        Dim writer = New HtmlTextWriter(New StringWriter(sb))
        writer.{sink}
    End Sub
End Class
";

            var testConfig = @"
TaintEntryPoints:
  Vulnerable:
    Method:
      Name: Run
";
            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            if (warn)
            {
                await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            }
        }

        [DataRow("new Control(); temp.ID = input", true)]
        [DataRow("new Label(); temp.Text = input", true)]
        [DataRow("new HyperLink(); temp.NavigateUrl = input", true)]
        [DataRow("new HyperLink(); temp.Text = input", true)]
        [DataRow("new LinkButton(); temp.Text = input", true)]
        [DataRow("new Literal(); temp.Text = input", true)]
        [DataRow("new CheckBox(); temp.Text = input", true)]
        [DataRow("new RadioButton(); temp.Text = input", true)]
        [DataRow("new RadioButton(); temp.GroupName = input", true)]
        [DataRow("new Calendar(); temp.Caption = input", true)]
        [DataRow("new Table(); temp.Caption = input", true)]
        [DataRow("new Panel(); temp.GroupingText = input", true)]
        [DataRow("new HtmlElement(); temp.InnerHtml = input", true)]
        [DataRow("new Page(); temp.ClientScript.RegisterStartupScript(null, \"constant\", input)", true)]
        [DataRow("new Page(); temp.ClientScript.RegisterClientScriptBlock(null, \"constant\", input)", true)]
        [DataRow("new Page(); temp.RegisterStartupScript(\"constant\", input)", true)]
        [DataRow("new Page(); temp.RegisterClientScriptBlock(\"constant\", input)", true)]
        [DataRow("new Page(); temp.Response.Write(input)", true)]
        [DataRow("new Page(); temp.Response.Write(input.ToCharArray(), 0, 1)", true)]

        [DataRow("new Control(); temp.ID = \"constant\"", false)]
        [DataRow("new Label(); temp.Text = \"constant\"", false)]
        [DataRow("new HyperLink(); temp.NavigateUrl = \"constant\"", false)]
        [DataRow("new HyperLink(); temp.Text = \"constant\"", false)]
        [DataRow("new HyperLink(); temp.ImageUrl = \"constant\"", false)]
        [DataRow("new Image(); temp.ImageUrl = \"constant\"", false)]
        [DataRow("new LinkButton(); temp.Text = \"constant\"", false)]
        [DataRow("new Literal(); temp.Text = \"constant\"", false)]
        [DataRow("new CheckBox(); temp.Text = \"constant\"", false)]
        [DataRow("new RadioButton(); temp.Text = \"constant\"", false)]
        [DataRow("new RadioButton(); temp.GroupName = \"constant\"", false)]
        [DataRow("new Calendar(); temp.Caption = \"constant\"", false)]
        [DataRow("new Table(); temp.Caption = \"constant\"", false)]
        [DataRow("new Panel(); temp.GroupingText = \"constant\"", false)]
        [DataRow("new HtmlElement(); temp.InnerHtml = \"constant\"", false)]
        [DataRow("new Page(); temp.ClientScript.RegisterStartupScript(null, \"constant\", \"constant\")", false)]
        [DataRow("new Page(); temp.ClientScript.RegisterClientScriptBlock(null, \"constant\", \"constant\")", false)]
        [DataRow("new Page(); temp.RegisterStartupScript(\"constant\", \"constant\")", false)]
        [DataRow("new Page(); temp.RegisterClientScriptBlock(\"constant\", \"constant\")", false)]
        [DataRow("new Page(); temp.Response.Write(\"constant\")", false)]
        [DataRow("new Page(); temp.Response.Write(\"constant\".ToCharArray(), 0, 1)", false)]

        [DataRow("new HyperLink(); temp.NavigateUrl = Encoder.UrlPathEncode(input)", false)]
        [DataRow("new HyperLink(); temp.NavigateUrl = Encoder.UrlEncode(input)", false)]
        [DataRow("new HyperLink(); temp.NavigateUrl = Encoder.HtmlEncode(input)", false)]
        [DataRow("new Label(); temp.Text = new Page().Server.HtmlEncode(input)", false)]
        [DataRow("new Label(); var sw = new StringWriter(); var page = new Page(); page.Server.HtmlEncode(input, sw); temp.Text = sw.ToString()", false)]

        [DataTestMethod]
        public async Task XssInWebForms(string sink, bool warn)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System.Web;
    using System.Web.UI;
    using System.Web.UI.WebControls;
    using System.Web.UI.HtmlControls;
    using System.IO;
    using System.Text;
    using Encoder = Microsoft.Security.Application.Encoder;
#pragma warning restore 8019

public class Vulnerable
{{
    public static HttpRequest Request = null;

    public static void Run(string input)
    {{
        input = Request.QueryString[0];
#pragma warning disable 618
        var temp = {sink};
#pragma warning restore 618
    }}
}}
";

            sink = sink.CSharpReplaceToVBasic();

            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System.Web
    Imports System.Web.UI
    Imports System.Web.UI.WebControls
    Imports System.Web.UI.HtmlControls
    Imports System.IO
    Imports Microsoft.Security.Application
    Imports System.Text
    Imports Encoder = Microsoft.Security.Application.Encoder
#Enable Warning BC50001

Public Class Vulnerable
    Public Shared Request As HttpRequest
    Public Shared Page As Page

    Public Shared Sub Run(input As System.String)
        input = Request.QueryString(0)
#Disable Warning BC40000
        Dim temp = {sink}
#Enable Warning BC40000
    End Sub
End Class
";

            if (warn)
            {
                await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
            }
        }

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
    }
}
