using System.Collections.Generic;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test.Taint
{
    [TestClass]
    public class TaintAnalyzerSanitizerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            if (language == LanguageNames.CSharp)
                return new DiagnosticAnalyzer[] { new CSharpAnalyzers(new TaintAnalyzerCSharp()) };
            else
                return new DiagnosticAnalyzer[] { new VBasicAnalyzers(new TaintAnalyzerVisualBasic()) };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(System.Data.SqlClient.SqlCommand).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Web.Mvc.ActionResult).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Web.HttpResponse).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Text.Encodings.Web.HtmlEncoder).Assembly.Location),
            MetadataReference.CreateFromFile(Assembly.Load("System.Runtime, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")
                                                     .Location),
            MetadataReference.CreateFromFile(Assembly.Load("System.IO, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a")
                                                     .Location),
            MetadataReference.CreateFromFile(typeof(System.DirectoryServices.DirectorySearcher).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.Security.Application.Encoder).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Http.HttpResponse).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.Controller).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.ControllerBase).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.IUrlHelper).Assembly.Location),
            MetadataReference.CreateFromFile(Assembly.Load("netstandard, Version=2.0.0.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51")
                                                     .Location),
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [DataTestMethod]
        [DataRow("using System; using System.Web.Mvc;",           "!!Url.IsLocalUrl(input)",                                   "Redirect(input)",          false)]
        [DataRow("using System; using System.Web.Mvc;",           "Url.IsLocalUrl(input)",                                     "Redirect(input)",          false)]
        [DataRow("using System; using System.Web.Mvc;",           "Url.IsLocalUrl(inputModel.x)",                              "Redirect(inputModel.x)",   false)]
        [DataRow("using System; using Microsoft.AspNetCore.Mvc;", "Url.IsLocalUrl(input)",                                     "Redirect(input)",          false)]
        [DataRow("using System; using System.Web.Mvc;",           "Uri.TryCreate(input, UriKind.Relative, out uri)",           "Redirect(uri.ToString())", false)]
        [DataRow("using System; using System.Web.Mvc;",           "Uri.TryCreate(input, UriKind.RelativeOrAbsolute, out uri)", "Redirect(uri.ToString())", true)]
        public async Task Validator(string usingNamespace, string validate, string sink, bool warn)
        {
            var cSharpTest = $@"
{usingNamespace}

namespace sample
{{
    class Model
    {{
        public string x {{ get; set; }}
    }}

    class MyController : Controller
    {{
        public object Run(string input, Model inputModel)
        {{
#pragma warning disable CS0219
            Uri uri = null;
#pragma warning restore CS0219
            if ({validate})
                return {sink};
            else
                return null;
        }}
    }}
}}
";

            var vb = validate.CSharpReplaceToVBasic().Replace("!", "Not ");

            var visualBasicTest = $@"
{usingNamespace.CSharpReplaceToVBasic()}

Namespace sample
    Class Model
        Public Property x As String
    End Class

    Class MyController
        Inherits Controller

        Public Function Run(ByVal input As String, ByVal inputModel As Model) As Object
#Disable Warning BC42024
            Dim uri As Uri = Nothing
#Enable Warning BC42024
            If {vb} Then
                Return {sink}
            Else
                Return Nothing
            End If
        End Function
    End Class
End Namespace
";

            if (warn)
            {
                var expected = new DiagnosticResult
                {
                    Id       = "SCS0027",
                    Severity = DiagnosticSeverity.Warning,
                };

                await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
            }

        }

        [TestCategory("Detect")]
        [TestMethod]
        [Ignore("Implement control flow check.")]
        public async Task Validator2()
        {
            var cSharpTest = @"
using System.Web.Mvc;

namespace sample
{
    class MyController : Controller
    {
        public object Run(string input)
        {
            Url.IsLocalUrl(input);
            return Redirect(input);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Web.Mvc

Namespace sample
    Public Class MyController
        Inherits Controller

        Public Function Run(ByVal input As String) As Object
            Url.IsLocalUrl(input)
            Return Redirect(input)
        End Function
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0027",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        [Ignore("Implement control flow check.")]
        public async Task Validator3()
        {
            var cSharpTest = @"
using System.Web.Mvc;

namespace sample
{
    class MyController : Controller
    {
        public object Run(string input)
        {
            if (!Url.IsLocalUrl(input))
                return Redirect(input);
            else
                return null;
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Web.Mvc

Namespace sample
    Public Class MyController
        Inherits Controller

        Public Function Run(ByVal input As String) As Object
            If Not Url.IsLocalUrl(input) Then
                Return Redirect(input)
            Else
                Return Nothing
            End If
        End Function
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0027",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow(@"var s = new SqlCommand(input);",                                             "SCS0026")]

        [DataRow(@"Redirect(input);",                                                           "SCS0027")]
        [DataRow(@"var r = Url.RouteUrl(input);
                var a = new SqlCommand(r);
                Redirect(r);",                                                                  "SCS0026")]
        [DataRow(@"var r = Url.RouteUrl(input);
                var r2 = r;
                var a = new SqlCommand(r2);
                Redirect(r2);",                                                                 "SCS0026")]

        [DataRow(@"var d = new DirectoryEntry();
                   d.Path = input;",                                                            "SCS0031")]
        [DataRow(@"var d = new DirectoryEntry(input);",                                         "SCS0031")]
        [DataRow(@"var d = new DirectoryEntry();
                   var enc = Encoder.LdapFilterEncode(input);
                   d.Path = enc;",                                                              "SCS0031")]
        [DataRow(@"var d = new DirectoryEntry(Encoder.LdapFilterEncode(input));",               "SCS0031")]
        [DataRow(@"var d = new DirectoryEntry();
                   var enc = Encoder.LdapDistinguishedNameEncode(input);
                   d.Path = enc;
                   var a = new SqlCommand(enc);",                                               "SCS0026")]
        [DataRow(@"var enc = Encoder.LdapDistinguishedNameEncode(input);
                   var d = new DirectoryEntry(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0026")]

        [DataRow(@"var d = new DirectorySearcher();
                   d.Filter = input;",                                                          "SCS0031")]
        [DataRow(@"var d = new DirectorySearcher(input);",                                      "SCS0031")]
        [DataRow(@"var d = new DirectorySearcher();
                   var enc = Encoder.LdapDistinguishedNameEncode(input);
                   d.Filter = enc;",                                                            "SCS0031")]
        [DataRow(@"var d = new DirectorySearcher(Encoder.LdapDistinguishedNameEncode(input));", "SCS0031")]
        [DataRow(@"var enc = Encoder.LdapFilterEncode(input);
                   var d = new DirectorySearcher();
                   d.Filter = enc;
                   var a = new SqlCommand(enc);",                                               "SCS0026")]
        [DataRow(@"var enc = Encoder.LdapFilterEncode(input);
                   var d = new DirectorySearcher(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0026")]

        [DataRow(@"Response.Write(input);",                                                     "SCS0029")]
        [DataRow(@"Response.Write(Encoder.LdapFilterEncode(input));",                           "SCS0029")]
        [DataRow(@"var enc = Encoder.HtmlEncode(input);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0026")]
        [DataRow(@"var enc = _HttpServerUtility.HtmlEncode(input);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0026")]
        [DataRow(@"var enc = System.Text.Encodings.Web.HtmlEncoder.Default.Encode(input);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0026")]
        [DataRow(@"var enc = HttpUtility.HtmlEncode(input);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0026")]
        [DataRow(@"var o = (object)input;
                   var enc = HttpUtility.HtmlEncode(o);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0026")]
        [DataRow(@"var w = new StringWriter();
                   HttpUtility.HtmlEncode(input, w);
                   var enc = w.ToString();
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0026")]
        [DataRow(@"var enc = System.Web.Security.AntiXss.AntiXssEncoder.HtmlEncode(input, true);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0026")]
        [DataRow(@"var enc = System.Web.Security.AntiXss.AntiXssEncoder.HtmlEncode(input, false);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0026")]
        [DataRow(@"var w = new StringWriter();
                   System.Text.Encodings.Web.HtmlEncoder.Default.Encode(w, input);
                   var enc = w.ToString();
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0026")]
        [DataRow(@"var w = new StringWriter();
                   System.Text.Encodings.Web.HtmlEncoder.Default.Encode(w, input, 0, 10);
                   var enc = w.ToString();
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0026")]
        [DataRow(@"var w = new StringWriter();
                   System.Text.Encodings.Web.HtmlEncoder.Default.Encode(w, inputChars, 0, 10);
                   var enc = w.ToString();
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0026")]
        [DataRow(@"var w = new StringWriter();
                   _HttpServerUtility.HtmlEncode(input, w);
                   var enc = w.ToString();
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0026")]

        // sanitizer bit merging
        // sanitized with safe
        [DataRow(@"var r = Url.RouteUrl(input) + Path.GetRandomFileName();
                   var a = new SqlCommand(r);
                   Redirect(r);",                                                               "SCS0026")]
        [DataRow(@"var r = Path.GetRandomFileName() + Url.RouteUrl(input);
                   var a = new SqlCommand(r);
                   Redirect(r);",                                                               "SCS0026")]

        // sanitized with const
        [DataRow(@"var r = Url.RouteUrl(input) + ""a"";
                   var a = new SqlCommand(r);
                   Redirect(r);",                                                               "SCS0026")]
        [DataRow(@"var r = ""a"" + Url.RouteUrl(input);
                   var a = new SqlCommand(r);
                   Redirect(r);",                                                               "SCS0026")]
        [DataRow(@"var enc = Encoder.HtmlEncode(input) + Encoder.HtmlEncode(""a"");
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0026")]
        [DataRow(@"var enc = Encoder.HtmlEncode(""a"") + Encoder.HtmlEncode(input);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0026")]
        [DataRow(@"var enc = Encoder.HtmlEncode(""a"") + Encoder.HtmlEncode(""a"");
                   Response.Write(enc);
                   var a = new SqlCommand(enc);
                   var b = new SqlCommand(input);",                                             "SCS0026")]

        // sanitized with sanitized same type and different
        [DataRow(@"var enc = Encoder.HtmlEncode(input) + Encoder.HtmlEncode(input);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0026")]
        [DataRow(@"var enc = Encoder.HtmlEncode(input) + Encoder.HtmlEncode(Encoder.LdapFilterEncode(input));
                   Response.Write(enc);
                   var d = new DirectorySearcher(enc);",                                        "SCS0031")]
        [DataRow(@"var enc = Encoder.HtmlEncode(Encoder.LdapFilterEncode(input)) + Encoder.HtmlEncode(input);
                   Response.Write(enc);
                   var d = new DirectorySearcher(enc);",                                        "SCS0031")]
        [DataRow(@"var enc = Encoder.HtmlEncode(Encoder.LdapFilterEncode(input)) + Encoder.HtmlEncode(Encoder.LdapFilterEncode(input));
                   Response.Write(enc);
                   var d = new DirectorySearcher(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0026")]
        [DataRow(@"var enc = Encoder.HtmlEncode(input) + Encoder.LdapFilterEncode(input);
                   Response.Write(enc);",                                                       "SCS0029")]
        [DataRow(@"var enc = Encoder.LdapFilterEncode(input) + Encoder.HtmlEncode(input);
                   Response.Write(enc);",                                                       "SCS0029")]
        public async Task Sanitizer(string payload, string warningId)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System.Data.SqlClient;
    using System.Web.Mvc;
    using System.DirectoryServices;
    using Microsoft.Security.Application;
    using System.Web;
    using System.IO;
#pragma warning restore 8019

namespace sample
{{
    class MyController : Controller
    {{
#pragma warning disable CS0414
        private HttpServerUtility _HttpServerUtility = null;
#pragma warning restore CS0414

        public void Run(string input, char[] inputChars)
        {{
            {payload}
        }}
    }}
}}
";

            payload = payload.CSharpReplaceToVBasic();

            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System.Data.SqlClient
    Imports System.Web.Mvc
    Imports System.DirectoryServices
    Imports Microsoft.Security.Application
    Imports System.Web
    Imports System.IO
#Enable Warning BC50001

Namespace sample
    Public Class MyController
        Inherits Controller

        Private _HttpServerUtility As HttpServerUtility = Nothing

        Public Sub Run(input As System.String, ByVal inputChars As System.Char())
            {payload}
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id       = warningId,
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }
    }
}
