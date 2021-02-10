using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Config;
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test.Taint
{
    [TestClass]
    public class TaintAnalyzerSanitizerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            if (language == LanguageNames.CSharp)
                return new DiagnosticAnalyzer[]
                {
                    new XssTaintAnalyzer(),
                    new OpenRedirectTaintAnalyzer(),
                    new SqlInjectionTaintAnalyzer(),
                    new LdapPathTaintAnalyzer(),
                    new LdapFilterTaintAnalyzer()
                };
            else
                return new DiagnosticAnalyzer[]
                {
                    new XssTaintAnalyzer(),
                    new OpenRedirectTaintAnalyzer(),
                    new SqlInjectionTaintAnalyzer(),
                    new LdapPathTaintAnalyzer(),
                    new LdapFilterTaintAnalyzer()
                };
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
            MetadataReference.CreateFromFile(Assembly.Load("netstandard, Version=2.0.0.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51")
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
        [DataRow("System.String",           "System.String", "value = input", true)]
        [DataRow("System.Byte",             "System.String", "value = input.ToString()", false)]
        [DataRow("System.SByte",            "System.String", "value = input.ToString()", false)]
        [DataRow("System.Char",             "System.String", "value = input.ToString()", false)]
        [DataRow("System.Boolean",          "System.String", "value = input.ToString()", false)]
        [DataRow("System.Int16",            "System.String", "value = input.ToString()", false)]
        [DataRow("System.Int32",            "System.String", "value = input.ToString()", false)]
        [DataRow("System.Int64",            "System.String", "value = input.ToString()", false)]
        [DataRow("System.UInt16",           "System.String", "value = input.ToString()", false)]
        [DataRow("System.UInt32",           "System.String", "value = input.ToString()", false)]
        [DataRow("System.UInt64",           "System.String", "value = input.ToString()", false)]
        [DataRow("System.IntPtr",           "System.String", "value = input.ToString()", false)]
        [DataRow("System.UIntPtr",          "System.String", "value = input.ToString()", false)]
        [DataRow("System.Single",           "System.String", "value = input.ToString()", false)]
        [DataRow("System.Double",           "System.String", "value = input.ToString()", false)]
        [DataRow("System.Decimal",          "System.String", "value = input.ToString()", false)]
        [DataRow("System.Guid",             "System.String", "value = input.ToString()", false)]
        [DataRow("System.DateTime",         "System.String", "value = input.ToString()", false)]
        [DataRow("System.TimeSpan",         "System.String", "value = input.ToString()", false)]
        [DataRow("System.DateTimeOffset",   "System.String", "value = input.ToString()", false)]
        [DataRow("System.Enum",             "System.String", "value = input.ToString()", false)]
        [DataRow("System.String",           "System.Byte",      "value = System.Byte.Parse(input)",      false)]
        [DataRow("System.String",           "System.SByte",     "value = System.SByte.Parse(input)",     false)]
        [DataRow("System.String",           "System.Char",      "value = System.Char.Parse(input)",      false)]
        [DataRow("System.String",           "System.Boolean",   "value = System.Boolean.Parse(input)",   false)]
        [DataRow("System.String",           "System.Int16",     "value = System.Int16.Parse(input)",     false)]
        [DataRow("System.String",           "System.Int32",     "value = System.Int32.Parse(input)",     false)]
        [DataRow("System.String",           "System.Int64",     "value = System.Int64.Parse(input)",     false)]
        [DataRow("System.String",           "System.UInt16",    "value = System.UInt16.Parse(input)",    false)]
        [DataRow("System.String",           "System.UInt32",    "value = System.UInt32.Parse(input)",    false)]
        [DataRow("System.String",           "System.UInt64",    "value = System.UInt64.Parse(input)",    false)]
        [DataRow("System.String",           "System.Single",    "value = System.Single.Parse(input)",    false)]
        [DataRow("System.String",           "System.Double",    "value = System.Double.Parse(input)",    false)]
        [DataRow("System.String",           "System.Decimal",   "value = System.Decimal.Parse(input)",   false)]
        [DataRow("System.String",           "System.Guid",      "value = System.Guid.Parse(input)",      false)]
        [DataRow("System.String",           "System.Guid",      "value = System.Guid.ParseExact(input, \"\")",      false)]
        [DataRow("System.String",           "System.DateTime",  "value = System.DateTime.Parse(input)",  false)]
        [DataRow("System.String",           "System.DateTime",  "value = System.DateTime.ParseExact(input, (System.String)null, null, 0)",  false)]
        [DataRow("System.String",           "System.TimeSpan",  "value = System.TimeSpan.Parse(input)",  false)]
        [DataRow("System.String",           "System.TimeSpan",  "value = System.TimeSpan.ParseExact(input, (System.String)null, null, 0)",  false)]
        [DataRow("System.String",           "System.DateTimeOffset", "value = System.DateTimeOffset.Parse(input)", false)]
        [DataRow("System.String",           "System.DateTimeOffset", "value = System.DateTimeOffset.ParseExact(input, (System.String)null, null, 0)", false)]
        [DataRow("System.String",           "System.Byte",      "System.Byte.TryParse(input, out value)",      false)]
        [DataRow("System.String",           "System.SByte",     "System.SByte.TryParse(input, out value)",     false)]
        [DataRow("System.String",           "System.Char",      "System.Char.TryParse(input, out value)",      false)]
        [DataRow("System.String",           "System.Boolean",   "System.Boolean.TryParse(input, out value)",   false)]
        [DataRow("System.String",           "System.Int16",     "System.Int16.TryParse(input, out value)",     false)]
        [DataRow("System.String",           "System.Int32",     "System.Int32.TryParse(input, out value)",     false)]
        [DataRow("System.String",           "System.Int64",     "System.Int64.TryParse(input, out value)",     false)]
        [DataRow("System.String",           "System.UInt16",    "System.UInt16.TryParse(input, out value)",    false)]
        [DataRow("System.String",           "System.UInt32",    "System.UInt32.TryParse(input, out value)",    false)]
        [DataRow("System.String",           "System.UInt64",    "System.UInt64.TryParse(input, out value)",    false)]
        [DataRow("System.String",           "System.Single",    "System.Single.TryParse(input, out value)",    false)]
        [DataRow("System.String",           "System.Double",    "System.Double.TryParse(input, out value)",    false)]
        [DataRow("System.String",           "System.Decimal",   "System.Decimal.TryParse(input, out value)",   false)]
        [DataRow("System.String",           "System.Guid",      "System.Guid.TryParse(input, out value)",      false)]
        [DataRow("System.String",           "System.Guid",      "System.Guid.TryParseExact(input, \"\", out value)",      false)]
        [DataRow("System.String",           "System.DateTime",  "System.DateTime.TryParse(input, out value)",  false)]
        [DataRow("System.String",           "System.DateTime",  "System.DateTime.TryParseExact(input, (System.String)null, null, 0, out value)",  false)]
        [DataRow("System.String",           "System.TimeSpan",  "System.TimeSpan.TryParse(input, out value)",  false)]
        [DataRow("System.String",           "System.TimeSpan",  "System.TimeSpan.TryParseExact(input, (System.String)null, null, 0, out value)",  false)]
        [DataRow("System.String",           "System.DateTimeOffset", "System.DateTimeOffset.TryParse(input, out value)", false)]
        [DataRow("System.String",           "System.DateTimeOffset", "System.DateTimeOffset.TryParseExact(input, (System.String)null, null, 0, out value)", false)]

        [DataRow("System.String",           "System.String", "value = System.Convert.ToString(input)", true)]
        [DataRow("System.Byte",             "System.String", "value = System.Convert.ToString(input)", false)]
        [DataRow("System.SByte",            "System.String", "value = System.Convert.ToString(input)", false)]
        [DataRow("System.Char",             "System.String", "value = System.Convert.ToString(input)", false)]
        [DataRow("System.Boolean",          "System.String", "value = System.Convert.ToString(input)", false)]
        [DataRow("System.Int16",            "System.String", "value = System.Convert.ToString(input)", false)]
        [DataRow("System.Int32",            "System.String", "value = System.Convert.ToString(input)", false)]
        [DataRow("System.Int64",            "System.String", "value = System.Convert.ToString(input)", false)]
        [DataRow("System.UInt16",           "System.String", "value = System.Convert.ToString(input)", false)]
        [DataRow("System.UInt32",           "System.String", "value = System.Convert.ToString(input)", false)]
        [DataRow("System.UInt64",           "System.String", "value = System.Convert.ToString(input)", false)]
        [DataRow("System.Single",           "System.String", "value = System.Convert.ToString(input)", false)]
        [DataRow("System.Double",           "System.String", "value = System.Convert.ToString(input)", false)]
        [DataRow("System.Decimal",          "System.String", "value = System.Convert.ToString(input)", false)]
        [DataRow("System.DateTime",         "System.String", "value = System.Convert.ToString(input)", false)]

        [DataRow("System.String", "System.Byte",        "value = System.Convert.ToByte(input)",     false)]
        [DataRow("System.String", "System.SByte",       "value = System.Convert.ToSByte(input)",    false)]
        [DataRow("System.String", "System.Char",        "value = System.Convert.ToChar(input)",     false)]
        [DataRow("System.String", "System.Boolean",     "value = System.Convert.ToBoolean(input)",  false)]
        [DataRow("System.String", "System.Int16",       "value = System.Convert.ToInt16(input)",    false)]
        [DataRow("System.String", "System.Int32",       "value = System.Convert.ToInt32(input)",    false)]
        [DataRow("System.String", "System.Int64",       "value = System.Convert.ToInt64(input)",    false)]
        [DataRow("System.String", "System.UInt16",      "value = System.Convert.ToUInt16(input)",   false)]
        [DataRow("System.String", "System.UInt32",      "value = System.Convert.ToUInt32(input)",   false)]
        [DataRow("System.String", "System.UInt64",      "value = System.Convert.ToUInt64(input)",   false)]
        [DataRow("System.String", "System.Single",      "value = System.Convert.ToSingle(input)",   false)]
        [DataRow("System.String", "System.Double",      "value = System.Convert.ToDouble(input)",   false)]
        [DataRow("System.String", "System.Decimal",     "value = System.Convert.ToDecimal(input)",  false)]
        [DataRow("System.String", "System.DateTime",    "value = System.Convert.ToDateTime(input)", false)]
        public async Task ToStringSanitizer(string intputType, string sinkType, string sink, bool warn)
        {
            var cSharpTest = $@"
namespace sample
{{
    public enum MyEnum
    {{
        Value = 1
    }}

    public class Sink
    {{
        public static void Redirect({sinkType} x)
        {{
        }}
    }}

    public class My
    {{
        public void Run({intputType} input)
        {{
            {sinkType} value = default({sinkType});
            {sink};
            Sink.Redirect(value);
        }}
    }}
}}
";

            var visualBasicTest = $@"
Namespace sample
    Public Enum MyEnum
        Value = 1
    End Enum

    Public Class Sink
        Public Shared Sub Redirect(ByVal x As {sinkType})
        End Sub
    End Class

    Public Class My
        Public Sub Run(ByVal input As {intputType})
            Dim value As {sinkType}
            {sink.CSharpReplaceToVBasic()}
            Sink.Redirect(value)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  sample.My:
    Method:
      Name: Run

Sinks:
  - Type: sample.Sink
    TaintTypes:
      - SCS0027
    Methods:
    - Name: Redirect
      Arguments:
        - x
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            if (warn)
            {
                var expected = new DiagnosticResult
                {
                    Id       = "SCS0027",
                    Severity = DiagnosticSeverity.Warning,
                };

                await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            }
        }

        [TestMethod]
        public async Task ToStringSanitizer2()
        {
            var cSharpTest = @"
namespace sample
{
    public enum MyEnum
    {
        Value = 1
    }

    public class Sink
    {
        public static void Redirect(MyEnum x)
        {
        }
    }

    public class My
    {
        public void Run(string input)
        {
            Sink.Redirect((MyEnum)System.Enum.Parse(typeof(MyEnum), input));
        }
    }
}
";

            var visualBasicTest = @"
Namespace sample
    Public Enum MyEnum
        Value = 1
    End Enum

    Public Class Sink
        Public Shared Sub Redirect(ByVal x As MyEnum)
        End Sub
    End Class

    Public Class My
        Public Sub Run(ByVal input As String)
            Sink.Redirect(CType(System.[Enum].Parse(GetType(MyEnum), input), MyEnum))
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  sample.My:
    Method:
      Name: Run

Sinks:
  - Type: sample.Sink
    TaintTypes:
      - SCS0027
    Methods:
    - Name: Redirect
      Arguments:
        - x
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task ToStringSanitizer3()
        {
            var cSharpTest = @"
namespace sample
{
    public enum MyEnum
    {
        Value = 1
    }

    public class Sink
    {
        public static void Redirect(MyEnum x)
        {
        }
    }

    public class My
    {
        public void Run(string input)
        {
            System.Enum.TryParse<MyEnum>(input, false, out MyEnum value);
            Sink.Redirect(value);
        }
    }
}
";

            var visualBasicTest = @"
Namespace sample
    Public Enum MyEnum
        Value = 1
    End Enum

    Public Class Sink
        Public Shared Sub Redirect(ByVal x As MyEnum)
        End Sub
    End Class

    Public Class My
        Public Sub Run(ByVal input As String)
            Dim value As MyEnum = Nothing
            System.[Enum].TryParse(Of MyEnum)(input, False, value)
            Sink.Redirect(value)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  sample.My:
    Method:
      Name: Run

Sinks:
  - Type: sample.Sink
    TaintTypes:
      - SCS0027
    Methods:
    - Name: Redirect
      Arguments:
        - x
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [DataTestMethod]
        [DataRow("using System; using System.Web.Mvc;",           "!!Url.IsLocalUrl(input)",                                   "Redirect(input)",          false)]
        [DataRow("using System; using System.Web.Mvc;",           "Url.IsLocalUrl(input)",                                     "Redirect(input)",          false)]
        // todo: roslyn conditional branches
        //[DataRow("using System; using System.Web.Mvc;",           "!Url.IsLocalUrl(input)",                                    "Redirect(input)",          true)]
        [DataRow("using System; using System.Web.Mvc;",           "Url.IsLocalUrl(inputModel.x)",                              "Redirect(inputModel.x)",   false)]
        [DataRow("using System; using Microsoft.AspNetCore.Mvc;", "Url.IsLocalUrl(input)",                                     "Redirect(input)",          false)]
        [DataRow("using System; using System.Web.Mvc;",           "Uri.TryCreate(input, UriKind.Relative, out uri)",           "Redirect(uri.ToString())", false)]
        [DataRow("using System; using System.Web.Mvc;",           "Uri.TryCreate(input, UriKind.RelativeOrAbsolute, out uri)", "Redirect(uri.ToString())", true)]
        [DataRow("using System; using System.Web.Mvc;",           "Uri.TryCreate(inputUri, input, out uri)",           "Redirect(uri.ToString())", true)]
        [DataRow("using System; using System.Web.Mvc;",           "Uri.TryCreate(inputUri, inputUri, out uri)",        "Redirect(uri.ToString())", true)]
        public async Task Validator(string usingNamespace, string validate, string sink, bool warn)
        {
            var cSharpTest = $@"
{usingNamespace}

namespace sample
{{
    public class Model
    {{
        public string x {{ get; set; }}
    }}

    public class MyController : Controller
    {{
        public object Run(string input, Uri inputUri, Model inputModel)
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
    Public Class Model
        Public Property x As String
    End Class

    Public Class MyController
        Inherits Controller

        Public Function Run(ByVal input As String, ByVal inputUri as Uri, ByVal inputModel As Model) As Object
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

        [DataTestMethod]
        //todo: roslyn conditional branches
        //[DataRow("using System; using System.Web.Mvc;", "!System.String.IsNullOrWhiteSpace(input) && !Url.IsLocalUrl(input)", "Redirect(input)", false)]
        [DataRow("using System; using System.Web.Mvc;", "!Url.IsLocalUrl(input)", "Redirect(input)", false)]
        public async Task Validator1(string usingNamespace, string validate, string sink, bool warn)
        {
            var cSharpTest = $@"
{usingNamespace}

namespace sample
{{
    public class Model
    {{
        public string x {{ get; set; }}
    }}

    public class MyController : Controller
    {{
        public object Run(string input, Uri inputUri, Model inputModel)
        {{
#pragma warning disable CS0219
            Uri uri = null;
#pragma warning restore CS0219
            if ({validate})
                input = """";

            return {sink};
        }}
    }}
}}
";

            var vb = validate.CSharpReplaceToVBasic().Replace("!", "Not ");

            var visualBasicTest = $@"
{usingNamespace.CSharpReplaceToVBasic()}

Namespace sample
    Public Class Model
        Public Property x As String
    End Class

    Public Class MyController
        Inherits Controller

        Public Function Run(ByVal input As String, ByVal inputUri as Uri, ByVal inputModel As Model) As Object
#Disable Warning BC42024
            Dim uri As Uri = Nothing
#Enable Warning BC42024
            If {vb} Then
                input = Nothing
            End If

            Return {sink}
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
        [Ignore("now it is sanitizing input, but really should calculate possible branches")]
        public async Task Validator2()
        {
            var cSharpTest = @"
using System.Web.Mvc;

namespace sample
{
    public class MyController : Controller
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
        [Ignore("now it is sanitizing input, but really should calculate possible branches")]
        public async Task Validator3()
        {
            var cSharpTest = @"
using System.Web.Mvc;

namespace sample
{
    public class MyController : Controller
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
        [DataRow(@"var s = new SqlCommand(input);",                                             "SCS0002")]

        [DataRow(@"Redirect(input);",                                                           "SCS0027")]
        [DataRow(@"var r = Url.RouteUrl(input);
                var a = new SqlCommand(r);
                Redirect(r);",                                                                  "SCS0002")]
        [DataRow(@"var r = Url.RouteUrl(input);
                var r2 = r;
                var a = new SqlCommand(r2);
                Redirect(r2);",                                                                 "SCS0002")]

        [DataRow(@"var d = new DirectoryEntry();
                   d.Path = input;",                                                            "SCS0026")]
        [DataRow(@"var d = new DirectoryEntry(input);",                                         "SCS0026")]
        [DataRow(@"var d = new DirectoryEntry();
                   var enc = Encoder.LdapFilterEncode(input);
                   d.Path = enc;",                                                              "SCS0026")]
        [DataRow(@"var d = new DirectoryEntry(Encoder.LdapFilterEncode(input));",               "SCS0026")]
        [DataRow(@"var d = new DirectoryEntry();
                   var enc = Encoder.LdapDistinguishedNameEncode(input);
                   d.Path = enc;
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var enc = Encoder.LdapDistinguishedNameEncode(input);
                   var d = new DirectoryEntry(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]

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
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var enc = Encoder.LdapFilterEncode(input);
                   var d = new DirectorySearcher(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]

        [DataRow(@"Response.Write(input);",                                                     "SCS0029")]
        [DataRow(@"Response.Write(Encoder.LdapFilterEncode(input));",                           "SCS0029")]
        [DataRow(@"var enc = Encoder.HtmlAttributeEncode(input);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var enc = Encoder.HtmlEncode(input);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var enc = Encoder.HtmlFormUrlEncode(input);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var enc = Encoder.UrlEncode(input);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var enc = Encoder.UrlPathEncode(input);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var enc = Encoder.XmlAttributeEncode(input);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var enc = Encoder.XmlEncode(input);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var enc = _HttpServerUtility.HtmlEncode(input);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var enc = _HttpServerUtility.UrlEncode(input);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var enc = System.Text.Encodings.Web.HtmlEncoder.Default.Encode(input);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var enc = HttpUtility.HtmlEncode(input);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var o = (object)input;
                   var enc = HttpUtility.HtmlEncode(o);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var w = new StringWriter();
                   HttpUtility.HtmlEncode(input, w);
                   var enc = w.ToString();
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var enc = System.Web.Security.AntiXss.AntiXssEncoder.HtmlEncode(input, true);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var enc = System.Web.Security.AntiXss.AntiXssEncoder.HtmlEncode(input, false);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var enc = System.Web.Security.AntiXss.AntiXssEncoder.HtmlFormUrlEncode(input);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var enc = System.Web.Security.AntiXss.AntiXssEncoder.UrlEncode(input);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var enc = System.Web.Security.AntiXss.AntiXssEncoder.XmlAttributeEncode(input);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var enc = System.Web.Security.AntiXss.AntiXssEncoder.XmlEncode(input);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var w = new StringWriter();
                   System.Text.Encodings.Web.HtmlEncoder.Default.Encode(w, input);
                   var enc = w.ToString();
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var w = new StringWriter();
                   System.Text.Encodings.Web.HtmlEncoder.Default.Encode(w, input, 0, 10);
                   var enc = w.ToString();
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var w = new StringWriter();
                   System.Text.Encodings.Web.HtmlEncoder.Default.Encode(w, inputChars, 0, 10);
                   var enc = w.ToString();
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var w = new StringWriter();
                   _HttpServerUtility.HtmlEncode(input, w);
                   var enc = w.ToString();
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]

        // sanitizer bit merging
        // sanitized with safe
        [DataRow(@"var r = Url.RouteUrl(input) + Path.GetRandomFileName();
                   var a = new SqlCommand(r);
                   Redirect(r);",                                                               "SCS0002")]
        [DataRow(@"var r = Path.GetRandomFileName() + Url.RouteUrl(input);
                   var a = new SqlCommand(r);
                   Redirect(r);",                                                               "SCS0002")]

        // sanitized with const
        [DataRow(@"var r = Url.RouteUrl(input) + ""a"";
                   var a = new SqlCommand(r);
                   Redirect(r);",                                                               "SCS0002")]
        [DataRow(@"var r = ""a"" + Url.RouteUrl(input);
                   var a = new SqlCommand(r);
                   Redirect(r);",                                                               "SCS0002")]
        [DataRow(@"var enc = Encoder.HtmlEncode(input) + Encoder.HtmlEncode(""a"");
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var enc = Encoder.HtmlEncode(""a"") + Encoder.HtmlEncode(input);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var enc = Encoder.HtmlEncode(""a"") + Encoder.HtmlEncode(""a"");
                   Response.Write(enc);
                   var a = new SqlCommand(enc);
                   var b = new SqlCommand(input);",                                             "SCS0002")]

        // sanitized with sanitized same type and different
        [DataRow(@"var enc = Encoder.HtmlEncode(input) + Encoder.HtmlEncode(input);
                   Response.Write(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var enc = Encoder.HtmlEncode(input) + Encoder.HtmlEncode(Encoder.LdapFilterEncode(input));
                   Response.Write(enc);
                   var d = new DirectorySearcher(enc);",                                        "SCS0031")]
        [DataRow(@"var enc = Encoder.HtmlEncode(Encoder.LdapFilterEncode(input)) + Encoder.HtmlEncode(input);
                   Response.Write(enc);
                   var d = new DirectorySearcher(enc);",                                        "SCS0031")]
        [DataRow(@"var enc = Encoder.HtmlEncode(Encoder.LdapFilterEncode(input)) + Encoder.HtmlEncode(Encoder.LdapFilterEncode(input));
                   Response.Write(enc);
                   var d = new DirectorySearcher(enc);
                   var a = new SqlCommand(enc);",                                               "SCS0002")]
        [DataRow(@"var enc = Encoder.HtmlEncode(input) + Encoder.LdapFilterEncode(input);
                   Response.Write(enc);",                                                       "SCS0029")]
        [DataRow(@"var enc = Encoder.LdapFilterEncode(input) + Encoder.HtmlEncode(input);
                   Response.Write(enc);",                                                       "SCS0029")]
        public async Task Sanitizer(string payload, string warningId, int count = 1)
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
    public class MyController : Controller
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

            await VerifyCSharpDiagnostic(cSharpTest, Enumerable.Repeat(expected, count).ToArray()).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Enumerable.Repeat(expected, count).ToArray()).ConfigureAwait(false);
        }
    }
}
