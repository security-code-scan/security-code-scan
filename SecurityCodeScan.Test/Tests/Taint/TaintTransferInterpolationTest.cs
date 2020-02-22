using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Config;
using SecurityCodeScan.Test.Helpers;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test.Taint
{
    [TestClass]
    public class TaintTransferInterpolationTest : DiagnosticVerifier
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
            MetadataReference.CreateFromFile(typeof(System.Web.HttpResponse).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Web.Mvc.ActionResult).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Http.HttpResponse).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.Controller).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.ControllerBase).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.IUrlHelper).Assembly.Location),
        };

        private DiagnosticResult Expected = new DiagnosticResult
        {
            Id       = "SCS0027",
            Severity = DiagnosticSeverity.Warning,
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [DataRow(@"var t = new Test();
                   t.SetVal(value);
                   Test.Sink(t.ToString());", true)]
        [DataRow(@"var t = new Test();
                   t.SetVal(""const"");
                   Test.Sink(t.ToString());", false)]
        [DataRow(@"var t = new Test();
                   t.SetVal(value);
                   Test.Sink(t.GetVal());", true)]
        [DataRow(@"var t = new Test();
                   t.SetVal(""const"");
                   Test.Sink(t.GetVal());", false)]
        [DataRow(@"var t = new Test();
                   t.SetVal(value);
                   Test.Sink(string.Format(""{0}"", t));", true)]
        [DataRow(@"var t = new Test();
                   t.SetVal(""const"");
                   Test.Sink(string.Format(""{0}"", t));", false)]
        [DataTestMethod]
        public async Task OpenRedirectStringObject(string payload, bool warn)
        {
            var testConfig = @"
TaintEntryPoints:
  AAA:
    ClassName: OpenRedirect

Behavior:
  MyKey:
    ClassName: Test
    Name: Sink
    Method:
      InjectableArguments: [SCS0027: 0]
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            var cSharpTest = $@"
class Test
{{
    private string _val;

    public void SetVal(string val)
    {{
        _val = val;
    }}

    public string GetVal()
    {{
        return _val;
    }}

    public override string ToString()
    {{
        return _val;
    }}

    public static void Sink(string val)
    {{
    }}
}}

class OpenRedirect
{{
    public void Run(string value)
    {{
        {payload}
    }}
}}
";

            var vbTest = $@"
Class Test
    Private _val As String

    Public Sub SetVal(ByVal val As String)
        _val = val
    End Sub

    Public Function GetVal() As String
        Return _val
    End Function

    Public Overrides Function ToString() As String
        Return _val
    End Function

    Public Shared Sub Sink(val as String)
    End Sub
End Class

Class OpenRedirect
    Public Sub Run(value As String)
        {payload.CSharpReplaceToVBasic()}
    End Sub
End Class
";

            if (warn)
            {
                await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(vbTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(vbTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            }
        }

        [TestCategory("Safe")]
        [DataRow("Test.Sink(\"\"+value)", false, false, new[] { "System.Byte", "System.SByte", "System.Char", "System.Boolean",
                                                                 "System.Int16", "System.UInt16", "System.Int32", "System.UInt32",
                                                                 "System.Int64", "System.UInt64", "System.Single", "System.Double",
                                                                 "System.Decimal", "System.DateTime" })]

        [DataRow(@"var t = new Test();
                   t.Prop1 = value;
                   Test.Sink(""""+t.Prop1)", false, false, new[] { "System.Byte", "System.SByte", "System.Char", "System.Boolean",
                                                                   "System.Int16", "System.UInt16", "System.Int32", "System.UInt32",
                                                                   "System.Int64", "System.UInt64", "System.Single", "System.Double",
                                                                   "System.Decimal", "System.DateTime" })]
        [DataTestMethod]
        public async Task OpenRedirectImplicitString(string sink, bool auditMode, bool warn, string[] types)
        {
            var testConfig = $@"
AuditMode: {auditMode}

TaintEntryPoints:
  AAA:
    ClassName: OpenRedirect

Behavior:
  MyKey:
    ClassName: Test
    Name: Sink
    Method:
      InjectableArguments: [SCS0027: 0]
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            foreach (var type in types)
            {
                var cSharpTest = $@"
class Test
{{
    public {type} Prop1 {{ get; set; }}

    public static void Sink(string val)
    {{
    }}
}}

class OpenRedirect
{{
    public void Run({type} value)
    {{
        {sink};
    }}
}}
";

                var vbTest1 = $@"
Class Test
    Public Property Prop1 As {type}

    Public Shared Sub Sink(val as String)
    End Sub
End Class

Class OpenRedirect
    Public Sub Run(value As {type})
        {sink.CSharpReplaceToVBasic().Replace("+", "&")}
    End Sub
End Class
";

                var vbTest2 = $@"
Class Test
    Public Property Prop1 As {type}

    Public Shared Sub Sink(val as String)
    End Sub
End Class

Class OpenRedirect
    Public Sub Run(value As {type})
        {sink.CSharpReplaceToVBasic()}
    End Sub
End Class
";

                if (warn)
                {
                    await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
                    await VerifyVisualBasicDiagnostic(vbTest1, Expected, optionsWithProjectConfig).ConfigureAwait(false);
                    await VerifyVisualBasicDiagnostic(vbTest2, Expected, optionsWithProjectConfig).ConfigureAwait(false);
                }
                else
                {
                    await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
                    await VerifyVisualBasicDiagnostic(vbTest1, null, optionsWithProjectConfig).ConfigureAwait(false);
                    await VerifyVisualBasicDiagnostic(vbTest2, null, optionsWithProjectConfig).ConfigureAwait(false);
                }
            }
        }

        [TestCategory("Detect")]
        [DataRow("Test.Sink(\"\"+value)", new object[] { "string", "object" })]
        [DataTestMethod]
        public async Task OpenRedirectStringConcat(string sink, params string[] types)
        {
            var testConfig = @"
TaintEntryPoints:
  AAA:
    ClassName: OpenRedirect

Behavior:
  MyKey:
    ClassName: Test
    Name: Sink
    Method:
      InjectableArguments: [SCS0027: 0]
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            foreach (var type in types)
            {
                var cSharpTest = $@"
class Test
{{
    public static void Sink(string val)
    {{
    }}
}}

class OpenRedirect
{{
    public void Run({type} value)
    {{
        {sink};
    }}
}}
";

                var vbTest1 = $@"
Class Test
    Public Shared Sub Sink(val as String)
    End Sub
End Class

Class OpenRedirect
    Public Sub Run(value As {type})
        {sink.Replace("+", "&")}
    End Sub
End Class
";

                var vbTest2 = $@"
Class Test
    Public Shared Sub Sink(val as String)
    End Sub
End Class

Class OpenRedirect
    Public Sub Run(value As {type})
        {sink}
    End Sub
End Class
";

                await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(vbTest1, Expected, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(vbTest2, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            }
        }

        [TestCategory("Safe")]
        [DataRow("Test.Sink($\"{value}\")", false, false, new[] { "System.Byte", "System.SByte", "System.Char", "System.Boolean",
                                                                  "System.Int16", "System.UInt16", "System.Int32", "System.UInt32",
                                                                  "System.Int64", "System.UInt64", "System.Single", "System.Double",
                                                                  "System.Decimal", "System.DateTime" })]
        [DataRow("Test.Sink($\"{value:#.0}\")", false, false, new[] { "System.Single" })] // ensure we're not broken by composite formatting
        [DataRow("Test.Sink($\"{value:yyyy'-'MM'-'dd}\")", false, false, new[] { "System.DateTime" })]
        [DataRow("Test.Sink($\"{value:O}\")", false, false, new[] { "System.DateTimeOffset" })]
        [DataRow("Test.Sink($\"{value:G}\")", false, false, new[] { "System.Guid" })]
        [DataTestMethod]
        public async Task OpenRedirectInterpolatedStringSafe(string sink, bool auditMode, bool warn, string[] types)
        {
            var testConfig = $@"
AuditMode: {auditMode}

TaintEntryPoints:
  AAA:
    ClassName: OpenRedirect

Behavior:
  MyKey:
    ClassName: Test
    Name: Sink
    Method:
      InjectableArguments: [SCS0027: 0]
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            foreach (var type in types)
            {
                var cSharpTest = $@"
class Test
{{
    public static void Sink(string val)
    {{
    }}
}}

class OpenRedirect
{{
    public void Run({type} value)
    {{
        {sink};
    }}
}}
";


                var vbTest1 = $@"
Class Test
    Public Shared Sub Sink(val as String)
    End Sub
End Class

Class OpenRedirect
    Public Sub Run(value As {type})
        {sink.Replace("+", "&")}
    End Sub
End Class
";

                var vbTest2 = $@"
Class Test
    Public Shared Sub Sink(val as String)
    End Sub
End Class

Class OpenRedirect
    Public Sub Run(value As {type})
        {sink}
    End Sub
End Class
";

                if (warn)
                {
                    await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
                    await VerifyVisualBasicDiagnostic(vbTest1, Expected, optionsWithProjectConfig).ConfigureAwait(false);
                    await VerifyVisualBasicDiagnostic(vbTest2, Expected, optionsWithProjectConfig).ConfigureAwait(false);
                }
                else
                {
                    await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
                    await VerifyVisualBasicDiagnostic(vbTest1, null, optionsWithProjectConfig).ConfigureAwait(false);
                    await VerifyVisualBasicDiagnostic(vbTest2, null, optionsWithProjectConfig).ConfigureAwait(false);
                }
            }
        }

        [TestCategory("Detect")]
        [DataRow("Test.Sink($\"{value}\")", new object[] { "string", "object" })]
        // we're still tainted if we use a format string
        [DataRow("Test.Sink($\"{value:G}\")", new object[] { "string", "object" })]
        // {flag} is safe, ensure we're still tainted
        [DataRow("Test.Sink($\"{flag}{value}\")", new object[] { "string", "object" })]
        // concat + interp is still tainted
        [DataRow("Test.Sink(flag + $\"{value}\")", new object[] { "string", "object" })]
        [DataTestMethod]
        public async Task OpenRedirectInterpolatedStringDetect(string sink, params string[] types)
        {
            var testConfig = @"
TaintEntryPoints:
  AAA:
    ClassName: OpenRedirect

Behavior:
  MyKey:
    ClassName: Test
    Name: Sink
    Method:
      InjectableArguments: [SCS0027: 0]
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            foreach (var type in types)
            {
                var cSharpTest = $@"
class Test
{{
    public static void Sink(string val)
    {{
    }}
}}

class OpenRedirect
{{
    public void Run({type} value, bool flag)
    {{
        {sink};
    }}
}}
";

                var vbTest1 = $@"
Class Test
    Public Shared Sub Sink(val as String)
    End Sub
End Class

Class OpenRedirect
    Public Sub Run(value As {type}, flag As System.Boolean)
        {sink.Replace("+", "&")}
    End Sub
End Class
";

                var vbTest2 = $@"
Class Test
    Public Shared Sub Sink(val as String)
    End Sub
End Class

Class OpenRedirect
    Public Sub Run(value As {type}, flag As System.Boolean)
        {sink}
    End Sub
End Class
";

                await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(vbTest1, Expected, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(vbTest2, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            }
        }
    }
}
