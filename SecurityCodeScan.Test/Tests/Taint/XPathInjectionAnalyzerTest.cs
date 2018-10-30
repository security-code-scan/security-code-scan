using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Helpers;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test.Taint
{
    [TestClass]
    public class XPathInjectionAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            return new DiagnosticAnalyzer[] { new TaintAnalyzerCSharp(), new TaintAnalyzerVisualBasic(), };
        }

        [DataRow("nav.SelectSingleNode(input)", true)]
        [DataRow("nav.SelectSingleNode(\"input\")", false)]
        [DataRow("nav.SelectSingleNode(input, null)", true)]
        [DataRow("nav.SelectSingleNode(\"input\", null)", false)]
        [DataRow("nav.SelectSingleNode(nav.Compile(input))", true)]
        [DataRow("nav.SelectSingleNode(nav.Compile(\"input\"))", false)]
        [DataRow("nav.Select(input)", true)]
        [DataRow("nav.Select(\"input\")", false)]
        [DataRow("nav.Select(input, null)", true)]
        [DataRow("nav.Select(\"input\", null)", false)]
        [DataRow("nav.Select(nav.Compile(input))", true)]
        [DataRow("nav.Select(nav.Compile(\"input\"))", false)]
        [DataRow("nav.Compile(input)", true)]
        [DataRow("nav.Compile(\"input\")", false)]
        [DataRow("nav.Evaluate(input)", true)]
        [DataRow("nav.Evaluate(\"input\")", false)]
        [DataRow("nav.Evaluate(input, null)", true)]
        [DataRow("nav.Evaluate(\"input\", null)", false)]
        [DataRow("nav.Evaluate(nav.Compile(input))", true)]
        [DataRow("nav.Evaluate(nav.Compile(\"input\"))", false)]
        [DataRow("nav.Evaluate(nav.Compile(input), null)", true)]
        [DataRow("nav.Evaluate(nav.Compile(\"input\"), null)", false)]
        [DataTestMethod]
        public async Task XPathInjection(string sink, bool warn)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System.Xml;
    using System.Xml.XPath;
#pragma warning restore 8019

namespace sample
{{
    class MyFoo
    {{
        public static void Run(XPathNavigator nav, string input)
        {{
            {sink};
        }}
    }}
}}
";

            sink = sink.Replace("null", "Nothing").Replace("new ", "New ");

            var visualBasicTest = $@"
#Disable Warning BC50001    
    Imports System.Xml
    Imports System.Xml.XPath
#Enable Warning BC50001

Namespace sample
    Class MyFoo
        Public Shared Sub Run(nav As XPathNavigator, input As System.String)
            {sink}
        End Sub
    End Class
End Namespace
";
            var expected = new DiagnosticResult
            {
                Id = "SCS0003",
                Severity = DiagnosticSeverity.Warning,
            };

            if (warn)
            {
                await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
            }
        }

        //No diagnostics expected to show up
        [TestMethod]
        public async Task XPathInjectionFalsePositive()
        {
            var cSharpTest = @"
using System.Xml;

class XPathInjectionTP
{

    public void vulnerableCases(string input) {
        XmlDocument doc = new XmlDocument();
        doc.Load(""/secret_config.xml"");

        doc.SelectNodes(""/Config/Devices/Device[id='1337']"");
        doc.SelectSingleNode(""/Config/Devices/Device[type='2600']"");
    }
}";

            var visualBasicTest = @"
Imports System.Xml

Class XPathInjectionTP
    Public Sub vulnerableCases(input As String)
        Dim doc As New XmlDocument()
        doc.Load("" / secret_config.xml"")
        doc.SelectNodes(""/Config/Devices/Device[id='1337']"")
        doc.SelectSingleNode(""/Config/Devices/Device[type='2600']"")
    End Sub
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task XPathInjectionVulnerable1()
        {
            var cSharpTest = @"
using System.Xml;

class XPathInjectionTP
{

    public void vulnerableCases(string input) {
        XmlDocument doc = new XmlDocument();
        doc.Load(""/secret_config.xml"");

        doc.SelectNodes(""/Config/Devices/Device[id='"" + input + ""']"");
        doc.SelectSingleNode(""/Config/Devices/Device[type='"" + input + ""']"");
    }
}";

            var visualBasicTest = @"
Imports System.Xml

Class XPathInjectionTP
    Public Sub vulnerableCases(input As String)
        Dim doc As New XmlDocument()
        doc.Load("" / secret_config.xml"")
        doc.SelectNodes(""/Config/Devices/Device[id='"" & input & ""']"")
        doc.SelectSingleNode(""/Config/Devices/Device[type='"" & input & ""']"")
    End Sub
End Class
";

            //Two occurrences
            var expected = new[]
            {
                new DiagnosticResult
                {
                    Id       = "SCS0003",
                    Severity = DiagnosticSeverity.Warning
                },
                new DiagnosticResult
                {
                    Id       = "SCS0003",
                    Severity = DiagnosticSeverity.Warning
                }
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }
    }
}
