using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Config;
using SecurityCodeScan.Test.Helpers;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test.Taint
{
    [TestClass]
    public class XPathInjectionAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string _)
        {
            return new[] { new XPathTaintAnalyzer() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(System.Xml.Linq.XElement).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [DataRow("doc.SelectNodes(input)",                           true)]
        [DataRow("doc.SelectNodes(\"constant\")",                   false)]
        [DataRow("doc.SelectNodes(input, null)",                     true)]
        [DataRow("doc.SelectNodes(\"constant\", null)",             false)]
        [DataRow("doc.SelectSingleNode(input)",                      true)]
        [DataRow("doc.SelectSingleNode(\"constant\")",              false)]
        [DataRow("doc.SelectSingleNode(input, null)",                true)]
        [DataRow("doc.SelectSingleNode(\"constant\", null)",        false)]
        [DataRow("nav.SelectSingleNode(input)",                      true)]
        [DataRow("nav.SelectSingleNode(\"constant\")",              false)]
        [DataRow("nav.SelectSingleNode(input, null)",                true)]
        [DataRow("nav.SelectSingleNode(\"constant\", null)",        false)]
        [DataRow("nav.SelectSingleNode(nav.Compile(input))",         true)]
        [DataRow("nav.SelectSingleNode(nav.Compile(\"constant\"))", false)]
        [DataRow("nav.Select(input)",                                true)]
        [DataRow("nav.Select(\"constant\")",                        false)]
        [DataRow("nav.Select(input, null)",                          true)]
        [DataRow("nav.Select(\"constant\", null)",                  false)]
        [DataRow("nav.Select(nav.Compile(input))",                   true)]
        [DataRow("nav.Select(nav.Compile(\"constant\"))",           false)]
        [DataRow("nav.Compile(input)",                               true)]
        [DataRow("nav.Compile(\"constant\")",                       false)]
        [DataRow("nav.Evaluate(input)",                              true)]
        [DataRow("nav.Evaluate(\"constant\")",                      false)]
        [DataRow("nav.Evaluate(input, null)",                        true)]
        [DataRow("nav.Evaluate(\"constant\", null)",                false)]
        [DataRow("nav.Evaluate(nav.Compile(input))",                 true)]
        [DataRow("nav.Evaluate(nav.Compile(\"constant\"))",         false)]
        [DataRow("nav.Evaluate(nav.Compile(input), null)",           true)]
        [DataRow("nav.Evaluate(nav.Compile(\"constant\"), null)",   false)]
        [DataRow("XPathExpression.Compile(input)",                   true)]
        [DataRow("XPathExpression.Compile(\"constant\")",           false)]
        [DataRow("XPathExpression.Compile(input, null)",             true)]
        [DataRow("XPathExpression.Compile(\"constant\", null)",     false)]
        [DataRow("element.XPathSelectElement(input)",                true)]
        [DataRow("element.XPathSelectElement(\"constant\")",        false)]
        [DataRow("element.XPathSelectElement(input, null)",          true)]
        [DataRow("element.XPathSelectElement(\"constant\", null)",  false)]
        [DataRow("element.XPathSelectElements(input)",               true)]
        [DataRow("element.XPathSelectElements(\"constant\")",       false)]
        [DataRow("element.XPathSelectElements(input, null)",         true)]
        [DataRow("element.XPathSelectElements(\"constant\", null)", false)]
        [DataRow("element.XPathEvaluate(input)",                     true)]
        [DataRow("element.XPathEvaluate(\"constant\")",             false)]
        [DataRow("element.XPathEvaluate(input, null)",               true)]
        [DataRow("element.XPathEvaluate(\"constant\", null)",       false)]
        [DataRow("System.Xml.XPath.Extensions.XPathSelectElement(element, input)",               true)]
        [DataRow("System.Xml.XPath.Extensions.XPathSelectElement(element, \"constant\")",        false)]
        [DataRow("System.Xml.XPath.Extensions.XPathSelectElement(element, input, null)",         true)]
        [DataRow("System.Xml.XPath.Extensions.XPathSelectElement(element, \"constant\", null)",  false)]
        [DataRow("System.Xml.XPath.Extensions.XPathSelectElements(element, input)",              true)]
        [DataRow("System.Xml.XPath.Extensions.XPathSelectElements(element, \"constant\")",       false)]
        [DataRow("System.Xml.XPath.Extensions.XPathSelectElements(element, input, null)",        true)]
        [DataRow("System.Xml.XPath.Extensions.XPathSelectElements(element, \"constant\", null)", false)]
        [DataRow("System.Xml.XPath.Extensions.XPathEvaluate(element, input)",                    true)]
        [DataRow("System.Xml.XPath.Extensions.XPathEvaluate(element, \"constant\")",             false)]
        [DataRow("System.Xml.XPath.Extensions.XPathEvaluate(element, input, null)",              true)]
        [DataRow("System.Xml.XPath.Extensions.XPathEvaluate(element, \"constant\", null)",       false)]
        [DataTestMethod]
        public async Task XPathInjection(string sink, bool warn)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System.Xml;
    using System.Xml.XPath;
    using System.Xml.Linq;
#pragma warning restore 8019

namespace sample
{{
    public class MyFoo
    {{
        public void Run(XmlDocument doc, XPathNavigator nav, XNode element, string input)
        {{
            {sink};
        }}
    }}
}}
";
            sink = sink.CSharpReplaceToVBasic();
            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System.Xml
    Imports System.Xml.XPath
    Imports System.Xml.Linq
#Enable Warning BC50001

Namespace sample
    Public Class MyFoo
        Public Sub Run(doc As XmlDocument, nav As XPathNavigator, element As XNode, input As System.String)
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

            var testConfig = @"
TaintEntryPoints:
  sample.MyFoo:
    Method:
      Name: Run
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);

            if (warn)
            {
                await VerifyCSharpDiagnostic(cSharpTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, expected, optionsWithProjectConfig).ConfigureAwait(false);
            }
            else
            {
                await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            }
        }
    }
}
