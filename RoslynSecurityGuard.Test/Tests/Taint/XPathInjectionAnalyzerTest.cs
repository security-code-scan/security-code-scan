using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TestHelper;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Xml;
using RoslynSecurityGuard.Analyzers.Taint;

namespace RoslynSecurityGuard.Tests
{
    [TestClass]
    public class XPathInjectionAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new[] { new TaintAnalyzer() };
        }

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[] { MetadataReference.CreateFromFile(typeof(XmlNode).Assembly.Location) };
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
            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);

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
            var expected = new[] {
                new DiagnosticResult {Id = "SG0003",Severity = DiagnosticSeverity.Warning},
                new DiagnosticResult { Id = "SG0003", Severity = DiagnosticSeverity.Warning} };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        //TODO: Make sure MemberAccessExpressionSyntax are covered
        [TestMethod]
        public async Task XPathInjectionVulnerable2()
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
            var expected = new[] {
                new DiagnosticResult {Id = "SG0003",Severity = DiagnosticSeverity.Warning},
                new DiagnosticResult { Id = "SG0003", Severity = DiagnosticSeverity.Warning} };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }
    }
}
