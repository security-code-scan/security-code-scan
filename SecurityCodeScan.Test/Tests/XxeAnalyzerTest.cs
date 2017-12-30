using System.Collections.Generic;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Analyzers.Taint;
using TestHelper;

namespace SecurityCodeScan.Tests
{
    [TestClass]
    public class XxeAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new [] { new XxeAnalyzer() };
        }

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[] { MetadataReference.CreateFromFile(typeof(XmlNode).Assembly.Location) };
        }

        [TestMethod]
        public async Task XxeFalsePositive1()
        {
            var cSharpTest = @"
using System.Xml;

class Xxe
{
    public static void parseUpload(string inputXml)
    {
        XmlReaderSettings settings = new XmlReaderSettings();
        XmlReader reader = XmlReader.Create(inputXml, settings);
    }
}
";
            var visualBasicTest = @"
Imports System.Xml

Class Xxe
	Public Shared Sub parseUpload(inputXml As String)
		Dim settings As New XmlReaderSettings()
		Dim reader As XmlReader = XmlReader.Create(inputXml, settings)
	End Sub
End Class
";
            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [TestMethod]
        public async Task XxeFalsePositive2()
        {
            var cSharpTest = @"
using System.Xml;

class Xxe
{
    public static void parseUpload(string inputXml)
    {
        XmlReaderSettings settings = new XmlReaderSettings();
#pragma warning disable 618
        settings.ProhibitDtd = true;
#pragma warning restore 618
        XmlReader reader = XmlReader.Create(inputXml, settings);
    }
}";
            var visualBasicTest = @"
Imports System.Xml

Class Xxe
	Public Shared Sub parseUpload(inputXml As String)
		Dim settings As New XmlReaderSettings()
#Disable Warning BC40000
		settings.ProhibitDtd = True
#Enable Warning BC40000
		Dim reader As XmlReader = XmlReader.Create(inputXml, settings)
	End Sub
End Class
";
            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }


        [TestMethod]
        public async Task XxeFalsePositive3()
        {
            var cSharpTest = @"
using System.Xml;

class Xxe
{
    public static void parseUpload(string inputXml)
    {
        XmlReaderSettings settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Prohibit;
        XmlReader reader = XmlReader.Create(inputXml, settings);
    }
}
";
            var visualBasicTest = @"
Imports System.Xml

Class Xxe
	Public Shared Sub parseUpload(inputXml As String)
		Dim settings As New XmlReaderSettings()
		settings.DtdProcessing = DtdProcessing.Prohibit
		Dim reader As XmlReader = XmlReader.Create(inputXml, settings)
	End Sub
End Class
";
            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [TestMethod]
        public async Task XxeFalsePositive4()
        {
            var cSharpTest = @"
using System.Xml;

class Xxe
{
    public static void parseUpload(string inputXml)
    {
        XmlReaderSettings settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Ignore;
        XmlReader reader = XmlReader.Create(inputXml, settings);
    }
}
";
            var visualBasicTest = @"
Imports System.Xml

Class Xxe
	Public Shared Sub parseUpload(inputXml As String)
		Dim settings As New XmlReaderSettings()
		settings.DtdProcessing = DtdProcessing.Ignore
		Dim reader As XmlReader = XmlReader.Create(inputXml, settings)
	End Sub
End Class
";
            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [TestMethod]
        public async Task XxeVulnerable1()
        {
            var cSharpTest = @"
using System.Xml;

class Xxe
{
    public static void parseUpload(string inputXml)
    {
        XmlReaderSettings settings = new XmlReaderSettings();
#pragma warning disable 618
        settings.ProhibitDtd = false;
#pragma warning restore 618
        XmlReader reader = XmlReader.Create(inputXml, settings);
    }
}
";
            var visualBasicTest = @"
Imports System.Xml

Class Xxe
	Public Shared Sub parseUpload(inputXml As String)
		Dim settings As New XmlReaderSettings()
#Disable Warning BC40000
		settings.ProhibitDtd = False
#Enable Warning BC40000
		Dim reader As XmlReader = XmlReader.Create(inputXml, settings)
	End Sub
End Class
";
            var expected = new[] {
                new DiagnosticResult {Id = "SCS0007",Severity = DiagnosticSeverity.Warning}};

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        [TestMethod]
        public async Task XxeVulnerable2()
        {
            var cSharpTest = @"
using System.Xml;

class Xxe
{
    public static void parseUpload(string inputXml)
    {
        XmlReaderSettings settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Parse;
        XmlReader reader = XmlReader.Create(inputXml, settings);
    }
}
";
            var visualBasicTest = @"
Imports System.Xml

Class Xxe
	Public Shared Sub parseUpload(inputXml As String)
		Dim settings As New XmlReaderSettings()
		settings.DtdProcessing = DtdProcessing.Parse
		Dim reader As XmlReader = XmlReader.Create(inputXml, settings)
	End Sub
End Class
";
            var expected = new[] {
                new DiagnosticResult {Id = "SCS0007",Severity = DiagnosticSeverity.Warning}};

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }
    }

    [TestClass]
    public class XxeAnalyzerTest2 : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new DiagnosticAnalyzer[] { new XxeAnalyzer(), new TaintAnalyzer() };
        }

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[] { MetadataReference.CreateFromFile(typeof(XmlNode).Assembly.Location) };
        }

        [TestMethod]
        public async Task FalsePositive1()
        {
            var cSharpTest = @"
using System.IO;
using System.Xml;

class PathTraversal
{
    public static void Run(string strText)
    {
        using (var reader = XmlReader.Create(new StringReader(strText)))
        {
            reader.Read();
        }
    }
}
";
            var visualBasicTest = @"
Imports System.IO
Imports System.Xml

Class PathTraversal
	Public Shared Sub Run(strText As String)
		Using reader = XmlReader.Create(New StringReader(strText))
			reader.Read()
		End Using
	End Sub
End Class
";
            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }
    }
}
