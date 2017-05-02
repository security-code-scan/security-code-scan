using System.Collections.Generic;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers;
using RoslynSecurityGuard.Analyzers.Taint;
using TestHelper;

namespace RoslynSecurityGuard.Tests
{
    [TestClass]
    public class XxeAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
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
            var code = @"
using System.Xml;

class Xxe
{
    public static void parseUpload(string inputXml)
    {
        XmlReaderSettings settings = new XmlReaderSettings();
        XmlReader reader = XmlReader.Create(inputXml, settings);

    }
}";

            await VerifyCSharpDiagnostic(code);
        }

        [TestMethod]
        public async Task XxeFalsePositive2()
        {
            var code = @"
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

            await VerifyCSharpDiagnostic(code);
        }


        [TestMethod]
        public async Task XxeFalsePositive3()
        {
            var code = @"
using System.Xml;

class Xxe
{
    public static void parseUpload(string inputXml)
    {
        XmlReaderSettings settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Prohibit;
        XmlReader reader = XmlReader.Create(inputXml, settings);

    }
}";

            await VerifyCSharpDiagnostic(code);
        }

        [TestMethod]
        public async Task XxeFalsePositive4()
        {
            var code = @"
using System.Xml;

class Xxe
{
    public static void parseUpload(string inputXml)
    {
        XmlReaderSettings settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Ignore;
        XmlReader reader = XmlReader.Create(inputXml, settings);

    }
}";

            await VerifyCSharpDiagnostic(code);
        }

        [TestMethod]
        public async Task XxeVulnerable1()
        {
            var code = @"
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
}";

            var expected = new[] {
                new DiagnosticResult {Id = "SG0007",Severity = DiagnosticSeverity.Warning}};

            await VerifyCSharpDiagnostic(code, expected);
        }

        [TestMethod]
        public async Task XxeVulnerable2()
        {
            var code = @"
using System.Xml;

class Xxe
{
    public static void parseUpload(string inputXml)
    {
        XmlReaderSettings settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Parse;
        XmlReader reader = XmlReader.Create(inputXml, settings);

    }
}";
            var expected = new[] {
                new DiagnosticResult {Id = "SG0007",Severity = DiagnosticSeverity.Warning}};

            await VerifyCSharpDiagnostic(code, expected);
        }
    }

    [TestClass]
    public class XxeAnalyzerTest2 : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
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
            var test = @"
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
            await VerifyCSharpDiagnostic(test);
        }
    }
}
