using System.Collections.Generic;
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
        public void XxeFalsePositive1()
        {
            var code = @"
using System;
using System.Xml;

class Xxe
{
    public static void parseUpload(string inputXml)
    {
        XmlReaderSettings settings = new XmlReaderSettings();
        XmlReader reader = XmlReader.Create(inputXml, settings);

    }
}";

            VerifyCSharpDiagnostic(code);
        }

        [TestMethod]
        public void XxeFalsePositive2()
        {
            var code = @"
using System;
using System.Xml;

class Xxe
{
    public static void parseUpload(string inputXml)
    {
        XmlReaderSettings settings = new XmlReaderSettings();
        settings.ProhibitDtd = true;
        XmlReader reader = XmlReader.Create(inputXml, settings);

    }
}";

            VerifyCSharpDiagnostic(code);
        }


        [TestMethod]
        public void XxeFalsePositive3()
        {
            var code = @"
using System;
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

            VerifyCSharpDiagnostic(code);
        }

        [TestMethod]
        public void XxeFalsePositive4()
        {
            var code = @"
using System;
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

            VerifyCSharpDiagnostic(code);
        }

        [TestMethod]
        public void XxeVulnerable1()
        {
            var code = @"
using System;
using System.Xml;

class Xxe
{
    public static void parseUpload(string inputXml)
    {
        XmlReaderSettings settings = new XmlReaderSettings();
        settings.ProhibitDtd = false;
        XmlReader reader = XmlReader.Create(inputXml, settings);

    }
}";

            var expected = new[] {
                new DiagnosticResult {Id = "SG0007",Severity = DiagnosticSeverity.Warning}};

            VerifyCSharpDiagnostic(code, expected);
        }

        [TestMethod]
        public void XxeVulnerable2()
        {
            var code = @"
using System;
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

            VerifyCSharpDiagnostic(code, expected);
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
        public void FalsePositive1()
        {
            var test = @"
using System.IO;
using System;
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
            VerifyCSharpDiagnostic(test);
        }
    }
}
