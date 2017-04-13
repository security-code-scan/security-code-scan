using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers.Taint;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using System.Xml;
using TestHelper;

namespace RoslynSecurityGuard.Test.Tests.Taint
{
    [TestClass]
    public class PathTraversalAnalyzerTest : DiagnosticVerifier
    {

        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
        {
            return new[] { new TaintAnalyzer() };
        }

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[] { MetadataReference.CreateFromFile(typeof(File).Assembly.Location), MetadataReference.CreateFromFile(typeof(XmlReader).Assembly.Location) };
        }


        [TestMethod]
        public async Task PathTraversalFound1()
        {
            var test = @"
using System.IO;

class PathTraversal
{
    public static void Run(string input)
    {
        File.ReadAllText(input);
    }
}
";
            var expected = new DiagnosticResult
            {
                Id = "SG0018",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(test, expected);
        }

        [TestMethod]
        public async Task PathTraversalFound2()
        {
            var test = @"
using System.IO;

class PathTraversal
{
    public static void Run(string input)
    {
        File.OpenRead(input);
    }
}
";
            var expected = new DiagnosticResult
            {
                Id = "SG0018",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(test, expected);
        }


        [TestMethod]
        public async Task PathTraversalFound3()
        {
            var test = @"
using System.IO;

class PathTraversal
{
    public static void Run(string input)
    {
        File.WriteAllText(input,""ouput.."");
    }
}
";
            var expected = new DiagnosticResult
            {
                Id = "SG0018",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(test, expected);
        }

        [TestMethod]
        public async Task PathTraversalFound4()
        {
            var test = @"
using System.IO;

class PathTraversal
{
    public static void Run(string input)
    {
        new StreamReader(input);
    }
}
";
            var expected = new DiagnosticResult
            {
                Id = "SG0018",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(test, expected);
        }

        [TestMethod]
        public async Task PathTraversalFound5()
        {
            var test = @"
using System.IO;

class PathTraversal
{
    public static void Run(string input)
    {
        new StreamReader(input, System.Text.Encoding.ASCII, false, 0);
    }
}
";
            var expected = new DiagnosticResult
            {
                Id = "SG0018",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(test, expected);
        }

        [TestMethod]
        public async Task PathTraversalFound6()
        {
            var test = @"
using System.Xml;

class PathTraversal
{
    public static void Run(string input)
    {
        XmlReaderSettings settings = new XmlReaderSettings();
        XmlReader reader = XmlReader.Create(input, settings, (XmlParserContext)null);
    }
}
";
            var expected = new DiagnosticResult
            {
                Id = "SG0018",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(test, expected);
        }

        [TestMethod]
        public async Task FalsePositive1()
        {
            var test = @"
using System.IO;

class PathTraversal
{
    public static void Run(string input)
    {
        File.OpenRead(""C:/static/fsociety.dat"");
    }
}
";
            await VerifyCSharpDiagnostic(test);
        }
    }
}
