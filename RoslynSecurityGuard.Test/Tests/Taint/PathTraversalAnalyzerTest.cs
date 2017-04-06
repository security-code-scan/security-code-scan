using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers.Taint;
using System.Collections.Generic;
using System.IO;
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
            return new[] { MetadataReference.CreateFromFile(typeof(File).Assembly.Location) };
        }


        [TestMethod]
        public void PathTraversalFound1()
        {
            var test = @"
using System.IO;

class PathTraversal
{
    public static void Run(string input)
    {
        return File.ReadAllText(input);
    }
}
";
            var expected = new DiagnosticResult
            {
                Id = "SG0018",
                Severity = DiagnosticSeverity.Warning,
            };
            VerifyCSharpDiagnostic(test, expected);
        }

        [TestMethod]
        public void PathTraversalFound2()
        {
            var test = @"
using System.IO;

class PathTraversal
{
    public static void Run(string input)
    {
        return File.OpenRead(input);
    }
}
";
            var expected = new DiagnosticResult
            {
                Id = "SG0018",
                Severity = DiagnosticSeverity.Warning,
            };
            VerifyCSharpDiagnostic(test, expected);
        }


        [TestMethod]
        public void PathTraversalFound3()
        {
            var test = @"
using System.IO;

class PathTraversal
{
    public static void Run(string input)
    {
        return File.WriteAllText(input,""ouput.."");
    }
}
";
            var expected = new DiagnosticResult
            {
                Id = "SG0018",
                Severity = DiagnosticSeverity.Warning,
            };
            VerifyCSharpDiagnostic(test, expected);
        }

        [TestMethod]
        public void PathTraversalFound4()
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
            VerifyCSharpDiagnostic(test, expected);
        }

        [TestMethod]
        public void FalsePositive1()
        {
            var test = @"
using System.IO;

class PathTraversal
{
    public static void Run(string input)
    {
        return File.OpenRead(""C:/static/fsociety.dat"");
    }
}
";
            VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public void FalsePositive2()
        {
            var test = @"
using System.IO;

class PathTraversal
{
    public static void Run(string input)
    {
        new StreamReader(input, false, System.Text.Encoding.ASCII, 0);
    }
}
";
            VerifyCSharpDiagnostic(test);
        }
    }
}
