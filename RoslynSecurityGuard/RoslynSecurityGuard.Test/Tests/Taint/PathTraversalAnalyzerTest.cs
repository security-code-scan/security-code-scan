using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers.Taint;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TestHelper;

namespace RoslynSecurityGuard.Test.Tests.Taint
{
    [TestClass]
    public class PathTraversalAnalyzerTest : DiagnosticVerifier
    {

        protected override DiagnosticAnalyzer GetCSharpDiagnosticAnalyzers()
        {
            return new TaintAnalyzer();
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
    }
}
