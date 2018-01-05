using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Helpers;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test.Taint
{
    [TestClass]
    public class PathTraversalAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new[] { new TaintAnalyzer() };
        }

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[]
            {
                MetadataReference.CreateFromFile(typeof(File).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(XmlReader).Assembly.Location)
            };
        }

        [TestMethod]
        public async Task PathTraversalFound1()
        {
            var cSharpTest = @"
using System.IO;

class PathTraversal
{
    public static void Run(string input)
    {
        File.ReadAllText(input);
    }
}
";

            var visualBasicTest = @"
Imports System.IO

Class PathTraversal
	Public Shared Sub Run(input As String)
		File.ReadAllText(input)
	End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0018",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        [TestMethod]
        public async Task PathTraversalFound2()
        {
            var cSharpTest = @"
using System.IO;

class PathTraversal
{
    public static void Run(string input)
    {
        File.OpenRead(input);
    }
}
";

            var visualBasicTest = @"
Imports System.IO

Class PathTraversal
	Public Shared Sub Run(input As String)
		File.OpenRead(input)
	End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0018",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        [TestMethod]
        public async Task PathTraversalFound3()
        {
            var cSharpTest = @"
using System.IO;

class PathTraversal
{
    public static void Run(string input)
    {
        File.WriteAllText(input,""output.."");
    }
}
";

            var visualBasicTest = @"
Imports System.IO

Class PathTraversal
	Public Shared Sub Run(input As String)
		File.WriteAllText(input,""ouput.."")
	End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0018",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        [TestMethod]
        public async Task PathTraversalFound4()
        {
            var cSharpTest = @"
using System.IO;

class PathTraversal
{
    public static void Run(string input)
    {
        new StreamReader(input);
    }
}
";

            var visualBasicTest1 = @"
Imports System.IO

Class PathTraversal
	Public Shared Sub Run(input As String)
		Dim sr As New StreamReader(input)
	End Sub
End Class
";

            //TODO: Move to VB expression test class. 
            var visualBasicTest2 = @"
Imports System.IO

Class PathTraversal
	Public Shared Sub Run(input As String)
		Using sr As New StreamReader(input)
        End Using
	End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0018",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest1, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest2, expected);
        }

        [TestMethod]
        public async Task PathTraversalFound5()
        {
            var cSharpTest = @"
using System.IO;

class PathTraversal
{
    public static void Run(string input)
    {
        new StreamReader(input, System.Text.Encoding.ASCII, false, 0);
    }
}
";

            var visualBasicTest = @"
Imports System.IO

Class PathTraversal
	Public Shared Sub Run(input As String)
		Dim sr As New StreamReader(input, System.Text.Encoding.ASCII, False, 0)
	End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0018",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        [TestMethod]
        public async Task PathTraversalFound6()
        {
            var cSharpTest = @"
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

            var visualBasicTest = @"
Imports System.Xml

Class PathTraversal
	Public Shared Sub Run(input As String)
        Dim settings As New XmlReaderSettings()
        Dim reader As XMLReader = XMLReader.Create(input, settings, Nothing)
	End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0018",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        [TestMethod]
        public async Task FalsePositive1()
        {
            var cSharpTest = @"
using System.IO;

class PathTraversal
{
    public static void Run(string input)
    {
        File.OpenRead(""C:/static/fsociety.dat"");
    }
}
";

            var visualBasicTest = @"
Imports System.IO

Class PathTraversal
	Public Shared Sub Run(input As String)
		File.OpenRead(""C:/static/fsociety.dat"")
	End Sub
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }
    }
}
