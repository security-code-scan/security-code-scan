using System.Collections.Generic;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Helpers;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test.Xxe
{
    [TestClass]
    public class XxeAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new[] { new XxeAnalyzer() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(XmlNode).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestMethod]
        public async Task XxeXmlReaderSettingsDefault()
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

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [DataRow("ProhibitDtd   = true")]
        [DataRow("DtdProcessing = DtdProcessing.Ignore")]
        [DataRow("DtdProcessing = DtdProcessing.Prohibit")]
        [DataTestMethod]
        public async Task XxeDtdProcessingSafeAssignment(string dtdPolicy)
        {
            var cSharpTest = $@"
using System.Xml;

class Xxe
{{
    public static void parseUpload(string inputXml)
    {{
        XmlReaderSettings settings = new XmlReaderSettings();
#pragma warning disable 618
        settings.{dtdPolicy};
#pragma warning restore 618
        XmlReader reader = XmlReader.Create(inputXml, settings);
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Xml

Class Xxe
    Public Shared Sub parseUpload(inputXml As String)
        Dim settings As New XmlReaderSettings()
#Disable Warning BC40000
        settings.{dtdPolicy}
#Enable Warning BC40000
        Dim reader As XmlReader = XmlReader.Create(inputXml, settings)
    End Sub
End Class
";
            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [DataRow("ProhibitDtd   = true")]
        [DataRow("DtdProcessing = DtdProcessing.Ignore")]
        [DataRow("DtdProcessing = DtdProcessing.Prohibit")]
        [DataTestMethod]
        public async Task XxeDtdProcessingSafeInitializer(string dtdPolicy)
        {
            var cSharpTest = $@"
using System.Xml;

class Xxe
{{
    public static void parseUpload(string inputXml)
    {{
#pragma warning disable 618
        XmlReaderSettings settings = new XmlReaderSettings {{{dtdPolicy}}};
#pragma warning restore 618
        XmlReader reader = XmlReader.Create(inputXml, settings);
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Xml

Class Xxe
    Public Shared Sub parseUpload(inputXml As String)
#Disable Warning BC40000
        Dim settings As New XmlReaderSettings With {{.{dtdPolicy}}}
#Enable Warning BC40000
        Dim reader As XmlReader = XmlReader.Create(inputXml, settings)
    End Sub
End Class
";
            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [DataRow("ProhibitDtd   = false")]
        [DataRow("DtdProcessing = DtdProcessing.Parse")]
        [DataTestMethod]
        public async Task XxeDtdProcessingUnsafeAssignment(string dtdPolicy)
        {
            var cSharpTest = $@"
using System.Xml;

class Xxe
{{
    public static void parseUpload(string inputXml)
    {{
        XmlReaderSettings settings = new XmlReaderSettings();
#pragma warning disable 618
        settings.{dtdPolicy};
#pragma warning restore 618
        XmlReader reader = XmlReader.Create(inputXml, settings);
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Xml

Class Xxe
    Public Shared Sub parseUpload(inputXml As String)
        Dim settings As New XmlReaderSettings()
#Disable Warning BC40000
        settings.{dtdPolicy}
#Enable Warning BC40000
        Dim reader As XmlReader = XmlReader.Create(inputXml, settings)
    End Sub
End Class
";
            var expected = new[]
            {
                new DiagnosticResult
                {
                    Id       = "SCS0007",
                    Severity = DiagnosticSeverity.Warning
                }
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [DataRow("ProhibitDtd   = false")]
        [DataRow("DtdProcessing = DtdProcessing.Parse")]
        [TestMethod, Ignore] // todo: not implemented
        public async Task XxeDtdProcessingUnsafeInitializer(string dtdPolicy)
        {
            var cSharpTest = $@"
using System.Xml;

class Xxe
{{
    public static void parseUpload(string inputXml)
    {{
#pragma warning disable 618
        XmlReaderSettings settings = new XmlReaderSettings {{{dtdPolicy}}};
#pragma warning restore 618
        XmlReader reader = XmlReader.Create(inputXml, settings);
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Xml

Class Xxe
    Public Shared Sub parseUpload(inputXml As String)
#Disable Warning BC40000
        Dim settings As New XmlReaderSettings With {{.{dtdPolicy}}}
#Enable Warning BC40000
        Dim reader As XmlReader = XmlReader.Create(inputXml, settings)
    End Sub
End Class
";
            var expected = new[]
            {
                new DiagnosticResult
                {
                    Id       = "SCS0007",
                    Severity = DiagnosticSeverity.Warning
                }
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }
    }

    [TestClass]
    public class XxeAnalyzerTaintTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new DiagnosticAnalyzer[] { new XxeAnalyzer(), new TaintAnalyzer() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(XmlNode).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        // although the input is untrusted
        // there is not xxe or path injection
        [TestMethod]
        public async Task StringReader()
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

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        // todo: introduce configuration setting to show questionable findings
        // add tests where ProhibitDtd, DtdProcessing or entire XmlReaderSettings comes from untrusted source
        //[DataRow("XmlReader.Create(default(Stream))")]
        //[DataRow("XmlReader.Create(default(Stream), xmlReaderSettingsInput)")]
        //[DataRow("XmlReader.Create(default(Stream), xmlReaderSettingsInput, default(string))")]
        //[DataRow("XmlReader.Create(default(Stream), xmlReaderSettingsInput, default(XmlParserContext))")]
        //[DataRow("XmlReader.Create(default(TextReader))")]
        //[DataRow("XmlReader.Create(default(TextReader), xmlReaderSettingsInput)")]
        //[DataRow("XmlReader.Create(default(TextReader), xmlReaderSettingsInput, default(string))")]
        //[DataRow("XmlReader.Create(default(TextReader), xmlReaderSettingsInput, default(XmlParserContext))")]
        //[DataRow("XmlReader.Create(default(TextReader), xmlReaderSettingsInput)")]
    }
}
