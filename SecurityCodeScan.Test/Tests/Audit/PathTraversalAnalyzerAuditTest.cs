using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Config;
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test.Tests.Audit
{
    [TestClass]
    public class PathTraversalAnalyzerAuditTest : ConfigurationTest
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            return new DiagnosticAnalyzer[] { new TaintAnalyzerCSharp(), new TaintAnalyzerVisualBasic(), };
        }

        [DataRow("File.AppendAllLines(path, null)")]
        [DataRow("AppendAllLines(path, null)")]
        [DataRow("File.AppendAllLines(path, null, System.Text.Encoding.ASCII)")]
        [DataRow("AppendAllLines(path, null, System.Text.Encoding.ASCII)")]
        [DataRow("File.AppendAllLines(\"c:\\aaa.txt\", contents)")]
        [DataRow("AppendAllLines(\"c:\\aaa.txt\", contents)")]
        [DataRow("File.AppendAllLines(\"c:\\aaa.txt\", contents, System.Text.Encoding.ASCII)")]
        [DataRow("AppendAllLines(\"c:\\aaa.txt\", contents, System.Text.Encoding.ASCII)")]

        [DataRow("File.AppendAllText(path, null)")]
        [DataRow("AppendAllText(path, null)")]
        [DataRow("File.AppendAllText(path, null, System.Text.Encoding.ASCII)")]
        [DataRow("AppendAllText(path, null, System.Text.Encoding.ASCII)")]
        [DataRow("File.AppendAllText(\"c:\\aaa.txt\", path)")]
        [DataRow("AppendAllText(\"c:\\aaa.txt\", path)")]
        [DataRow("File.AppendAllText(\"c:\\aaa.txt\", path, System.Text.Encoding.ASCII)")]
        [DataRow("AppendAllText(\"c:\\aaa.txt\", path, System.Text.Encoding.ASCII)")]

        [DataRow("File.AppendText(path)")]
        [DataRow("AppendText(path)")]

        [DataRow("File.Copy(\"\", path)")]
        [DataRow("Copy(\"\", path)")]
        [DataRow("File.Copy(\"\", path, true)")]
        [DataRow("Copy(\"\", path, true)")]
        [DataRow("File.Copy(path, \"\")")]
        [DataRow("Copy(path, \"\")")]
        [DataRow("File.Copy(path, \"\", true)")]
        [DataRow("Copy(path, \"\", true)")]
        [DataRow("File.Copy(\"\", \"\", flag)")]

        [DataRow("File.Create(path)")]
        [DataRow("Create(path)")]
        [DataRow("File.Create(path, 10)")]
        [DataRow("Create(path, 10)")]
        [DataRow("File.Create(path, 10, System.IO.FileOptions.None)")]
        [DataRow("Create(path, 10, System.IO.FileOptions.None)")]
        [DataRow("File.Create(\"\", 10, fileOptions)")]
        [DataRow("Create(\"\", 10, fileOptions)")]
        [DataRow("File.Create(path, 10, System.IO.FileOptions.None, null)")]
        [DataRow("Create(path, 10, System.IO.FileOptions.None, null)")]
        [DataRow("File.Create(\"\", 10, fileOptions, null)")]
        [DataRow("Create(\"\", 10, fileOptions, null)")]

        [DataRow("File.CreateText(path)")]
        [DataRow("CreateText(path)")]

        [DataRow("File.Move(\"c:\\aaa.txt\", path)")]
        [DataRow("Move(\"c:\\aaa.txt\", path)")]
        [DataRow("File.Move(path, \"c:\\aaa.txt\")")]
        [DataRow("Move(path, \"c:\\aaa.txt\")")]

        [DataRow("File.SetAccessControl(path, null)")]
        [DataRow("SetAccessControl(path, null)")]
        [DataRow("File.SetAccessControl(\"c:\\aaa.txt\", fileSecurity)")]
        [DataRow("SetAccessControl(\"c:\\aaa.txt\", fileSecurity)")]
        [DataTestMethod]
        public async Task PathTraversalMethods(string sink)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System;
    using System.Collections.Generic;
    using System.IO;
    using static System.IO.File;
    using System.Security.AccessControl;
#pragma warning restore 8019

class PathTraversal
{{
    public static void Run(string path, IEnumerable<String> contents, bool flag,
                           FileMode fileMode, FileAccess access, FileShare share, byte[] bytes,
                           FileSecurity fileSecurity, FileOptions fileOptions)
    {{
        {sink};
    }}
}}
";

            sink = sink.Replace("null", "Nothing");
            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System
    Imports System.Collections.Generic
    Imports System.IO
    Imports System.IO.File
    Imports System.Security.AccessControl
#Enable Warning BC50001

Class PathTraversal
    Public Shared Sub Run(path As String, contents As IEnumerable(Of String), flag As Boolean, fileMode As FileMode,
                          access as FileAccess, share As FileShare, bytes As Byte(), fileSecurity As FileSecurity,
                          fileOptions As FileOptions)
        {sink}
    End Sub
End Class
";

            // should be no warnings without audit config
            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);

            string testConfig;
            using (var file = File.OpenText(@"Config\AuditingMode.yml"))
            {
                testConfig = await file.ReadToEndAsync().ConfigureAwait(false);
            }
            var optionsWithProjectConfig = await CreateAnalyzersOptionsWithConfig(testConfig).ConfigureAwait(false);

            var expected = new DiagnosticResult
            {
                Id       = "SCS0018",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest,
                                         expected,
                                         optionsWithProjectConfig).ConfigureAwait(false);

            await VerifyVisualBasicDiagnostic(visualBasicTest,
                                              expected,
                                              optionsWithProjectConfig).ConfigureAwait(false);
        }

        [DataRow("File.AppendAllLines(\"c:\\aaa.txt\", null)")]
        [DataRow("AppendAllLines(\"c:\\aaa.txt\", null)")]
        [DataRow("File.AppendAllLines(\"c:\\aaa.txt\", null, encoding)")]
        [DataRow("AppendAllLines(\"c:\\aaa.txt\", null, encoding)")]

        [DataRow("File.AppendAllText(\"c:\\aaa.txt\", \"\")")]
        [DataRow("AppendAllText(\"c:\\aaa.txt\", \"\")")]
        [DataRow("File.AppendAllText(\"c:\\aaa.txt\", \"\", encoding)")]
        [DataRow("AppendAllText(\"c:\\aaa.txt\", \"\", encoding)")]

        [DataRow("File.AppendText(\"c:\\aaa.txt\")")]
        [DataRow("AppendText(\"c:\\aaa.txt\")")]

        [DataRow("File.Copy(\"c:\\aaa.txt\", \"c:\\aaa.txt\")")]
        [DataRow("Copy(\"c:\\aaa.txt\", \"c:\\aaa.txt\")")]
        [DataRow("File.Copy(\"c:\\aaa.txt\", \"c:\\aaa.txt\", true)")]
        [DataRow("Copy(\"c:\\aaa.txt\", \"c:\\aaa.txt\", true)")]

        [DataRow("File.Create(\"c:\\aaa.txt\")")]
        [DataRow("Create(\"c:\\aaa.txt\")")]
        [DataRow("File.Create(\"c:\\aaa.txt\", digit)")]
        [DataRow("Create(\"c:\\aaa.txt\", digit)")]
        [DataRow("File.Create(\"c:\\aaa.txt\", digit, System.IO.FileOptions.None)")]
        [DataRow("Create(\"c:\\aaa.txt\", digit, System.IO.FileOptions.None)")]
        [DataRow("File.Create(\"c:\\aaa.txt\", digit, System.IO.FileOptions.None, null)")]
        [DataRow("Create(\"c:\\aaa.txt\", digit, System.IO.FileOptions.None, null)")]

        [DataRow("File.CreateText(\"c:\\aaa.txt\")")]
        [DataRow("CreateText(\"c:\\aaa.txt\")")]

        [DataRow("File.Move(\"c:\\aaa.txt\", \"c:\\aaa.txt\")")]
        [DataRow("Move(\"c:\\aaa.txt\", \"c:\\aaa.txt\")")]

        [DataRow("File.SetAccessControl(\"c:\\aaa.txt\", null)")]
        [DataRow("SetAccessControl(\"c:\\aaa.txt\", null)")]
        [DataTestMethod]
        public async Task PathTraversalMethodsConst(string sink)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System;
    using System.Collections.Generic;
    using System.IO;
    using static System.IO.File;
    using System.Security.AccessControl;
#pragma warning restore 8019

class PathTraversal
{{
    public static void Run(bool flag, int digit, System.Text.Encoding encoding)
    {{
        {sink};
    }}
}}
";

            sink = sink.Replace("null", "Nothing");
            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System
    Imports System.Collections.Generic
    Imports System.IO
    Imports System.IO.File
    Imports System.Security.AccessControl
#Enable Warning BC50001

Class PathTraversal
    Public Shared Sub Run(flag As Boolean, digit As Int32, encoding As System.Text.Encoding)
        {sink}
    End Sub
End Class
";
            // should be no warnings without audit config
            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);

            string testConfig;
            using (var file = File.OpenText(@"Config\AuditingMode.yml"))
            {
                testConfig = await file.ReadToEndAsync().ConfigureAwait(false);
            }
            var optionsWithProjectConfig = await CreateAnalyzersOptionsWithConfig(testConfig).ConfigureAwait(false);

            // no warnings with config too
            await VerifyCSharpDiagnostic(cSharpTest, options:optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, options:optionsWithProjectConfig).ConfigureAwait(false);
        }

        [DataRow("XmlReader.Create(textInput)")]
        [DataRow("XmlReader.Create(textInput, new XmlReaderSettings())")]
        [DataRow("XmlReader.Create(textInput, new XmlReaderSettings(), default(XmlParserContext))")]
        [DataRow("XmlReader.Create(default(Stream), new XmlReaderSettings(), textInput)")]
        [DataRow("XmlReader.Create(default(TextReader), new XmlReaderSettings(), textInput)")]
        [DataTestMethod]
        public async Task PathTraversalXmlReader(string sink)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System.IO;
    using System.Xml;
#pragma warning restore 8019

class PathTraversal
{{
    public static void Run(string textInput, Stream streamInput, TextReader textReaderInput, XmlReader xmlReaderInput)
    {{
        var reader = {sink};
    }}
}}
";

            sink = sink.Replace("null", "Nothing");
            sink = Regex.Replace(sink, "default\\(([^\\)]*)\\)", "DirectCast(Nothing, $1)");
            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System.IO
    Imports System.Xml
#Enable Warning BC50001

Class PathTraversal
    Public Shared Sub Run(textInput As String, streamInput As Stream, textReaderInput As TextReader, xmlReaderInput As XmlReader)
        Dim reader As XMLReader = {sink}
    End Sub
End Class
";

            // should be no warnings without audit config
            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);

            string testConfig;
            using (var file = File.OpenText(@"Config\AuditingMode.yml"))
            {
                testConfig = await file.ReadToEndAsync().ConfigureAwait(false);
            }
            var optionsWithProjectConfig = await CreateAnalyzersOptionsWithConfig(testConfig).ConfigureAwait(false);

            var expected = new DiagnosticResult
            {
                Id       = "SCS0018",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest,
                                         expected,
                                         optionsWithProjectConfig).ConfigureAwait(false);

            await VerifyVisualBasicDiagnostic(visualBasicTest,
                                              expected,
                                              optionsWithProjectConfig).ConfigureAwait(false);
        }
    }
}
