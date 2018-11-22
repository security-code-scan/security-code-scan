using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test.Audit
{
    [TestClass]
    public class PathTraversalAnalyzerAuditTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            return new DiagnosticAnalyzer[] { new TaintAnalyzerCSharp(), new TaintAnalyzerVisualBasic(), };
        }

        private static readonly PortableExecutableReference[] References =
        {
             MetadataReference.CreateFromFile(typeof(System.Web.Mvc.Controller).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [DataRow("FS.AppendAllLines(path, null)")]
        [DataRow("AppendAllLines(path, null)")]
        [DataRow("FS.AppendAllLines(path, null, System.Text.Encoding.ASCII)")]
        [DataRow("AppendAllLines(path, null, System.Text.Encoding.ASCII)")]
        [DataRow("FS.AppendAllLines(\"c:\\aaa.txt\", contents)")]
        [DataRow("AppendAllLines(\"c:\\aaa.txt\", contents)")]
        [DataRow("FS.AppendAllLines(\"c:\\aaa.txt\", contents, System.Text.Encoding.ASCII)")]
        [DataRow("AppendAllLines(\"c:\\aaa.txt\", contents, System.Text.Encoding.ASCII)")]

        [DataRow("FS.AppendAllText(path, null)")]
        [DataRow("AppendAllText(path, null)")]
        [DataRow("FS.AppendAllText(path, null, System.Text.Encoding.ASCII)")]
        [DataRow("AppendAllText(path, null, System.Text.Encoding.ASCII)")]
        [DataRow("FS.AppendAllText(\"c:\\aaa.txt\", path)")]
        [DataRow("AppendAllText(\"c:\\aaa.txt\", path)")]
        [DataRow("FS.AppendAllText(\"c:\\aaa.txt\", path, System.Text.Encoding.ASCII)")]
        [DataRow("AppendAllText(\"c:\\aaa.txt\", path, System.Text.Encoding.ASCII)")]

        [DataRow("FS.AppendText(path)")]
        [DataRow("AppendText(path)")]

        [DataRow("FS.Copy(\"\", path)")]
        [DataRow("Copy(\"\", path)")]
        [DataRow("FS.Copy(\"\", path, true)")]
        [DataRow("Copy(\"\", path, true)")]
        [DataRow("FS.Copy(path, \"\")")]
        [DataRow("Copy(path, \"\")")]
        [DataRow("FS.Copy(path, \"\", true)")]
        [DataRow("Copy(path, \"\", true)")]
        [DataRow("FS.Copy(\"\", \"\", flag)")]

        [DataRow("FS.Create(path)")]
        [DataRow("Create(path)")]
        [DataRow("FS.Create(path, 10)")]
        [DataRow("Create(path, 10)")]
        [DataRow("FS.Create(path, 10, System.IO.FileOptions.None)")]
        [DataRow("Create(path, 10, System.IO.FileOptions.None)")]
        [DataRow("FS.Create(\"\", 10, fileOptions)")]
        [DataRow("Create(\"\", 10, fileOptions)")]
        [DataRow("FS.Create(path, 10, System.IO.FileOptions.None, null)")]
        [DataRow("Create(path, 10, System.IO.FileOptions.None, null)")]
        [DataRow("FS.Create(\"\", 10, fileOptions, null)")]
        [DataRow("Create(\"\", 10, fileOptions, null)")]

        [DataRow("FS.CreateText(path)")]
        [DataRow("CreateText(path)")]

        [DataRow("FS.Move(\"c:\\aaa.txt\", path)")]
        [DataRow("Move(\"c:\\aaa.txt\", path)")]
        [DataRow("FS.Move(path, \"c:\\aaa.txt\")")]
        [DataRow("Move(path, \"c:\\aaa.txt\")")]

        [DataRow("FS.SetAccessControl(path, null)")]
        [DataRow("SetAccessControl(path, null)")]
        [DataRow("FS.SetAccessControl(\"c:\\aaa.txt\", fileSecurity)")]
        [DataRow("SetAccessControl(\"c:\\aaa.txt\", fileSecurity)")]
        [TestCategory("Detect")]
        [DataTestMethod]
        public async Task PathTraversalMethods(string sink)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System;
    using System.Collections.Generic;
    using System.IO;
    using FS = System.IO.File;
    using static System.IO.File;
    using System.Security.AccessControl;
    using System.Web.Mvc;
#pragma warning restore 8019

class MyController : Controller
{{
    public void Run(string path, IEnumerable<String> contents, bool flag,
                           FileMode fileMode, FileAccess access, FileShare share, byte[] bytes,
                           FileSecurity fileSecurity, FileOptions fileOptions)
    {{
        {sink};
    }}
}}
";

            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System
    Imports System.Collections.Generic
    Imports System.IO
    Imports System.IO.File
    Imports FS = System.IO.File
    Imports System.Security.AccessControl
    Imports System.Web.Mvc
#Enable Warning BC50001

Class MyController
    Inherits Controller

    Public Sub Run(path As String, contents As IEnumerable(Of String), flag As Boolean, fileMode As FileMode,
                          access as FileAccess, share As FileShare, bytes As Byte(), fileSecurity As FileSecurity,
                          fileOptions As FileOptions)
        {sink.CSharpReplaceToVBasic()}
    End Sub
End Class
";

            // should be no warnings without audit config
            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);

            var expected = new DiagnosticResult
            {
                Id       = "SCS0018",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest,
                                         expected,
                                         await AuditTest.GetAuditModeConfigOptions()).ConfigureAwait(false);

            await VerifyVisualBasicDiagnostic(visualBasicTest,
                                              expected,
                                              await AuditTest.GetAuditModeConfigOptions()).ConfigureAwait(false);
        }

        [DataRow("FS.AppendAllLines(\"c:\\aaa.txt\", null)")]
        [DataRow("AppendAllLines(\"c:\\aaa.txt\", null)")]
        [DataRow("FS.AppendAllLines(\"c:\\aaa.txt\", null, encoding)")]
        [DataRow("AppendAllLines(\"c:\\aaa.txt\", null, encoding)")]

        [DataRow("FS.AppendAllText(\"c:\\aaa.txt\", \"\")")]
        [DataRow("AppendAllText(\"c:\\aaa.txt\", \"\")")]
        [DataRow("FS.AppendAllText(\"c:\\aaa.txt\", \"\", encoding)")]
        [DataRow("AppendAllText(\"c:\\aaa.txt\", \"\", encoding)")]

        [DataRow("FS.AppendText(\"c:\\aaa.txt\")")]
        [DataRow("AppendText(\"c:\\aaa.txt\")")]

        [DataRow("FS.Copy(\"c:\\aaa.txt\", \"c:\\aaa.txt\")")]
        [DataRow("Copy(\"c:\\aaa.txt\", \"c:\\aaa.txt\")")]
        [DataRow("FS.Copy(\"c:\\aaa.txt\", \"c:\\aaa.txt\", true)")]
        [DataRow("Copy(\"c:\\aaa.txt\", \"c:\\aaa.txt\", true)")]

        [DataRow("FS.Create(\"c:\\aaa.txt\")")]
        [DataRow("Create(\"c:\\aaa.txt\")")]
        [DataRow("FS.Create(\"c:\\aaa.txt\", digit)")]
        [DataRow("Create(\"c:\\aaa.txt\", digit)")]
        [DataRow("FS.Create(\"c:\\aaa.txt\", digit, System.IO.FileOptions.None)")]
        [DataRow("Create(\"c:\\aaa.txt\", digit, System.IO.FileOptions.None)")]
        [DataRow("FS.Create(\"c:\\aaa.txt\", digit, System.IO.FileOptions.None, null)")]
        [DataRow("Create(\"c:\\aaa.txt\", digit, System.IO.FileOptions.None, null)")]

        [DataRow("FS.CreateText(\"c:\\aaa.txt\")")]
        [DataRow("CreateText(\"c:\\aaa.txt\")")]

        [DataRow("FS.Move(\"c:\\aaa.txt\", \"c:\\aaa.txt\")")]
        [DataRow("Move(\"c:\\aaa.txt\", \"c:\\aaa.txt\")")]

        [DataRow("FS.SetAccessControl(\"c:\\aaa.txt\", null)")]
        [DataRow("SetAccessControl(\"c:\\aaa.txt\", null)")]
        [TestCategory("Safe")]
        [DataTestMethod]
        public async Task PathTraversalMethodsConst(string sink)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System;
    using System.Collections.Generic;
    using System.IO;
    using FS = System.IO.File;
    using static System.IO.File;
    using System.Security.AccessControl;
    using System.Web.Mvc;
#pragma warning restore 8019

class MyController : Controller
{{
    public void Run(bool flag, int digit, System.Text.Encoding encoding)
    {{
        {sink};
    }}
}}
";

            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System
    Imports System.Collections.Generic
    Imports System.IO
    Imports System.IO.File
    Imports FS = System.IO.File
    Imports System.Security.AccessControl
    Imports System.Web.Mvc
#Enable Warning BC50001

Class MyController
    Inherits Controller

    Public Sub Run(flag As Boolean, digit As Int32, encoding As System.Text.Encoding)
        {sink.CSharpReplaceToVBasic()}
    End Sub
End Class
";
            // should be no warnings without audit config
            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);

            // no warnings with config too
            await VerifyCSharpDiagnostic(cSharpTest, options:await AuditTest.GetAuditModeConfigOptions()).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, options:await AuditTest.GetAuditModeConfigOptions()).ConfigureAwait(false);
        }

        [DataRow("XmlReader.Create(textInput)")]
        [DataRow("XmlReader.Create(textInput, new XmlReaderSettings())")]
        [DataRow("XmlReader.Create(textInput, new XmlReaderSettings(), default(XmlParserContext))")]
        [DataRow("XmlReader.Create(default(Stream), new XmlReaderSettings(), textInput)")]
        [DataRow("XmlReader.Create(default(TextReader), new XmlReaderSettings(), textInput)")]
        [TestCategory("Detect")]
        [DataTestMethod]
        public async Task PathTraversalXmlReader(string sink)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System.IO;
    using System.Xml;
    using System.Web.Mvc;
#pragma warning restore 8019

class MyController : Controller
{{
    public void Run(string textInput, Stream streamInput, TextReader textReaderInput, XmlReader xmlReaderInput)
    {{
        var reader = {sink};
    }}
}}
";

            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System.IO
    Imports System.Xml
    Imports System.Web.Mvc
#Enable Warning BC50001

Class MyController
    Inherits Controller

    Public Sub Run(textInput As String, streamInput As Stream, textReaderInput As TextReader, xmlReaderInput As XmlReader)
        Dim reader As XMLReader = {sink.CSharpReplaceToVBasic()}
    End Sub
End Class
";

            // should be no warnings without audit config
            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);

            var expected = new DiagnosticResult
            {
                Id       = "SCS0018",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest,
                                         expected,
                                         await AuditTest.GetAuditModeConfigOptions()).ConfigureAwait(false);

            await VerifyVisualBasicDiagnostic(visualBasicTest,
                                              expected,
                                              await AuditTest.GetAuditModeConfigOptions()).ConfigureAwait(false);
        }
    }
}
