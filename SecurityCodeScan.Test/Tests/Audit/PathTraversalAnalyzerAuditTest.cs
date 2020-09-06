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
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string _)
        {
            return new[] { new PathTraversalTaintAnalyzer() };
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

        [DataRow("FS.AppendAllText(path, null)")]
        [DataRow("AppendAllText(path, null)")]
        [DataRow("FS.AppendAllText(path, null, System.Text.Encoding.ASCII)")]
        [DataRow("AppendAllText(path, null, System.Text.Encoding.ASCII)")]

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

        [DataRow("FS.Create(path)")]
        [DataRow("Create(path)")]
        [DataRow("FS.Create(path, 10)")]
        [DataRow("Create(path, 10)")]
        [DataRow("FS.Create(path, 10, System.IO.FileOptions.None)")]
        [DataRow("Create(path, 10, System.IO.FileOptions.None)")]
        [DataRow("FS.Create(path, 10, System.IO.FileOptions.None, null)")]
        [DataRow("Create(path, 10, System.IO.FileOptions.None, null)")]

        [DataRow("FS.CreateText(path)")]
        [DataRow("CreateText(path)")]

        [DataRow("FS.Move(\"c:\\aaa.txt\", path)")]
        [DataRow("Move(\"c:\\aaa.txt\", path)")]
        [DataRow("FS.Move(path, \"c:\\aaa.txt\")")]
        [DataRow("Move(path, \"c:\\aaa.txt\")")]

        [DataRow("FS.SetAccessControl(path, null)")]
        [DataRow("SetAccessControl(path, null)")]

        [DataRow("var temp = new FileInfo(path)")]
        [DataRow("var temp = new FileInfo(\"c:\\aaa.txt\").CopyTo(path)")]
        [DataRow("var temp = new FileInfo(\"c:\\aaa.txt\").CopyTo(path, true)")]
        [DataRow("var temp = new FileInfo(\"c:\\aaa.txt\").Replace(path, \"c:\\aaa.txt\")")]
        [DataRow("var temp = new FileInfo(\"c:\\aaa.txt\").Replace(\"c:\\aaa.txt\", path)")]
        [DataRow("var temp = new FileInfo(\"c:\\aaa.txt\").Replace(path, \"c:\\aaa.txt\", true)")]
        [DataRow("var temp = new FileInfo(\"c:\\aaa.txt\").Replace(\"c:\\aaa.txt\", path, true)")]
        [DataRow("var temp = new FileInfo(\"c:\\aaa.txt\"); temp.MoveTo(path)")]
        [DataRow("Assembly.LoadFile(path)")]
        [DataRow("Assembly.LoadFile(path, null)")]
        [DataRow("Assembly.LoadFrom(path)")]
        [DataRow("Assembly.LoadFrom(path, null)")]
        [DataRow("Assembly.LoadFrom(path, null, AssemblyHashAlgorithm.SHA512)")]
        [DataRow("Assembly.LoadFrom(path, null, null, AssemblyHashAlgorithm.SHA512)")]
        [DataRow("Assembly.UnsafeLoadFrom(path)")]

        [DataRow("var a = new FileStream(path, FileMode.Open)")]

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
    using System.Security.Policy;
    using System.Configuration.Assemblies;
    using System.Reflection;
    using System.Web.Mvc;
#pragma warning restore 8019

public class MyController : Controller
{{
    public void Run(string path, IEnumerable<String> contents, bool flag,
                    FileMode fileMode, FileAccess access, FileShare share, byte[] bytes,
                    FileSecurity fileSecurity, FileOptions fileOptions)
    {{
#pragma warning disable CS0618
        {sink};
#pragma warning restore CS0618
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
    Imports System.Security.Policy
    Imports System.Configuration.Assemblies
    Imports System.Reflection
    Imports System.Web.Mvc
#Enable Warning BC50001

Public Class MyController
    Inherits Controller

    Public Sub Run(path As String, contents As IEnumerable(Of String), flag As Boolean, fileMode As FileMode,
                   access as FileAccess, share As FileShare, bytes As Byte(), fileSecurity As FileSecurity,
                   fileOptions As FileOptions)
#Disable Warning BC40000
        {sink.CSharpReplaceToVBasic()}
#Enable Warning BC40000
    End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0018",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);

            cSharpTest = $@"
#pragma warning disable 8019
    using System;
    using System.Collections.Generic;
    using System.IO;
    using FS = System.IO.File;
    using static System.IO.File;
    using System.Security.AccessControl;
    using System.Security.Policy;
    using System.Configuration.Assemblies;
    using System.Reflection;
    using System.Web.Mvc;
#pragma warning restore 8019

public class Foo
{{
    public void Run(string path, IEnumerable<String> contents, bool flag,
                    FileMode fileMode, FileAccess access, FileShare share, byte[] bytes,
                    FileSecurity fileSecurity, FileOptions fileOptions)
    {{
#pragma warning disable CS0618
        {sink};
#pragma warning restore CS0618
    }}
}}
";

            visualBasicTest = $@"
#Disable Warning BC50001
    Imports System
    Imports System.Collections.Generic
    Imports System.IO
    Imports System.IO.File
    Imports FS = System.IO.File
    Imports System.Security.AccessControl
    Imports System.Security.Policy
    Imports System.Configuration.Assemblies
    Imports System.Reflection
    Imports System.Web.Mvc
#Enable Warning BC50001

Public Class Foo

    Public Sub Run(path As String, contents As IEnumerable(Of String), flag As Boolean, fileMode As FileMode,
                   access as FileAccess, share As FileShare, bytes As Byte(), fileSecurity As FileSecurity,
                   fileOptions As FileOptions)
#Disable Warning BC40000
        {sink.CSharpReplaceToVBasic()}
#Enable Warning BC40000
    End Sub
End Class
";

            // same warnings in audit mode
            await VerifyCSharpDiagnostic(cSharpTest,
                                         expected,
                                         await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false)).ConfigureAwait(false);

            await VerifyVisualBasicDiagnostic(visualBasicTest,
                                              expected,
                                              await AuditTest.GetAuditModeConfigOptions().ConfigureAwait(false)).ConfigureAwait(false);
        }

        [TestCategory("Safe")]

        [DataRow("FS.AppendAllLines(\"c:\\aaa.txt\", contents)")]
        [DataRow("AppendAllLines(\"c:\\aaa.txt\", contents)")]
        [DataRow("FS.AppendAllLines(\"c:\\aaa.txt\", contents, encoding)")]
        [DataRow("AppendAllLines(\"c:\\aaa.txt\", contents, encoding)")]

        [DataRow("FS.AppendAllText(\"c:\\aaa.txt\", path)")]
        [DataRow("AppendAllText(\"c:\\aaa.txt\", path)")]
        [DataRow("FS.AppendAllText(\"c:\\aaa.txt\", path, encoding)")]
        [DataRow("AppendAllText(\"c:\\aaa.txt\", path, encoding)")]

        [DataRow("FS.AppendText(\"c:\\aaa.txt\")")]
        [DataRow("AppendText(\"c:\\aaa.txt\")")]

        [DataRow("FS.Copy(\"c:\\aaa.txt\", \"c:\\aaa.txt\")")]
        [DataRow("Copy(\"c:\\aaa.txt\", \"c:\\aaa.txt\")")]
        [DataRow("FS.Copy(\"c:\\aaa.txt\", \"c:\\aaa.txt\", flag)")]
        [DataRow("Copy(\"c:\\aaa.txt\", \"c:\\aaa.txt\", flag)")]

        [DataRow("FS.Create(\"c:\\aaa.txt\")")]
        [DataRow("Create(\"c:\\aaa.txt\")")]
        [DataRow("FS.Create(\"c:\\aaa.txt\", digit)")]
        [DataRow("Create(\"c:\\aaa.txt\", digit)")]
        [DataRow("FS.Create(\"c:\\aaa.txt\", digit, fileOptions)")]
        [DataRow("Create(\"c:\\aaa.txt\", digit, fileOptions)")]
        [DataRow("FS.Create(\"c:\\aaa.txt\", digit, fileOptions, null)")]
        [DataRow("Create(\"c:\\aaa.txt\", digit, fileOptions, null)")]

        [DataRow("FS.CreateText(\"c:\\aaa.txt\")")]
        [DataRow("CreateText(\"c:\\aaa.txt\")")]

        [DataRow("FS.Move(\"c:\\aaa.txt\", \"c:\\aaa.txt\")")]
        [DataRow("Move(\"c:\\aaa.txt\", \"c:\\aaa.txt\")")]

        [DataRow("FS.SetAccessControl(\"c:\\aaa.txt\", fileSecurity)")]
        [DataRow("SetAccessControl(\"c:\\aaa.txt\", fileSecurity)")]

        [DataRow("var temp = new FileInfo(\"c:\\aaa.txt\")")]
        [DataRow("var temp = new FileInfo(\"c:\\aaa.txt\").CopyTo(\"c:\\aaa.txt\")")]
        [DataRow("var temp = new FileInfo(\"c:\\aaa.txt\").CopyTo(\"c:\\aaa.txt\", true)")]
        [DataRow("var temp = new FileInfo(\"c:\\aaa.txt\").Replace(\"c:\\aaa.txt\", \"c:\\aaa.txt\")")]
        [DataRow("var temp = new FileInfo(\"c:\\aaa.txt\").Replace(\"c:\\aaa.txt\", \"c:\\aaa.txt\")")]
        [DataRow("var temp = new FileInfo(\"c:\\aaa.txt\").Replace(\"c:\\aaa.txt\", \"c:\\aaa.txt\", true)")]
        [DataRow("var temp = new FileInfo(\"c:\\aaa.txt\").Replace(\"c:\\aaa.txt\", \"c:\\aaa.txt\", true)")]
        [DataRow("var temp = new FileInfo(\"c:\\aaa.txt\"); temp.MoveTo(\"c:\\aaa.txt\")")]
        [DataRow("Assembly.Load(\"c:\\aaa.txt\")")]
        [DataRow("Assembly.Load(\"c:\\aaa.txt\", new Evidence())")]
        [DataRow("Assembly.LoadFile(\"c:\\aaa.txt\")")]
        [DataRow("Assembly.LoadFile(\"c:\\aaa.txt\", new Evidence())")]
        [DataRow("Assembly.LoadFrom(\"c:\\aaa.txt\")")]
        [DataRow("Assembly.LoadFrom(\"c:\\aaa.txt\", new Evidence())")]
        [DataRow("Assembly.LoadFrom(\"c:\\aaa.txt\", null, AssemblyHashAlgorithm.SHA512)")]
        [DataRow("Assembly.LoadFrom(\"c:\\aaa.txt\", new Evidence(), null, AssemblyHashAlgorithm.SHA512)")]
        [DataRow("Assembly.LoadWithPartialName(\"c:\\aaa.txt\")")]
        [DataRow("Assembly.LoadWithPartialName(\"c:\\aaa.txt\", new Evidence())")]
        [DataRow("Assembly.ReflectionOnlyLoad(\"c:\\aaa.txt\")")]
        [DataRow("Assembly.ReflectionOnlyLoadFrom(\"c:\\aaa.txt\")")]
        [DataRow("Assembly.UnsafeLoadFrom(\"c:\\aaa.txt\")")]

        [DataRow("var a = new FileStream(\"\", FileMode.Open)")]

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
    using System.Security.Policy;
    using System.Configuration.Assemblies;
    using System.Reflection;
    using System.Web.Mvc;
#pragma warning restore 8019

public class MyController : Controller
{{
    public void Run(string path, IEnumerable<String> contents, bool flag,
                    FileMode fileMode, FileAccess access, FileShare share, byte[] bytes,
                    FileSecurity fileSecurity, FileOptions fileOptions, int digit, System.Text.Encoding encoding)
    {{
#pragma warning disable CS0618
        {sink};
#pragma warning restore CS0618
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
    Imports System.Security.Policy
    Imports System.Configuration.Assemblies
    Imports System.Reflection
    Imports System.Web.Mvc
#Enable Warning BC50001

Public Class MyController
    Inherits Controller

    Public Sub Run(path As String, contents As IEnumerable(Of String), flag As Boolean, fileMode As FileMode,
                   access as FileAccess, share As FileShare, bytes As Byte(), fileSecurity As FileSecurity,
                   fileOptions As FileOptions, digit As Int32, encoding As System.Text.Encoding)
#Disable Warning BC40000
        {sink.CSharpReplaceToVBasic()}
#Enable Warning BC40000
    End Sub
End Class
";
            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [DataRow("XmlReader.Create(textInput)")]
        [DataRow("XmlReader.Create(textInput, new XmlReaderSettings())")]
        [DataRow("XmlReader.Create(textInput, new XmlReaderSettings(), default(XmlParserContext))")]
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

public class MyController : Controller
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

Public Class MyController
    Inherits Controller

    Public Sub Run(textInput As String, streamInput As Stream, textReaderInput As TextReader, xmlReaderInput As XmlReader)
        Dim reader As XMLReader = {sink.CSharpReplaceToVBasic()}
    End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0018",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }
    }
}
