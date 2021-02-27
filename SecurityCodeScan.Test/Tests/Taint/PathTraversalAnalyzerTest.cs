using System.Collections.Generic;
using System.Threading.Tasks;
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
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string _)
        {
            return new[] { new PathTraversalTaintAnalyzer() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(System.Web.Mvc.Controller).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Web.UI.Page).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.Extensions.FileProviders.PhysicalFileProvider).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.Extensions.FileProviders.IFileInfo).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [DataRow("FS.Delete(path)")]
        [DataRow("Delete(path)")]

        [DataRow("FS.Open(path, System.IO.FileMode.CreateNew)")]
        [DataRow("Open(path, System.IO.FileMode.CreateNew)")]
        [DataRow("FS.Open(path, System.IO.FileMode.CreateNew, FileAccess.Read, FileShare.None)")]
        [DataRow("Open(path, System.IO.FileMode.CreateNew, FileAccess.Read, FileShare.None)")]
        [DataRow("FS.Open(path, System.IO.FileMode.CreateNew, FileAccess.Read)")]
        [DataRow("Open(path, System.IO.FileMode.CreateNew, FileAccess.Read)")]

        [DataRow("FS.OpenRead(path)")]
        [DataRow("OpenRead(path)")]

        [DataRow("FS.OpenText(path)")]
        [DataRow("OpenText(path)")]

        [DataRow("FS.OpenWrite(path)")]
        [DataRow("OpenWrite(path)")]

        [DataRow("FS.ReadAllBytes(path)")]
        [DataRow("ReadAllBytes(path)")]

        [DataRow("FS.ReadAllLines(path)")]
        [DataRow("ReadAllLines(path)")]
        [DataRow("FS.ReadAllLines(path, System.Text.Encoding.ASCII)")]
        [DataRow("ReadAllLines(path, System.Text.Encoding.ASCII)")]

        [DataRow("FS.ReadAllText(path)")]
        [DataRow("ReadAllText(path)")]
        [DataRow("FS.ReadAllText(path, System.Text.Encoding.ASCII)")]
        [DataRow("ReadAllText(path, System.Text.Encoding.ASCII)")]

        [DataRow("FS.ReadLines(path)")]
        [DataRow("ReadLines(path)")]
        [DataRow("FS.ReadLines(path, System.Text.Encoding.ASCII)")]
        [DataRow("ReadLines(path, System.Text.Encoding.ASCII)")]

        [DataRow("FS.Replace(path, \"c:\\aaa.txt\", \"c:\\aaa.txt\")")]
        [DataRow("Replace(path, \"c:\\aaa.txt\", \"c:\\aaa.txt\")")]
        [DataRow("FS.Replace(\"c:\\aaa.txt\", path, \"c:\\aaa.txt\")")]
        [DataRow("Replace(\"c:\\aaa.txt\", path, \"c:\\aaa.txt\")")]
        [DataRow("FS.Replace(\"c:\\aaa.txt\", \"c:\\aaa.txt\", path)")]
        [DataRow("Replace(\"c:\\aaa.txt\", \"c:\\aaa.txt\", path)")]
        [DataRow("FS.Replace(path, \"c:\\aaa.txt\", \"c:\\aaa.txt\", false)")]
        [DataRow("Replace(path, \"c:\\aaa.txt\", \"c:\\aaa.txt\", false)")]

        [DataRow("FS.WriteAllBytes(path, null)")]
        [DataRow("WriteAllBytes(path, null)")]

        [DataRow("FS.WriteAllLines(path, null)")]
        [DataRow("WriteAllLines(path, null)")]
        [DataRow("FS.WriteAllLines(path, null, System.Text.Encoding.ASCII)")]
        [DataRow("WriteAllLines(path, null, System.Text.Encoding.ASCII)")]

        [DataRow("FS.WriteAllText(path, \"\")")]
        [DataRow("WriteAllText(path, \"\")")]
        [DataRow("FS.WriteAllText(path, \"\", System.Text.Encoding.ASCII)")]
        [DataRow("WriteAllText(path, \"\", System.Text.Encoding.ASCII)")]
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

public class PathTraversalController : Controller
{{
    public void Run(string path, IEnumerable<String> contents, bool flag,
                    FileMode fileMode, FileAccess access, FileShare share, byte[] bytes,
                    FileSecurity fileSecurity, FileOptions fileOptions)
    {{
        {sink};
    }}
}}
";

            sink = sink.CSharpReplaceToVBasic();
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

Public Class PathTraversalController
    Inherits Controller

    Public Sub Run(path As String, contents As IEnumerable(Of String), flag As Boolean, fileMode As FileMode,
                   access as FileAccess, share As FileShare, bytes As Byte(), fileSecurity As FileSecurity,
                   fileOptions As FileOptions)
        {sink}
    End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id       = "SCS0018",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest,expected).ConfigureAwait(false);
        }

        [DataRow("FS.Delete(\"c:\\aaa.txt\")")]
        [DataRow("Delete(\"c:\\aaa.txt\")")]

        [DataRow("FS.Open(\"c:\\aaa.txt\", fileMode)")]
        [DataRow("Open(\"c:\\aaa.txt\", fileMode)")]
        [DataRow("FS.Open(\"c:\\aaa.txt\", fileMode, access)")]
        [DataRow("Open(\"c:\\aaa.txt\", fileMode, access)")]
        [DataRow("FS.Open(\"c:\\aaa.txt\", System.IO.FileMode.CreateNew, FileAccess.Read, share)")]
        [DataRow("Open(\"c:\\aaa.txt\", System.IO.FileMode.CreateNew, FileAccess.Read, share)")]

        [DataRow("FS.OpenRead(\"c:\\aaa.txt\")")]
        [DataRow("OpenRead(\"c:\\aaa.txt\")")]

        [DataRow("FS.OpenText(\"c:\\aaa.txt\")")]
        [DataRow("OpenText(\"c:\\aaa.txt\")")]

        [DataRow("FS.OpenWrite(\"c:\\aaa.txt\")")]
        [DataRow("OpenWrite(\"c:\\aaa.txt\")")]

        [DataRow("FS.ReadAllBytes(\"c:\\aaa.txt\")")]
        [DataRow("ReadAllBytes(\"c:\\aaa.txt\")")]

        [DataRow("FS.ReadAllLines(\"c:\\aaa.txt\")")]
        [DataRow("ReadAllLines(\"c:\\aaa.txt\")")]
        [DataRow("FS.ReadAllLines(\"c:\\aaa.txt\", encoding)")]
        [DataRow("ReadAllLines(\"c:\\aaa.txt\", encoding)")]

        [DataRow("FS.ReadAllText(\"c:\\aaa.txt\")")]
        [DataRow("ReadAllText(\"c:\\aaa.txt\")")]
        [DataRow("FS.ReadAllText(\"c:\\aaa.txt\", encoding)")]
        [DataRow("ReadAllText(\"c:\\aaa.txt\", encoding)")]

        [DataRow("FS.ReadLines(\"c:\\aaa.txt\")")]
        [DataRow("ReadLines(\"c:\\aaa.txt\")")]
        [DataRow("FS.ReadLines(\"c:\\aaa.txt\", encoding)")]
        [DataRow("ReadLines(\"c:\\aaa.txt\", encoding)")]

        [DataRow("FS.Replace(\"c:\\aaa.txt\", \"c:\\aaa.txt\", \"c:\\aaa.txt\")")]
        [DataRow("Replace(\"c:\\aaa.txt\", \"c:\\aaa.txt\", \"c:\\aaa.txt\")")]
        [DataRow("FS.Replace(\"c:\\aaa.txt\", \"c:\\aaa.txt\", \"c:\\aaa.txt\", false)")]
        [DataRow("Replace(\"c:\\aaa.txt\", \"c:\\aaa.txt\", \"c:\\aaa.txt\", false)")]

        [DataRow("FS.WriteAllBytes(\"c:\\aaa.txt\", bytes)")]
        [DataRow("WriteAllBytes(\"c:\\aaa.txt\", bytes)")]

        [DataRow("FS.WriteAllLines(\"c:\\aaa.txt\", contents)")]
        [DataRow("WriteAllLines(\"c:\\aaa.txt\", contents)")]
        [DataRow("FS.WriteAllLines(\"c:\\aaa.txt\", contents, encoding)")]
        [DataRow("WriteAllLines(\"c:\\aaa.txt\", contents, encoding)")]

        [DataRow("FS.WriteAllText(\"c:\\aaa.txt\", path)")]
        [DataRow("WriteAllText(\"c:\\aaa.txt\", path)")]
        [DataRow("FS.WriteAllText(\"c:\\aaa.txt\", path, encoding)")]
        [DataRow("WriteAllText(\"c:\\aaa.txt\", path, encoding)")]
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

public class PathTraversalController : Controller
{{
    public void Run(string path, IEnumerable<String> contents, bool flag,
                    FileMode fileMode, FileAccess access, FileShare share, byte[] bytes,
                    FileSecurity fileSecurity, FileOptions fileOptions, int digit, System.Text.Encoding encoding)
    {{
        {sink};
    }}
}}
";

            sink = sink.CSharpReplaceToVBasic();
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

Public Class PathTraversalController
    Inherits Controller

    Public Sub Run(path As String, contents As IEnumerable(Of String), flag As Boolean, fileMode As FileMode,
                   access as FileAccess, share As FileShare, bytes As Byte(), fileSecurity As FileSecurity,
                   fileOptions As FileOptions, digit As Int32, encoding As System.Text.Encoding)
        {sink}
    End Sub
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [DataTestMethod]
        [DataRow("FS.OpenRead(Server.MapPath(Request[\"file\"]))")]
        [DataRow("FS.OpenRead(Request.MapPath(Request[\"file\"]))")]
        [DataRow("FS.OpenRead(provider.GetFileInfo(Request[\"file\"]).PhysicalPath)")]
        public async Task PathTraversalMapPath(string payload)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using FS = System.IO.File;
    using System.Web.UI;
    using Microsoft.Extensions.FileProviders;
#pragma warning restore 8019

public class MyPage : Page
{{
    public void Run()
    {{
        var provider = new PhysicalFileProvider(""c:\\temp\\"");
        {payload};
    }}
}}
";

            payload = payload.CSharpReplaceToVBasic();
            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports FS = System.IO.File
    Imports System.Web.UI
    Imports Microsoft.Extensions.FileProviders
#Enable Warning BC50001

Public Class MyPage
    Inherits Page

    Public Sub Run()
        Dim provider = New PhysicalFileProvider(""c:\\temp\\"")
        {payload}
    End Sub
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }


        [DataRow("StreamReader(input)")]
        [DataRow("StreamReader(input, false)")]
        [DataRow("StreamReader(input, System.Text.Encoding.ASCII)")]
        [DataRow("StreamReader(input, System.Text.Encoding.ASCII, false)")]
        [DataRow("StreamReader(input, System.Text.Encoding.ASCII, false, 0)")]

        [DataRow("StreamWriter(input)")]
        [DataRow("StreamWriter(input, false)")]
        [DataRow("StreamWriter(input, false, System.Text.Encoding.ASCII)")]
        [DataRow("StreamWriter(input, false, System.Text.Encoding.ASCII, 10)")]
        [TestCategory("Detect")]
        [DataTestMethod]
        public async Task PathTraversalNewObject(string sink)
        {
            var cSharpTest = $@"
using System;
using System.IO;
using Microsoft.Win32.SafeHandles;
using System.Security.AccessControl;
using System.Web.Mvc;

public class PathTraversalController : Controller
{{
    public void Run(string input, FileMode fileMode, IntPtr handle, FileAccess access, SafeFileHandle safeHandle,
                    FileShare fileShare, FileOptions fileOptions, FileSystemRights fileSystemRights,
                    FileSecurity fileSecurity, bool flag)
    {{
#pragma warning disable 618
        new {sink};
#pragma warning restore 618
    }}
}}
";

            sink = sink.CSharpReplaceToVBasic();
            var visualBasicTest = $@"
Imports System
Imports System.IO
Imports Microsoft.Win32.SafeHandles
Imports System.Security.AccessControl
Imports System.Web.Mvc

Public Class PathTraversalController
    Inherits Controller

    Public Sub Run(input As String, fileMode As FileMode, handle As IntPtr, access As FileAccess,
                   safeHandle As SafeFileHandle, fileShare As FileShare, fileOptions As FileOptions,
                   fileSystemRights As FileSystemRights, fileSecurity As FileSecurity, flag As Boolean)
#Disable Warning BC40000
        Dim sr As New {sink}
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
        }

        [DataRow("StreamReader(\"\")")]
        [DataRow("StreamReader(\"\", flag)")]
        [DataRow("StreamReader(\"\", encoding)")]
        [DataRow("StreamReader(\"\", encoding, flag)")]
        [DataRow("StreamReader(\"\", encoding, flag, digit)")]

        [DataRow("StreamWriter(\"\")")]
        [DataRow("StreamWriter(\"\", flag)")]
        [DataRow("StreamWriter(\"\", flag, encoding)")]
        [DataRow("StreamWriter(\"\", flag, encoding, digit)")]
        [DataRow("StreamWriter(\"\", flag, System.Text.Encoding.ASCII, digit)")]
        [DataRow("StreamWriter(\"\", flag, encoding, 10)")]

        [DataRow("FileStream(IntPtr.Zero, FileAccess.Read)")]
        [DataRow("FileStream(IntPtr.Zero, access)")]
        [DataRow("FileStream(IntPtr.Zero, FileAccess.Read, flag)")]
        [DataRow("FileStream(IntPtr.Zero, access, false)")]
        [DataRow("FileStream(IntPtr.Zero, access, false, 0, true)")]
        [DataRow("FileStream(\"\",        FileMode.CreateNew)")]
        [DataRow("FileStream(\"\",        fileMode)")]

        [DataRow("FileStream(default(SafeFileHandle), FileAccess.Read)")]
        [DataRow("FileStream(default(SafeFileHandle), access)")]
        [DataRow("FileStream(default(SafeFileHandle), FileAccess.Read, digit, flag)")]
        [DataRow("FileStream(default(SafeFileHandle), access, 0, false)")]

        [DataRow("FileStream(\"\", FileMode.CreateNew)")]
        [DataRow("FileStream(\"\", FileMode.CreateNew, FileAccess.Read)")]
        [DataRow("FileStream(\"\", FileMode.CreateNew, FileAccess.Read,         FileShare.Read)")]
        [DataRow("FileStream(\"\", FileMode.CreateNew, FileAccess.Read,         FileShare.Read, digit)")]
        [DataRow("FileStream(\"\", FileMode.CreateNew, FileAccess.Read,         FileShare.Read, digit, flag)")]
        [DataRow("FileStream(\"\", FileMode.CreateNew, FileAccess.Read,         FileShare.Read, digit, FileOptions.None)")]
        [DataRow("FileStream(\"\", FileMode.CreateNew, FileSystemRights.Read,   FileShare.Read, digit, FileOptions.None, default(FileSecurity))")]
        [DataRow("FileStream(\"\", fileMode)")]
        [DataRow("FileStream(\"\", FileMode.CreateNew, access)")]
        [DataRow("FileStream(\"\", FileMode.CreateNew, FileAccess.Read,         fileShare)")]
        [DataRow("FileStream(\"\", FileMode.CreateNew, FileAccess.Read,         fileShare,      10)")]
        [DataRow("FileStream(\"\", FileMode.CreateNew, FileAccess.Read,         fileShare,      10, false)")]
        [DataRow("FileStream(\"\", FileMode.CreateNew, FileAccess.Read,         FileShare.Read, 10, fileOptions)")]
        [DataRow("FileStream(\"\", FileMode.CreateNew, fileSystemRights,        FileShare.Read, 10, FileOptions.None)")]
        [DataRow("FileStream(\"\", FileMode.CreateNew, FileSystemRights.Read,   FileShare.Read, 10, FileOptions.None, fileSecurity)")]
        [TestCategory("Safe")]
        [DataTestMethod]
        public async Task PathTraversalNewObjectConst(string sink)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System;
    using System.IO;
    using Microsoft.Win32.SafeHandles;
    using System.Security.AccessControl;
    using System.Web.Mvc;
#pragma warning restore 8019

public class PathTraversalController : Controller
{{
    public void Run(string input, FileMode fileMode, IntPtr handle, FileAccess access, SafeFileHandle safeHandle,
                    FileShare fileShare, FileOptions fileOptions, FileSystemRights fileSystemRights,
                    FileSecurity fileSecurity, bool flag, int digit, System.Text.Encoding encoding)
    {{
#pragma warning disable 618
        new {sink};
#pragma warning restore 618
    }}
}}
";

            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System
    Imports System.IO
    Imports Microsoft.Win32.SafeHandles
    Imports System.Security.AccessControl
    Imports System.Web.Mvc
#Enable Warning BC50001

Public Class PathTraversalController
    Inherits Controller

    Public Sub Run(input As String, fileMode As FileMode, handle As IntPtr, access As FileAccess,
                   safeHandle As SafeFileHandle, fileShare As FileShare, fileOptions As FileOptions,
                   fileSystemRights As FileSystemRights, fileSecurity As FileSecurity, flag As Boolean,
                   digit As Int32, encoding As System.Text.Encoding)
#Disable Warning BC40000
        Dim sr As New {sink.CSharpReplaceToVBasic()}
#Enable Warning BC40000
    End Sub
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [DataRow("XmlReader.Create(\"\")")]
        [DataRow("XmlReader.Create(\"\", settings)")]
        [DataRow("XmlReader.Create(\"\", settings, context)")]
        [DataRow("XmlReader.Create(default(Stream))")]
        [DataRow("XmlReader.Create(default(Stream), settings)")]
        [DataRow("XmlReader.Create(default(Stream), settings, default(string))")]
        [DataRow("XmlReader.Create(default(Stream), settings, default(XmlParserContext))")]
        [DataRow("XmlReader.Create(default(TextReader))")]
        [DataRow("XmlReader.Create(default(TextReader), settings)")]
        [DataRow("XmlReader.Create(default(TextReader), settings, default(string))")]
        [DataRow("XmlReader.Create(default(TextReader), settings, default(XmlParserContext))")]
        [DataRow("XmlReader.Create(default(XmlReader), settings)")]
        [TestCategory("Safe")]
        [DataTestMethod]
        public async Task PathTraversalXmlReaderConst(string sink)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System.IO;
    using System.Xml;
    using System.Web.Mvc;
#pragma warning restore 8019

public class PathTraversalController : Controller
{{
    public void Run(XmlReaderSettings settings, XmlParserContext context)
    {{
        var reader = {sink};
    }}
}}
";

            sink = sink.CSharpReplaceToVBasic();
            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System.IO
    Imports System.Xml
    Imports System.Web.Mvc
#Enable Warning BC50001

Public Class PathTraversalController
    Inherits Controller

    Public Shared Sub Run(settings As XmlReaderSettings, context As XmlParserContext)
        Dim reader As XMLReader = {sink}
    End Sub
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [DataRow("fileUpload.SaveAs(path)")]
        [TestCategory("Detect")]
        [DataTestMethod]
        public async Task PathTraversalFileUploadSaveAs(string sink)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System;
    using System.Web.Mvc;
    using System.Web.UI.WebControls;
#pragma warning restore 8019

public class PathTraversalController : Controller
{{
    public void Run(string path)
    {{
        FileUpload fileUpload = new FileUpload();
        {sink};
    }}
}}
";

            sink = sink.CSharpReplaceToVBasic();
            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System
    Imports System.Web.Mvc
    Imports System.Web.UI.WebControls
#Enable Warning BC50001

Public Class PathTraversalController
    Inherits Controller

    Public Sub Run(path As String)
        Dim fileUpload As New FileUpload()
        {sink.CSharpReplaceToVBasic()}
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

        [DataRow("fileUpload.SaveAs(\"\")")]
        [TestCategory("Safe")]
        [DataTestMethod]
        public async Task PathTraversalFileUploadSaveAsConst(string sink)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System;
    using System.Web.Mvc;
    using System.Web.UI.WebControls;
#pragma warning restore 8019

public class PathTraversalController: Controller
{{
    public void Run()
    {{
        FileUpload fileUpload = new FileUpload();
        {sink};
    }}
}}
";

            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System
    Imports System.Web.Mvc
    Imports System.Web.UI.WebControls
#Enable Warning BC50001

Public Class PathTraversalController
    Inherits Controller

    Public Sub Run()
        Dim fileUpload As New FileUpload()
        {sink.CSharpReplaceToVBasic()}
    End Sub
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }
    }
}
