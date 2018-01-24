using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
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

        [DataRow("File.Delete(path)")]
        [DataRow("Delete(path)")]

        [DataRow("File.Move(\"c:\\aaa.txt\", path)")]
        [DataRow("Move(\"c:\\aaa.txt\", path)")]
        [DataRow("File.Move(path, \"c:\\aaa.txt\")")]
        [DataRow("Move(path, \"c:\\aaa.txt\")")]

        [DataRow("File.Open(path, System.IO.FileMode.CreateNew)")]
        [DataRow("Open(path, System.IO.FileMode.CreateNew)")]
        [DataRow("File.Open(\"c:\\aaa.txt\", fileMode)")]
        [DataRow("Open(\"c:\\aaa.txt\", fileMode)")]
        [DataRow("File.Open(\"c:\\aaa.txt\", System.IO.FileMode.CreateNew, access)")]
        [DataRow("Open(\"c:\\aaa.txt\", System.IO.FileMode.CreateNew, access)")]
        [DataRow("File.Open(path, System.IO.FileMode.CreateNew, FileAccess.Read)")]
        [DataRow("Open(path, System.IO.FileMode.CreateNew, FileAccess.Read)")]
        [DataRow("File.Open(\"c:\\aaa.txt\", System.IO.FileMode.CreateNew, FileAccess.Read, share)")]
        [DataRow("Open(\"c:\\aaa.txt\", System.IO.FileMode.CreateNew, FileAccess.Read, share)")]
        [DataRow("File.Open(path, System.IO.FileMode.CreateNew, FileAccess.Read, FileShare.None)")]
        [DataRow("Open(path, System.IO.FileMode.CreateNew, FileAccess.Read, FileShare.None)")]

        [DataRow("File.OpenRead(path)")]
        [DataRow("OpenRead(path)")]

        [DataRow("File.OpenText(path)")]
        [DataRow("OpenText(path)")]

        [DataRow("File.OpenWrite(path)")]
        [DataRow("OpenWrite(path)")]

        [DataRow("File.ReadAllBytes(path)")]
        [DataRow("ReadAllBytes(path)")]

        [DataRow("File.ReadAllLines(path)")]
        [DataRow("ReadAllLines(path)")]
        [DataRow("File.ReadAllLines(path, System.Text.Encoding.ASCII)")]
        [DataRow("ReadAllLines(path, System.Text.Encoding.ASCII)")]

        [DataRow("File.ReadAllText(path)")]
        [DataRow("ReadAllText(path)")]
        [DataRow("File.ReadAllText(path, System.Text.Encoding.ASCII)")]
        [DataRow("ReadAllText(path, System.Text.Encoding.ASCII)")]

        [DataRow("File.ReadLines(path)")]
        [DataRow("ReadLines(path)")]
        [DataRow("File.ReadLines(path, System.Text.Encoding.ASCII)")]
        [DataRow("ReadLines(path, System.Text.Encoding.ASCII)")]

        [DataRow("File.Replace(path, \"c:\\aaa.txt\", \"c:\\aaa.txt\")")]
        [DataRow("Replace(path, \"c:\\aaa.txt\", \"c:\\aaa.txt\")")]
        [DataRow("File.Replace(\"c:\\aaa.txt\", path, \"c:\\aaa.txt\")")]
        [DataRow("Replace(\"c:\\aaa.txt\", path, \"c:\\aaa.txt\")")]
        [DataRow("File.Replace(\"c:\\aaa.txt\", \"c:\\aaa.txt\", path)")]
        [DataRow("Replace(\"c:\\aaa.txt\", \"c:\\aaa.txt\", path)")]
        [DataRow("File.Replace(path, \"c:\\aaa.txt\", \"c:\\aaa.txt\", false)")]
        [DataRow("Replace(path, \"c:\\aaa.txt\", \"c:\\aaa.txt\", false)")]

        [DataRow("File.SetAccessControl(path, null)")]
        [DataRow("SetAccessControl(path, null)")]
        [DataRow("File.SetAccessControl(\"c:\\aaa.txt\", fileSecurity)")]
        [DataRow("SetAccessControl(\"c:\\aaa.txt\", fileSecurity)")]

        [DataRow("File.WriteAllBytes(path, null)")]
        [DataRow("WriteAllBytes(path, null)")]
        [DataRow("File.WriteAllBytes(\"c:\\aaa.txt\", bytes)")]
        [DataRow("WriteAllBytes(\"c:\\aaa.txt\", bytes)")]

        [DataRow("File.WriteAllLines(path, null)")]
        [DataRow("WriteAllLines(path, null)")]
        [DataRow("File.WriteAllLines(\"c:\\aaa.txt\", contents)")]
        [DataRow("WriteAllLines(\"c:\\aaa.txt\", contents)")]
        [DataRow("File.WriteAllLines(path, null, System.Text.Encoding.ASCII)")]
        [DataRow("WriteAllLines(path, null, System.Text.Encoding.ASCII)")]
        [DataRow("File.WriteAllLines(\"c:\\aaa.txt\", contents, System.Text.Encoding.ASCII)")]
        [DataRow("WriteAllLines(\"c:\\aaa.txt\", contents, System.Text.Encoding.ASCII)")]

        [DataRow("File.WriteAllText(path, \"\")")]
        [DataRow("WriteAllText(path, \"\")")]
        [DataRow("File.WriteAllText(path, \"\", System.Text.Encoding.ASCII)")]
        [DataRow("WriteAllText(path, \"\", System.Text.Encoding.ASCII)")]
        [DataRow("File.WriteAllText(\"c:\\aaa.txt\", path)")]
        [DataRow("WriteAllText(\"c:\\aaa.txt\", path)")]
        [DataRow("File.WriteAllText(\"c:\\aaa.txt\", path, System.Text.Encoding.ASCII)")]
        [DataRow("WriteAllText(\"c:\\aaa.txt\", path, System.Text.Encoding.ASCII)")]
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

            var expected = new DiagnosticResult
            {
                Id       = "SCS0018",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
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

        [DataRow("File.Delete(\"c:\\aaa.txt\")")]
        [DataRow("Delete(\"c:\\aaa.txt\")")]

        [DataRow("File.Move(\"c:\\aaa.txt\", \"c:\\aaa.txt\")")]
        [DataRow("Move(\"c:\\aaa.txt\", \"c:\\aaa.txt\")")]

        [DataRow("File.Open(\"c:\\aaa.txt\", System.IO.FileMode.CreateNew)")]
        [DataRow("Open(\"c:\\aaa.txt\", System.IO.FileMode.CreateNew)")]
        [DataRow("File.Open(\"c:\\aaa.txt\", System.IO.FileMode.CreateNew, FileAccess.Read)")]
        [DataRow("Open(\"c:\\aaa.txt\", System.IO.FileMode.CreateNew, FileAccess.Read)")]
        [DataRow("File.Open(\"c:\\aaa.txt\", System.IO.FileMode.CreateNew, FileAccess.Read)")]
        [DataRow("Open(\"c:\\aaa.txt\", System.IO.FileMode.CreateNew, FileAccess.Read)")]
        [DataRow("File.Open(\"c:\\aaa.txt\", System.IO.FileMode.CreateNew, FileAccess.Read, FileShare.None)")]
        [DataRow("Open(\"c:\\aaa.txt\", System.IO.FileMode.CreateNew, FileAccess.Read, FileShare.None)")]

        [DataRow("File.OpenRead(\"c:\\aaa.txt\")")]
        [DataRow("OpenRead(\"c:\\aaa.txt\")")]

        [DataRow("File.OpenText(\"c:\\aaa.txt\")")]
        [DataRow("OpenText(\"c:\\aaa.txt\")")]

        [DataRow("File.OpenWrite(\"c:\\aaa.txt\")")]
        [DataRow("OpenWrite(\"c:\\aaa.txt\")")]

        [DataRow("File.ReadAllBytes(\"c:\\aaa.txt\")")]
        [DataRow("ReadAllBytes(\"c:\\aaa.txt\")")]

        [DataRow("File.ReadAllLines(\"c:\\aaa.txt\")")]
        [DataRow("ReadAllLines(\"c:\\aaa.txt\")")]
        [DataRow("File.ReadAllLines(\"c:\\aaa.txt\", encoding)")]
        [DataRow("ReadAllLines(\"c:\\aaa.txt\", encoding)")]

        [DataRow("File.ReadAllText(\"c:\\aaa.txt\")")]
        [DataRow("ReadAllText(\"c:\\aaa.txt\")")]
        [DataRow("File.ReadAllText(\"c:\\aaa.txt\", encoding)")]
        [DataRow("ReadAllText(\"c:\\aaa.txt\", encoding)")]

        [DataRow("File.ReadLines(\"c:\\aaa.txt\")")]
        [DataRow("ReadLines(\"c:\\aaa.txt\")")]
        [DataRow("File.ReadLines(\"c:\\aaa.txt\", encoding)")]
        [DataRow("ReadLines(\"c:\\aaa.txt\", encoding)")]

        [DataRow("File.Replace(\"c:\\aaa.txt\", \"c:\\aaa.txt\", \"c:\\aaa.txt\")")]
        [DataRow("Replace(\"c:\\aaa.txt\", \"c:\\aaa.txt\", \"c:\\aaa.txt\")")]
        [DataRow("File.Replace(\"c:\\aaa.txt\", \"c:\\aaa.txt\", \"c:\\aaa.txt\", false)")]
        [DataRow("Replace(\"c:\\aaa.txt\", \"c:\\aaa.txt\", \"c:\\aaa.txt\", false)")]

        [DataRow("File.SetAccessControl(\"c:\\aaa.txt\", null)")]
        [DataRow("SetAccessControl(\"c:\\aaa.txt\", null)")]

        [DataRow("File.WriteAllBytes(\"c:\\aaa.txt\", null)")]
        [DataRow("WriteAllBytes(\"c:\\aaa.txt\", null)")]

        [DataRow("File.WriteAllLines(\"c:\\aaa.txt\", null)")]
        [DataRow("WriteAllLines(\"c:\\aaa.txt\", null)")]
        [DataRow("File.WriteAllLines(\"c:\\aaa.txt\", null, encoding)")]
        [DataRow("WriteAllLines(\"c:\\aaa.txt\", null, encoding)")]

        [DataRow("File.WriteAllText(\"c:\\aaa.txt\", \"\")")]
        [DataRow("WriteAllText(\"c:\\aaa.txt\", \"\")")]
        [DataRow("File.WriteAllText(\"c:\\aaa.txt\", \"\", encoding)")]
        [DataRow("WriteAllText(\"c:\\aaa.txt\", \"\", encoding)")]
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

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [DataRow("StreamReader(input)")]
        [DataRow("StreamReader(input, false)")]
        [DataRow("StreamReader(input, System.Text.Encoding.ASCII)")]
        [DataRow("StreamReader(input, System.Text.Encoding.ASCII, false)")]
        [DataRow("StreamReader(input, System.Text.Encoding.ASCII, false, 0)")]

        [DataRow("StreamWriter(input)")]
        [DataRow("StreamWriter(input, false)")]
        [DataRow("StreamWriter(\"\",  flag)")]
        [DataRow("StreamWriter(input, false, System.Text.Encoding.ASCII)")]
        [DataRow("StreamWriter(input, false, System.Text.Encoding.ASCII, 10)")]
        [DataRow("StreamWriter(\"\", flag, System.Text.Encoding.ASCII)")]
        [DataRow("StreamWriter(\"\", flag, System.Text.Encoding.ASCII, 10)")]

        [DataRow("FileStream(handle, FileAccess.Read)")]
        [DataRow("FileStream(IntPtr.Zero, access)")]
        [DataRow("FileStream(handle, FileAccess.Read, false)")]
        [DataRow("FileStream(IntPtr.Zero, access, false)")]
        [DataRow("FileStream(handle, FileAccess.Read, false, 0, true)")]
        [DataRow("FileStream(IntPtr.Zero, access, false, 0, true)")]

        [DataRow("FileStream(safeHandle, FileAccess.Read)")]
        [DataRow("FileStream(default(SafeFileHandle), access)")]
        [DataRow("FileStream(safeHandle, FileAccess.Read, 0, false)")]
        [DataRow("FileStream(default(SafeFileHandle), access, 0, false)")]

        [DataRow("FileStream(input, FileMode.CreateNew)")]
        [DataRow("FileStream(\"\", fileMode)")]
        [DataRow("FileStream(\"\", FileMode.CreateNew, access)")]
        [DataRow("FileStream(\"\", FileMode.CreateNew, FileAccess.Read,         fileShare)")]
        [DataRow("FileStream(\"\", FileMode.CreateNew, FileAccess.Read,         fileShare,      10)")]
        [DataRow("FileStream(\"\", FileMode.CreateNew, FileAccess.Read,         fileShare,      10, false)")]
        [DataRow("FileStream(\"\", FileMode.CreateNew, FileAccess.Read,         FileShare.Read, 10, fileOptions)")]
        [DataRow("FileStream(\"\", FileMode.CreateNew, fileSystemRights,        FileShare.Read, 10, FileOptions.None)")]
        [DataRow("FileStream(\"\", FileMode.CreateNew, FileSystemRights.Read,   FileShare.Read, 10, FileOptions.None, fileSecurity)")]
        [DataTestMethod]
        public async Task PathTraversalNewObject(string sink)
        {
            var cSharpTest = $@"
using System;
using System.IO;
using Microsoft.Win32.SafeHandles;
using System.Security.AccessControl;

class PathTraversal
{{
    public static void Run(string input, FileMode fileMode, IntPtr handle, FileAccess access, SafeFileHandle safeHandle,
                           FileShare fileShare, FileOptions fileOptions, FileSystemRights fileSystemRights,
                           FileSecurity fileSecurity, bool flag)
    {{
#pragma warning disable 618
        new {sink};
#pragma warning restore 618
    }}
}}
";

            sink = sink.Replace("null", "Nothing");
            sink = Regex.Replace(sink, "default\\(([^\\)]*)\\)", "DirectCast(Nothing, $1)");
            var visualBasicTest = $@"
Imports System
Imports System.IO
Imports Microsoft.Win32.SafeHandles
Imports System.Security.AccessControl

Class PathTraversal
    Public Shared Sub Run(input As String, fileMode As FileMode, handle As IntPtr, access As FileAccess,
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

            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        [DataRow("StreamReader(\"\")")]
        [DataRow("StreamReader(\"\", flag)")]
        [DataRow("StreamReader(\"\", encoding)")]
        [DataRow("StreamReader(\"\", encoding, flag)")]
        [DataRow("StreamReader(\"\", encoding, flag, digit)")]

        [DataRow("StreamWriter(\"\")")]
        [DataRow("StreamWriter(\"\", false)")]
        [DataRow("StreamWriter(\"\", false, encoding)")]
        [DataRow("StreamWriter(\"\", false, encoding, digit)")]
        [DataRow("StreamWriter(\"\", false, System.Text.Encoding.ASCII, digit)")]
        [DataRow("StreamWriter(\"\", false, encoding, 10)")]

        [DataRow("FileStream(IntPtr.Zero, FileAccess.Read)")]
        [DataRow("FileStream(IntPtr.Zero, FileAccess.Read, flag)")]
        [DataRow("FileStream(\"\",        FileMode.CreateNew)")]

        [DataRow("FileStream(default(SafeFileHandle), FileAccess.Read)")]
        [DataRow("FileStream(default(SafeFileHandle), FileAccess.Read, digit, flag)")]

        [DataRow("FileStream(\"\", FileMode.CreateNew)")]
        [DataRow("FileStream(\"\", FileMode.CreateNew, FileAccess.Read)")]
        [DataRow("FileStream(\"\", FileMode.CreateNew, FileAccess.Read,         FileShare.Read)")]
        [DataRow("FileStream(\"\", FileMode.CreateNew, FileAccess.Read,         FileShare.Read, digit)")]
        [DataRow("FileStream(\"\", FileMode.CreateNew, FileAccess.Read,         FileShare.Read, digit, flag)")]
        [DataRow("FileStream(\"\", FileMode.CreateNew, FileAccess.Read,         FileShare.Read, digit, FileOptions.None)")]
        [DataRow("FileStream(\"\", FileMode.CreateNew, FileSystemRights.Read,   FileShare.Read, digit, FileOptions.None, default(FileSecurity))")]
        [DataTestMethod]
        public async Task PathTraversalNewObjectConst(string sink)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System;
    using System.IO;
    using Microsoft.Win32.SafeHandles;
    using System.Security.AccessControl;
#pragma warning restore 8019

class PathTraversal
{{
    public static void Run(bool flag, int digit, System.Text.Encoding encoding)
    {{
#pragma warning disable 618
        new {sink};
#pragma warning restore 618
    }}
}}
";

            sink = Regex.Replace(sink, "default\\(([^\\)]*)\\)", "DirectCast(Nothing, $1)");
            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System
    Imports System.IO
    Imports Microsoft.Win32.SafeHandles
    Imports System.Security.AccessControl
#Enable Warning BC50001

Class PathTraversal
    Public Shared Sub Run(flag As Boolean, digit As Int32, encoding As System.Text.Encoding)
#Disable Warning BC40000
        Dim sr As New {sink}
#Enable Warning BC40000
    End Sub
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }

        [DataRow("XmlReader.Create(input)")]
        [DataRow("XmlReader.Create(input, new XmlReaderSettings())")]
        [DataRow("XmlReader.Create(input, new XmlReaderSettings(), default(XmlParserContext))")]
        [DataTestMethod]
        public async Task PathTraversalXmlReader(string sink)
        {
            var cSharpTest = $@"
using System.Xml;

class PathTraversal
{{
    public static void Run(string input)
    {{
        var reader = {sink};
    }}
}}
";

            sink = sink.Replace("null", "Nothing");
            sink = Regex.Replace(sink, "default\\(([^\\)]*)\\)", "DirectCast(Nothing, $1)");
            var visualBasicTest = $@"
Imports System.Xml

Class PathTraversal
    Public Shared Sub Run(input As String)
        Dim reader As XMLReader = {sink}
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

        [DataRow("XmlReader.Create(\"\")")]
        [DataRow("XmlReader.Create(\"\", settings)")]
        [DataRow("XmlReader.Create(\"\", settings, context)")]
        [DataTestMethod]
        public async Task PathTraversalXmlReaderConst(string sink)
        {
            var cSharpTest = $@"
using System.Xml;

class PathTraversal
{{
    public static void Run(XmlReaderSettings settings, XmlParserContext context)
    {{
        var reader = {sink};
    }}
}}
";

            sink                = sink.Replace("null", "Nothing");
            sink                = Regex.Replace(sink, "default\\(([^\\)]*)\\)", "DirectCast(Nothing, $1)");
            var visualBasicTest = $@"
Imports System.Xml

Class PathTraversal
    Public Shared Sub Run(settings As XmlReaderSettings, context As XmlParserContext)
        Dim reader As XMLReader = {sink}
    End Sub
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }
    }
}
