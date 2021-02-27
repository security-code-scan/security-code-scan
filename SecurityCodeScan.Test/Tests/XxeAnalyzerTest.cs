using System.Collections.Generic;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.Web.XmlTransform;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test.XXE
{
    [TestClass]
    public class XxeAnalyzerDotNetCoreTest : XxeAnalyzerTestBase
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            if (language == LanguageNames.CSharp)
                return new DiagnosticAnalyzer[] { new XxeDiagnosticAnalyzerCSharp() };
            else
                return new DiagnosticAnalyzer[] { new XxeDiagnosticAnalyzerVisualBasic() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Http.HttpContext).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.ControllerBase).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Mvc.Controller).Assembly.Location),
            MetadataReference.CreateFromFile(Assembly.Load("netstandard, Version=2.0.0.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51")
                                                     .Location)
        };

        /// <summary> XML parsing vulnerable to XXE </summary>
        private readonly DiagnosticResult[] Expected =
        {
            new DiagnosticResult { Id = "SCS0007", Severity = DiagnosticSeverity.Warning }
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectUnsafeResolver()
        {
            var cSharpTest = $@"
using Microsoft.AspNetCore.Mvc;
using System.IO;
using System.Xml;

namespace VulnerableApp
{{
    public class TestController : Controller
    {{
        public void ControllerMethod()
        {{
            var xml = """";

            using (var streamReader = new StreamReader(HttpContext.Request.Body))
            {{
                xml = streamReader.ReadToEnd();
            }}

            var xmlDoc = new XmlDocument();
            xmlDoc.XmlResolver = new XmlUrlResolver();
            xmlDoc.LoadXml(xml);
        }}
    }}
}}
";

            var visualBasicTest = @"
Imports Microsoft.AspNetCore.Mvc
Imports System.IO
Imports System.Xml

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller

        Public Sub ControllerMethod()
            Dim xml = """"

            Using streamReader = New StreamReader(HttpContext.Request.Body)
                xml = streamReader.ReadToEnd()
            End Using

            Dim xmlDoc = New XmlDocument()
            xmlDoc.XmlResolver = New XmlUrlResolver()
            xmlDoc.LoadXml(xml)
        End Sub
    End Class
End Namespace
";
            await VerifyCSharpDiagnostic(cSharpTest, Expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected).ConfigureAwait(false);
        }
    }

    [TestClass]
    public class XxeAnalyzerTest : XxeAnalyzerTestBase
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            if (language == LanguageNames.CSharp)
                return new DiagnosticAnalyzer[] { new XxeDiagnosticAnalyzerCSharp() };
            else
                return new DiagnosticAnalyzer[] { new XxeDiagnosticAnalyzerVisualBasic() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(XmlFileInfoDocument).Assembly.Location),
        };

        /// <summary> XML parsing vulnerable to XXE </summary>
        private readonly DiagnosticResult[] Expected =
        {
            new DiagnosticResult { Id = "SCS0007", Severity = DiagnosticSeverity.Warning }
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestMethod]
        public async Task XPathDocument_XmlReader()
        {
            string cSharpTest = @"
using System.Xml;
using System.Xml.XPath;

public class Xxe
{
    public static void parseUpload(XmlReader path)
    {
        var document = new XPathDocument(path);
        var nav = document.CreateNavigator();
    }
}";

            string visualBasicTest = @"
Imports System.Xml
Imports System.Xml.XPath

Public Class Xxe
    Public Shared Sub parseUpload(path As XmlReader)
        Dim document As New XPathDocument(path)
        Dim nav = document.CreateNavigator()
    End Sub
End Class
";

            await VerifyNoWarnings(cSharpTest, visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("System.Xml.XPath",                     "XPathDocument")]
        [DataRow("Doc = System.Xml.XPath.XPathDocument", "Doc")]
        public async Task XPathDocument(string alias, string name)
        {
            string cSharpTest = $@"
using {alias};

public class Xxe
{{
    public static void parseUpload(string path)
    {{
        var document = new {name}(path);
        var nav = document.CreateNavigator();
    }}
}}";

            string visualBasicTest = $@"
Imports {alias}

Public Class Xxe
    Public Shared Sub parseUpload(path As String)
        Dim document As New {name}(path)
        Dim nav = document.CreateNavigator()
    End Sub
End Class
";

            await VerifyDiagnosticSafeUnsafe(cSharpTest, visualBasicTest, Expected).ConfigureAwait(false);

            const string cSharpTest2 = @"
using System.Xml.XPath;

public class Xxe2
{
    public static void parseUpload(string path)
    {
        new XPathDocument(path).CreateNavigator();
    }
}";

            const string visualBasicTest2 = @"
Imports System.Xml.XPath

Public Class Xxe2
    Public Shared Sub parseUpload(path As String)
        Call New XPathDocument(path).CreateNavigator()
    End Sub
End Class
";

            await VerifyDiagnosticSafeUnsafe(cSharpTest2, visualBasicTest2, Expected).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataRow("new StringReader(path)", Warnings.OnFramework)]
        [DataRow("XmlReader.Create (path, new XmlReaderSettings (){DtdProcessing = DtdProcessing.Parse})", Warnings.OnFramework)]
        [DataTestMethod]
        public async Task XmlSchemaRead(string createReader, Warnings expectWarnings)
        {
            string vbCreateReader = createReader.CSharpReplaceToVBasic();

            var cSharpTest = $@"
#pragma warning disable 8019
    using System.Xml.Schema;
    using System.IO;
    using System.Xml;
#pragma warning restore 8019

public class Xxe
{{
    public static void parseUpload(string path)
    {{
        var tr = {createReader};
        var schema = XmlSchema.Read(tr, null);
    }}
}}";

            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System.Xml.Schema
    Imports System.IO
    Imports System.Xml
#Enable Warning BC50001

Public Class Xxe
    Public Shared Sub parseUpload(path As String)
        Dim tr = {vbCreateReader}
        Dim schema = XmlSchema.Read(tr, Nothing)
    End Sub
End Class
";
            await Verify(cSharpTest, visualBasicTest, Expected, expectWarnings).ConfigureAwait(false);

            string cSharpTest2 = $@"
#pragma warning disable 8019
    using System.Xml.Schema;
    using System.IO;
    using System.Xml;
#pragma warning restore 8019

public class Xxe2
{{
    public static void parseUpload(string path)
    {{
        XmlSchema.Read({createReader}, null);
    }}
}}";

            var visualBasicTest2 = $@"
#Disable Warning BC50001
    Imports System.Xml.Schema
    Imports System.IO
    Imports System.Xml
#Enable Warning BC50001

Public Class Xxe2
    Public Shared Sub parseUpload(path As String)
        XmlSchema.Read({vbCreateReader}, Nothing)
    End Sub
End Class
";
            await Verify(cSharpTest2, visualBasicTest2, Expected, expectWarnings).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataRow("XmlDocument",        "Load(text)",      Warnings.OnFramework)]
        [DataRow("XmlDocument",        "LoadXml(text)",   Warnings.OnFramework)]
        [DataRow("XmlDocument",        "InnerXml = text", Warnings.OnFramework)]
        [DataRow("ConfigXmlDocument",  "Load(text)",      Warnings.OnFramework)]
        [DataRow("ConfigXmlDocument",  "LoadXml(text)",   Warnings.OnFramework)]
        [DataRow("XmlDataDocument",    "Load(text)",      Warnings.OnFramework)]
        [DataRow("XmlDataDocument",    "LoadXml(text)",   Warnings.OnFramework)]
        [DataRow("DerivedXmlDocument", "Load(text)",      Warnings.None)] // safe design is assumed
        [DataRow("DerivedXmlDocument", "LoadXml(text)",   Warnings.None)] // safe design is assumed
        [DataRow("XmlDocument",        "InnerXml = text", Warnings.OnFramework)]
        [DataTestMethod]
        public async Task XmlDocumentDefaultsClassMember(string className, string sink, Warnings expectWarnings)
        {
            var cSharpTest3 = $@"
#pragma warning disable 8019
    using System.Xml;
    using System.Configuration;
#pragma warning restore 8019

public class DerivedXmlDocument : XmlDocument {{}}

public class Xxe
{{
#pragma warning disable 618
    private static {className} Parser = new {className}();
#pragma warning restore 618

    public static void parseUpload(string text)
    {{
        Parser.{sink};
    }}
}}";

            var visualBasicTest3 = !sink.Contains("=") ? $@"
#Disable Warning BC50001
    Imports System.Xml
    Imports System.Configuration
#Enable Warning BC50001

Public Class DerivedXmlDocument
    Inherits XmlDocument
End Class

Public Class Xxe
#Disable Warning BC40000
    Private Shared Parser As {className} = New {className}()
#Enable Warning BC40000

    Public Shared Sub parseUpload(text As String)
        Parser.{sink}
    End Sub
End Class
" : null; // todo: how to set property of a temporary object in VB?

            /*
                todo: different VB specific field declaration syntax is not recognized

                e.g. this does not work:
                Private Shared Parser As New XmlDocument()I
             */

            await Verify(cSharpTest3, visualBasicTest3, Expected, expectWarnings).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataRow("XmlDocument",         "?.Load(text)",     Warnings.OnFramework)]
        [DataRow("XmlDocument",         ".Load(text)",      Warnings.OnFramework)]
        [DataRow("XmlDocument",         ".LoadXml(text)",   Warnings.OnFramework)]
        [DataRow("XmlDocument",         ".InnerXml = text", Warnings.OnFramework)]
        // Special case: Load is overridden and resolver is set to null in all versions
        [DataRow("ConfigXmlDocument",   ".Load(text)",      Warnings.None)]
        [DataRow("ConfigXmlDocument",   ".LoadXml(text)",   Warnings.OnFramework)]
        [DataRow("XmlDataDocument",     ".Load(text)",      Warnings.OnFramework)]
        // Special case XmlDataDocument.LoadXml throws NotSupportedException
        [DataRow("XmlDataDocument",     ".LoadXml(text)",   Warnings.None)]
        [DataRow("DerivedXmlDocument",  ".Load(text)",      Warnings.None)] // safe design is assumed
        [DataRow("DerivedXmlDocument",  ".LoadXml(text)",   Warnings.None)] // safe design is assumed
        [DataRow("XmlDocument",         ".InnerXml = text", Warnings.OnFramework)]
        [DataRow("XmlFileInfoDocument", ".Load(text)",      Warnings.OnFramework)]
        [DataRow("XmlTransformableDocument", ".Load(text)", Warnings.OnFramework)]
        [DataTestMethod]
        public async Task XmlDocumentDefaults(string className, string sink, Warnings expectWarnings)
        {
            var cSharpTest = $@"
#pragma warning disable 8019
    using System.Xml;
    using System.Configuration;
    using Microsoft.Web.XmlTransform;
#pragma warning restore 8019

public class DerivedXmlDocument : XmlDocument {{}}

public class Xxe
{{
    public static void parseUpload(string text)
    {{
#pragma warning disable 618
        var xmlDoc = new {className}();
        xmlDoc{sink};
#pragma warning restore 618
    }}
}}";

            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System.Xml
    Imports System.Configuration
    Imports Microsoft.Web.XmlTransform
#Enable Warning BC50001

Public Class DerivedXmlDocument
    Inherits XmlDocument
End Class

Public Class Xxe
    Public Shared Sub parseUpload(text As String)
#Disable Warning BC40000
        Dim xmlDoc As New {className}()
        xmlDoc{sink}
#Enable Warning BC40000
    End Sub
End Class
";

            await Verify(cSharpTest, visualBasicTest, Expected, expectWarnings).ConfigureAwait(false);

            var cSharpTest2 = $@"
#pragma warning disable 8019
    using System.Xml;
    using System.Configuration;
    using Microsoft.Web.XmlTransform;
#pragma warning restore 8019

public class DerivedXmlDocument : XmlDocument {{}}

public class Xxe2
{{
    public static void parseUpload(string text)
    {{
#pragma warning disable 618
        new {className}(){sink};
#pragma warning restore 618
    }}
}}";

            var visualBasicTest2 = !sink.Contains("=") ? $@"
#Disable Warning BC50001
    Imports System.Xml
    Imports System.Configuration
    Imports Microsoft.Web.XmlTransform
#Enable Warning BC50001

Public Class DerivedXmlDocument
    Inherits XmlDocument
End Class

Public Class Xxe2
    Public Shared Sub parseUpload(text As String)
#Disable Warning BC40000
        Call New {className}(){sink}
#Enable Warning BC40000
    End Sub
End Class
" : null; // todo: how to set property of a temporary object in VB?

            await Verify(cSharpTest2, visualBasicTest2, Expected, expectWarnings).ConfigureAwait(false);
        }

        private const string SecureResolverText = "new XmlSecureResolver(new XmlUrlResolver(), \"http://myLocalSite/\")";

        [TestCategory("Detect")]
        [DataRow("XmlDocument",       "()",     "XmlResolver", "null",                 "Load(text)",      Warnings.None)]
        [DataRow("XmlDocument",       "()",     "XmlResolver", SecureResolverText,     "Load(text)",      Warnings.None)]
        [DataRow("XmlDocument",       "()",     "XmlResolver", "new XmlUrlResolver()", "Load(text)",      Warnings.Always)]
        [DataRow("XmlDocument",       "()",     "XmlResolver", "null",                 "LoadXml(text)",   Warnings.None)]
        [DataRow("XmlDocument",       "()",     "XmlResolver", SecureResolverText,     "LoadXml(text)",   Warnings.None)]
        [DataRow("XmlDocument",       "()",     "XmlResolver", "new XmlUrlResolver()", "LoadXml(text)",   Warnings.Always)]
        [DataRow("XmlDocument",       "()",     "XmlResolver", "null",                 "InnerXml = text", Warnings.None)]
        [DataRow("XmlDocument",       "()",     "XmlResolver", SecureResolverText,     "InnerXml = text", Warnings.None)]
        [DataRow("XmlDocument",       "()",     "XmlResolver", "new XmlUrlResolver()", "InnerXml = text", Warnings.Always)]
        [DataRow("ConfigXmlDocument", "()",     "XmlResolver", "null",                 "Load(text)",      Warnings.None)]
        [DataRow("ConfigXmlDocument", "()",     "XmlResolver", SecureResolverText,     "Load(text)",      Warnings.None)]
        // special case, ConfigXmlDocument.Load doesn't use the resolver
        [DataRow("ConfigXmlDocument", "()",     "XmlResolver", "new XmlUrlResolver()", "Load(text)",      Warnings.None)]
        [DataRow("ConfigXmlDocument", "()",     "XmlResolver", "null",                 "LoadXml(text)",   Warnings.None)]
        [DataRow("ConfigXmlDocument", "()",     "XmlResolver", SecureResolverText,     "LoadXml(text)",   Warnings.None)]
        [DataRow("ConfigXmlDocument", "()",     "XmlResolver", "new XmlUrlResolver()", "LoadXml(text)",   Warnings.Always)]
        [DataRow("XmlDataDocument",   "()",     "XmlResolver", "null",                 "Load(text)",      Warnings.None)]
        [DataRow("XmlDataDocument",   "()",     "XmlResolver", SecureResolverText,     "Load(text)",      Warnings.None)]
        [DataRow("XmlDataDocument",   "()",     "XmlResolver", "new XmlUrlResolver()", "Load(text)",      Warnings.Always)]
        [DataRow("XmlTextReader",     "(text)", "XmlResolver", "null",                 "Read()",          Warnings.None)]
        [DataRow("XmlTextReader",     "(text)", "XmlResolver", SecureResolverText,     "Read()",          Warnings.None)]
        [DataRow("XmlTextReader",     "(text)", "XmlResolver", "new XmlUrlResolver()", "Read()",          Warnings.Always)]
        [DataRow("XmlTransformableDocument", "()", "XmlResolver", "null",                 "Load(text)", Warnings.None)]
        [DataRow("XmlTransformableDocument", "()", "XmlResolver", SecureResolverText,     "Load(text)", Warnings.None)]
        [DataRow("XmlTransformableDocument", "()", "XmlResolver", "new XmlUrlResolver()", "Load(text)", Warnings.Always)]
        [DataRow("XmlFileInfoDocument",      "()", "XmlResolver", "null",                 "Load(text)", Warnings.None)]
        [DataRow("XmlFileInfoDocument",      "()", "XmlResolver", SecureResolverText,     "Load(text)", Warnings.None)]
        [DataRow("XmlFileInfoDocument",      "()", "XmlResolver", "new XmlUrlResolver()", "Load(text)", Warnings.Always)]
        [DataTestMethod]
        public async Task XmlDocumentBased(string className, string constructorParams, string property, string value, string sink, Warnings expectWarnings)
        {
            var vbValue = value.CSharpReplaceToVBasic();

            var cSharpTest = $@"
#pragma warning disable 8019
    using System.Xml;
    using System.Configuration;
    using Microsoft.Web.XmlTransform;
#pragma warning restore 8019

public class Xxe
{{
    public static void parseUpload(string text)
    {{
#pragma warning disable 618
        var xmlDoc = new {className}{constructorParams};
        xmlDoc.{property} = {value};
        xmlDoc.{sink};
#pragma warning restore 618
    }}
}}";

            var visualBasicTest = $@"
#Disable Warning BC50001
    Imports System.Xml
    Imports System.Configuration
    Imports Microsoft.Web.XmlTransform
#Enable Warning BC50001

Public Class Xxe
    Public Shared Sub parseUpload(text As String)
#Disable Warning BC40000
        Dim xmlDoc As New {className}{constructorParams}
        xmlDoc.{property} = {vbValue}
        xmlDoc.{sink}
#Enable Warning BC40000
    End Sub
End Class
";

            await Verify(cSharpTest, visualBasicTest, Expected, expectWarnings).ConfigureAwait(false);

            var cSharpTest2 = $@"
#pragma warning disable 8019
    using System.Xml;
    using System.Configuration;
    using Microsoft.Web.XmlTransform;
#pragma warning restore 8019

public class Xxe2
{{
    public static void parseUpload(string text)
    {{
#pragma warning disable 618
        var xmlDoc = new {className}{constructorParams} {{{property} = {value}}};
        xmlDoc.{sink};
#pragma warning restore 618
    }}
}}";

            var visualBasicTest2 = $@"
#Disable Warning BC50001
    Imports System.Xml
    Imports System.Configuration
    Imports Microsoft.Web.XmlTransform
#Enable Warning BC50001

Public Class Xxe2
    Public Shared Sub parseUpload(text As String)
#Disable Warning BC40000
        Dim xmlDoc As New {className}{constructorParams} With {{.{property} = {vbValue}}}
        xmlDoc.{sink}
#Enable Warning BC40000
    End Sub
End Class
";
            await Verify(cSharpTest2, visualBasicTest2, Expected, expectWarnings).ConfigureAwait(false);

            var cSharpTest3 = $@"
#pragma warning disable 8019
    using System.Xml;
    using System.Configuration;
    using Microsoft.Web.XmlTransform;
#pragma warning restore 8019

public class Xxe3
{{
    public static void parseUpload(string text)
    {{
#pragma warning disable 618
        new {className}{constructorParams} {{{property} = {value}}}.{sink};
#pragma warning restore 618
    }}
}}";

            var visualBasicTest3 = !sink.Contains("=") ? $@"
#Disable Warning BC50001
    Imports System.Xml
    Imports System.Configuration
    Imports Microsoft.Web.XmlTransform
#Enable Warning BC50001

Public Class Xxe3
    Public Shared Sub parseUpload(text As String)
#Disable Warning BC40000
        Call New {className}{constructorParams} With {{.{property} = {vbValue}}}.{sink}
#Enable Warning BC40000
    End Sub
End Class
"
                                       : null; // todo: how to set property of a temporary object in VB?
            await Verify(cSharpTest3, visualBasicTest3, Expected, expectWarnings).ConfigureAwait(false);

            var cSharpTest4 = $@"
#pragma warning disable 8019
    using System.Xml;
    using System.Configuration;
    using Microsoft.Web.XmlTransform;
#pragma warning restore 8019

public class Xxe4
{{
#pragma warning disable 618
    public static void parseUpload(string text, {className} xmlDoc)
    {{
        xmlDoc.{property} = {value};
        xmlDoc.{sink};
#pragma warning restore 618
    }}
}}";

            var visualBasicTest4 = $@"
#Disable Warning BC50001
    Imports System.Xml
    Imports System.Configuration
    Imports Microsoft.Web.XmlTransform
#Enable Warning BC50001

Public Class Xxe
#Disable Warning BC40000
    Public Shared Sub parseUpload(text As String, xmlDoc As {className})
        xmlDoc.{property} = {vbValue}
        xmlDoc.{sink}
#Enable Warning BC40000
    End Sub
End Class
";
            await Verify(cSharpTest4, visualBasicTest4, Expected, expectWarnings).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task XmlTextReaderFile()
        {
            const string cSharpTest = @"
using System.Xml;

public class Xxe
{
    public static void parseUpload(string path)
    {
        var reader = new XmlTextReader(path);
        reader.Read();
    }
}";

            const string visualBasicTest = @"
Imports System.Xml

Public Class Xxe
    Public Shared Sub parseUpload(path As String)
        Dim reader = new XmlTextReader(path)
        reader.Read()
    End Sub
End Class
";
            await VerifyDiagnosticSafeUnsafe(cSharpTest, visualBasicTest, Expected).ConfigureAwait(false);

            const string cSharpTest2 = @"
using System.Xml;

public class Xxe2
{
    public static void parseUpload(string path)
    {
        new XmlTextReader(path).Read();
    }
}";

            const string visualBasicTest2 = @"
Imports System.Xml

Public Class Xxe2
    Public Shared Sub parseUpload(path As String)
        Call new XmlTextReader(path).Read()
    End Sub
End Class
";
            await VerifyDiagnosticSafeUnsafe(cSharpTest2, visualBasicTest2, Expected).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task XmlTextReaderDerived()
        {
            const string cSharpTest = @"
using System.Xml;

public class DerivedXmlTextReader : XmlTextReader
{
    public DerivedXmlTextReader(string path) : base(path) {}
}

public class Xxe
{
    public static void parseUpload(string path)
    {
        var reader = new DerivedXmlTextReader(path);
        reader.Read();
    }
}";

            const string visualBasicTest = @"
Imports System.Xml

Public Class DerivedXmlTextReader
    Inherits XmlTextReader
    Public Sub New(path As String)
        MyBase.New(path)
    End Sub
End Class

Public Class Xxe
    Public Shared Sub parseUpload(path As String)
        Dim reader = new DerivedXmlTextReader(path)
        reader.Read()
    End Sub
End Class
";
            // safe design is assumed
            await VerifyNoWarnings(cSharpTest, visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task XmlTextReaderString()
        {
            const string cSharpTest = @"
using System.Xml;
using System.IO;

public class Xxe
{
    public static void parseUpload(string xmlContent)
    {
        var reader = new XmlTextReader(new StringReader(xmlContent));
        reader.Read();
    }
}";

            const string visualBasicTest = @"
Imports System.Xml
Imports System.IO

Public Class Xxe
    Public Shared Sub parseUpload(xmlContent As String)
        Dim reader = new XmlTextReader(new StringReader(xmlContent))
        reader.Read()
    End Sub
End Class
";
            await VerifyDiagnosticSafeUnsafe(cSharpTest, visualBasicTest, Expected).ConfigureAwait(false);

            const string cSharpTest2 = @"
using System.Xml;
using System.IO;

public class Xxe2
{
    public static void parseUpload(string xmlContent)
    {
        new XmlTextReader(new StringReader(xmlContent)).Read();
    }
}";

            const string visualBasicTest2 = @"
Imports System.Xml
Imports System.IO

Public Class Xxe2
    Public Shared Sub parseUpload(xmlContent As String)
        Call new XmlTextReader(new StringReader(xmlContent)).Read()
    End Sub
End Class
";
            await VerifyDiagnosticSafeUnsafe(cSharpTest2, visualBasicTest2, Expected).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [DataRow("XmlResolver",   "null")]
        [DataRow("XmlResolver",   SecureResolverText)]
        [DataRow("ProhibitDtd",   "true")]
        [DataRow("DtdProcessing", "DtdProcessing.Prohibit")]
        [DataRow("DtdProcessing", "0")]
        [DataRow("DtdProcessing", "DtdProcessing.Ignore")]
        [DataRow("DtdProcessing", "(DtdProcessing)1")]
        [DataTestMethod]
        public async Task XmlTextReaderStringSafeSettings(string property, string value)
        {
            var vbValue = value.CSharpReplaceToVBasic();

            var cSharpTest = $@"
using System.Xml;
using System.IO;

public class Xxe
{{
    public static void parseUpload(string xmlContent)
    {{
        var xmlDoc = new XmlTextReader(new StringReader(xmlContent));
#pragma warning disable 618
        xmlDoc.{property} = {value};
#pragma warning restore 618
        xmlDoc.Read();
    }}
}}";

            var visualBasicTest = $@"
Imports System.Xml
Imports System.IO

Public Class Xxe
    Public Shared Sub parseUpload(xmlContent As String)
        Dim reader = new XmlTextReader(new StringReader(xmlContent))
#Disable Warning BC40000
        reader.{property} = {vbValue}
#Enable Warning BC40000
        reader.Read()
    End Sub
End Class
";
            await VerifyNoWarnings(cSharpTest, visualBasicTest).ConfigureAwait(false);

            var cSharpTest2 = $@"
using System.Xml;
using System.IO;

public class Xxe2
{{
    public static void parseUpload(string xmlContent)
    {{
#pragma warning disable 618
        var xmlDoc = new XmlTextReader(new StringReader(xmlContent)) {{{property} = {value}}};
#pragma warning restore 618
        xmlDoc.Read();
    }}
}}";

            var visualBasicTest2 = $@"
Imports System.Xml
Imports System.IO

Public Class Xxe2
    Public Shared Sub parseUpload(xmlContent As String)
#Disable Warning BC40000
        Dim reader = new XmlTextReader(new StringReader(xmlContent)) With {{.{property} = {vbValue}}}
#Enable Warning BC40000
        reader.Read()
    End Sub
End Class
";
            await VerifyNoWarnings(cSharpTest2, visualBasicTest2).ConfigureAwait(false);

            var cSharpTest3 = $@"
using System.Xml;
using System.IO;

public class Xxe3
{{
    public static void parseUpload(string xmlContent)
    {{
#pragma warning disable 618
        new XmlTextReader(new StringReader(xmlContent)) {{{property} = {value}}}.Read();
#pragma warning restore 618
    }}
}}";

            var visualBasicTest3 = $@"
Imports System.Xml
Imports System.IO

Public Class Xxe3
    Public Shared Sub parseUpload(xmlContent As String)
#Disable Warning BC40000
        Call new XmlTextReader(new StringReader(xmlContent)) With {{.{property} = {vbValue}}}.Read()
#Enable Warning BC40000
    End Sub
End Class
";
            await VerifyNoWarnings(cSharpTest3, visualBasicTest3).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task XmlReaderCreateDefaultXmlReaderSettings()
        {
            const string cSharpTest = @"
using System.Xml;

public class Xxe
{
    public static void parseUpload(string path)
    {
        var settings = new XmlReaderSettings();
        var reader = XmlReader.Create(path, settings);
    }
}";

            const string visualBasicTest = @"
Imports System.Xml

Public Class Xxe
    Public Shared Sub parseUpload(path As String)
        Dim settings = new XmlReaderSettings()
        Dim reader = XmlReader.Create(path, settings)
    End Sub
End Class
";
            await VerifyNoWarnings(cSharpTest, visualBasicTest).ConfigureAwait(false);

            const string cSharpTest2 = @"
using System.Xml;

public class Xxe2
{
    public static void parseUpload(string path)
    {
        var reader = XmlReader.Create(path);
    }
}";

            const string visualBasicTest2 = @"
Imports System.Xml

Public Class Xxe2
    Public Shared Sub parseUpload(path As String)
        Dim reader = XmlReader.Create(path)
    End Sub
End Class
";

            await VerifyNoWarnings(cSharpTest2, visualBasicTest2).ConfigureAwait(false);

            const string cSharpTest3 = @"
using System.Xml;
using System.IO;

public class Xxe3
{
    public static void parseUpload(string path)
    {
        var reader = XmlReader.Create(new StringReader(path));
        XmlReader.Create(new StringReader(path));
    }
}";

            const string visualBasicTest3 = @"
Imports System.Xml
Imports System.IO

Public Class Xxe3
    Public Shared Sub parseUpload(path As String)
        Dim reader = XmlReader.Create(new StringReader(path))
        XmlReader.Create(new StringReader(path))
    End Sub
End Class
";

            await VerifyNoWarnings(cSharpTest3, visualBasicTest3).ConfigureAwait(false);

            const string cSharpTest4 = @"
using System.Xml;

public class Xxe4
{
    public static void parseUpload(string path)
    {
        var reader = XmlTextReader.Create(path); // access to a static member of a type via a derived type
    }
}";

            const string visualBasicTest4 = @"
Imports System.Xml

Public Class Xxe4
    Public Shared Sub parseUpload(path As String)
        Dim reader = XmlTextReader.Create(path)
    End Sub
End Class
";

            await VerifyNoWarnings(cSharpTest4, visualBasicTest4).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [DataRow("XmlResolver",   "null")]
        [DataRow("XmlResolver",   SecureResolverText)]
        [DataRow("ProhibitDtd",   "true")]
        [DataRow("DtdProcessing", "DtdProcessing.Prohibit")]
        [DataRow("DtdProcessing", "0")]
        [DataRow("DtdProcessing", "DtdProcessing.Ignore")]
        [DataRow("DtdProcessing", "(DtdProcessing)1")]
        [DataTestMethod]
        public async Task XmlReaderCreateDtdProcessingDisabled(string property, string value)
        {
            var vbValue = value.CSharpReplaceToVBasic();

            var cSharpTest = $@"
using System.Xml;

public class Xxe
{{
    public static void parseUpload(string path)
    {{
        XmlReaderSettings settings = new XmlReaderSettings();
#pragma warning disable 618
        settings.{property} = {value};
#pragma warning restore 618
        XmlReader reader = XmlReader.Create(path, settings);
    }}
}}";

            var visualBasicTest = $@"
Imports System.Xml

Public Class Xxe
    Public Shared Sub parseUpload(path As String)
        Dim settings = new XmlReaderSettings()
#Disable Warning BC40000
        settings.{property} = {vbValue}
#Enable Warning BC40000
        Dim reader = XmlReader.Create(path, settings)
    End Sub
End Class
";
            await VerifyNoWarnings(cSharpTest, visualBasicTest).ConfigureAwait(false);

            var cSharpTest2 = $@"
using System.Xml;

public class Xxe2
{{
    public static void parseUpload(string path)
    {{
#pragma warning disable 618
        XmlReaderSettings settings = new XmlReaderSettings {{{property} = {value}}};
#pragma warning restore 618
        XmlReader reader = XmlReader.Create(path, settings);
    }}
}}";

            var visualBasicTest2 = $@"
Imports System.Xml

Public Class Xxe2
    Public Shared Sub parseUpload(path As String)
#Disable Warning BC40000
        Dim settings = new XmlReaderSettings() With {{.{property} = {vbValue}}}
#Enable Warning BC40000
        Dim reader = XmlReader.Create(path, settings)
    End Sub
End Class
";
            await VerifyNoWarnings(cSharpTest2, visualBasicTest2).ConfigureAwait(false);

            var cSharpTest3 = $@"
using System.Xml;

public class Xxe3
{{
    public static void parseUpload(string path)
    {{
#pragma warning disable 618
        XmlReader.Create(path, new XmlReaderSettings {{{property} = {value}}});
#pragma warning restore 618
    }}
}}";

            var visualBasicTest3 = $@"
Imports System.Xml

Public Class Xxe3
    Public Shared Sub parseUpload(path As String)
#Disable Warning BC40000
        XmlReader.Create(path, new XmlReaderSettings() With {{.{property} = {vbValue}}})
#Enable Warning BC40000
    End Sub
End Class
";
            await VerifyNoWarnings(cSharpTest3, visualBasicTest3).ConfigureAwait(false);

//            var cSharpTest4 = $@"
//using System.Xml;

//class Xxe4
//{{
//    private static XmlReaderSettings Settings = new XmlReaderSettings();

//    public static void parseUpload(string path)
//    {{
//#pragma warning disable 618
//        Settings.{property} = {value};
//#pragma warning restore 618
//        XmlReader reader = XmlReader.Create(path, Settings);
//    }}
//}}
//";

//            var visualBasicTest4 = $@"
//Imports System.Xml

//Class Xxe4
//    Private Shared Settings As XmlReaderSettings = New XmlReaderSettings()

//    Public Shared Sub parseUpload(path As String)
//#Disable Warning BC40000
//        Settings.{property} = {vbValue}
//#Enable Warning BC40000
//        Dim reader As XmlReader = XmlReader.Create(path, Settings)
//    End Sub
//End Class
//";
//            await VerifyNoWarnings(cSharpTest4, visualBasicTest4).ConfigureAwait(false);

//            var cSharpTest5 = $@"
//using System.Xml;

//class Xxe5
//{{
//#pragma warning disable 618
//    private static XmlReaderSettings Settings = new XmlReaderSettings {{{property} = {value}}};
//#pragma warning restore 618

//    public static void parseUpload(string path)
//    {{
//        XmlReader reader = XmlReader.Create(path, Settings);
//    }}
//}}
//";

//            var visualBasicTest5 = $@"
//Imports System.Xml

//Class Xxe5
//#Disable Warning BC40000
//    Private Shared Settings As New XmlReaderSettings With {{.{property} = {vbValue}}}
//#Enable Warning BC40000

//    Public Shared Sub parseUpload(path As String)
//        Dim reader As XmlReader = XmlReader.Create(path, Settings)
//    End Sub
//End Class
//";
//            await VerifyNoWarnings(cSharpTest5, visualBasicTest5).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataRow("ProhibitDtd   = false")]
        [DataRow("DtdProcessing = DtdProcessing.Parse")]
        [DataRow("DtdProcessing = (DtdProcessing)2")]
        [DataTestMethod]
        public async Task XmlReaderCreateDtdProcessingEnabled(string dtdProcessing)
        {
            var vbDtdProcessing = dtdProcessing.CSharpReplaceToVBasic();

            var cSharpTest = $@"
using System.Xml;

public class Xxe
{{
    public static void parseUpload(string path)
    {{
        XmlReaderSettings settings = new XmlReaderSettings();
#pragma warning disable 618
        settings.{dtdProcessing};
#pragma warning restore 618
        XmlReader reader = XmlReader.Create(path, settings);
    }}
}}";

            var visualBasicTest = $@"
Imports System.Xml

Public Class Xxe
    Public Shared Sub parseUpload(path As String)
        Dim settings = new XmlReaderSettings()
#Disable Warning BC40000
        settings.{vbDtdProcessing}
#Enable Warning BC40000
        Dim reader = XmlReader.Create(path, settings)
    End Sub
End Class
";
            await VerifyDiagnosticSafeUnsafe(cSharpTest, visualBasicTest, Expected).ConfigureAwait(false);

            var cSharpTest2 = $@"
using System.Xml;

public class Xxe2
{{
    public void TestMethod(string path)
    {{
#pragma warning disable 618
        XmlReaderSettings settings = new XmlReaderSettings(){{ {dtdProcessing} }};
#pragma warning restore 618
        XmlReader reader = XmlReader.Create(path, settings);
    }}
}}";

            var visualBasicTest2 = $@"
Imports System.Xml

Public Class Xxe2
    Public Shared Sub parseUpload(path As String)
#Disable Warning BC40000
        Dim settings = new XmlReaderSettings() With {{.{vbDtdProcessing}}}
#Enable Warning BC40000
        Dim reader = XmlReader.Create(path, settings)
    End Sub
End Class
";
            await VerifyDiagnosticSafeUnsafe(cSharpTest2, visualBasicTest2, Expected).ConfigureAwait(false);

            var cSharpTest3 = $@"
using System.Xml;

public class Xxe3
{{
    public void TestMethod(string path)
    {{
#pragma warning disable 618
        XmlReader.Create(path, new XmlReaderSettings(){{ {dtdProcessing} }});
#pragma warning restore 618
    }}
}}";

            var visualBasicTest3 = $@"
Imports System.Xml

Public Class Xxe3
    Public Shared Sub parseUpload(path As String)
#Disable Warning BC40000
        XmlReader.Create(path, new XmlReaderSettings() With {{.{vbDtdProcessing}}})
#Enable Warning BC40000
    End Sub
End Class
";
            await VerifyDiagnosticSafeUnsafe(cSharpTest3, visualBasicTest3, Expected).ConfigureAwait(false);
        }

        [TestCategory("False Positive")]
        [TestMethod]
        public async Task FalsePositives1()
        {
            // todo: Once fixed, try uncomment tests in XmlReaderCreateDtdProcessingDisabled

            var cSharpTest4 = $@"
using System.Xml;

public class Xxe4
{{
    private static XmlReaderSettings Settings = new XmlReaderSettings();

    public static void parseUpload(string path)
    {{
#pragma warning disable 618
        Settings.XmlResolver = {SecureResolverText};
#pragma warning restore 618
        XmlReader reader = XmlReader.Create(path, Settings);
    }}
}}
";

            var visualBasicTest4 = $@"
Imports System.Xml

Public Class Xxe4
    Private Shared Settings As XmlReaderSettings = New XmlReaderSettings()

    Public Shared Sub parseUpload(path As String)
#Disable Warning BC40000
        Settings.XmlResolver = {SecureResolverText}
#Enable Warning BC40000
        Dim reader As XmlReader = XmlReader.Create(path, Settings)
    End Sub
End Class
";

            await Verify(cSharpTest4, visualBasicTest4, Expected, Warnings.OnFramework).ConfigureAwait(false);
        }

        [TestCategory("False Positive")]
        [TestMethod]
        public async Task FalsePositives2()
        {
            // todo: Once fixed, try uncomment tests in XmlReaderCreateDtdProcessingDisabled

            const string cSharpTest4 = @"
using System.Xml;

public class Xxe4
{
    private static XmlReaderSettings Settings = new XmlReaderSettings();

    public static void parseUpload(string path)
    {
#pragma warning disable 618
        Settings.XmlResolver = null;
#pragma warning restore 618
        XmlReader reader = XmlReader.Create(path, Settings);
    }
}
";

            const string visualBasicTest4 = @"
Imports System.Xml

Public Class Xxe4
    Private Shared Settings As XmlReaderSettings = New XmlReaderSettings()

    Public Shared Sub parseUpload(path As String)
#Disable Warning BC40000
        Settings.XmlResolver = Nothing
#Enable Warning BC40000
        Dim reader As XmlReader = XmlReader.Create(path, Settings)
    End Sub
End Class
";

            await Verify(cSharpTest4, visualBasicTest4, Expected, Warnings.OnFramework).ConfigureAwait(false);
        }

        [TestCategory("False Positive")]
        [TestMethod]
        public async Task FalsePositives3()
        {
            // todo: Once fixed, try uncomment tests in XmlReaderCreateDtdProcessingDisabled

            var cSharpTest5 = @"
using System.Xml;

public class Xxe5
{
#pragma warning disable 618
    private static XmlReaderSettings Settings = new XmlReaderSettings {DtdProcessing = (DtdProcessing)1};
#pragma warning restore 618

    public static void parseUpload(string path)
    {
        XmlReader reader = XmlReader.Create(path, Settings);
    }
}
";

            var visualBasicTest5 = @"
Imports System.Xml

Public Class Xxe5
#Disable Warning BC40000
    Private Shared Settings As New XmlReaderSettings With {.DtdProcessing = DirectCast(1, DtdProcessing)}
#Enable Warning BC40000

    Public Shared Sub parseUpload(path As String)
        Dim reader As XmlReader = XmlReader.Create(path, Settings)
    End Sub
End Class
";

            await Verify(cSharpTest5, visualBasicTest5, Expected, Warnings.OnFramework).ConfigureAwait(false);
        }

        [TestCategory("False Positive")]
        [TestMethod]
        public async Task FalsePositives4()
        {
            // todo: Once fixed, try uncomment tests in XmlReaderCreateDtdProcessingDisabled

            var cSharpTest5 = @"
using System.Xml;

public class Xxe5
{
#pragma warning disable 618
    private static XmlReaderSettings Settings = new XmlReaderSettings {DtdProcessing = 0};
#pragma warning restore 618

    public static void parseUpload(string path)
    {
        XmlReader reader = XmlReader.Create(path, Settings);
    }
}
";

            var visualBasicTest5 = @"
Imports System.Xml

Public Class Xxe5
#Disable Warning BC40000
    Private Shared Settings As New XmlReaderSettings With {.DtdProcessing = 0}
#Enable Warning BC40000

    Public Shared Sub parseUpload(path As String)
        Dim reader As XmlReader = XmlReader.Create(path, Settings)
    End Sub
End Class
";

            await Verify(cSharpTest5, visualBasicTest5, Expected, Warnings.OnFramework).ConfigureAwait(false);
        }

        [TestCategory("False Positive")]
        [TestMethod]
        public async Task FalsePositives5()
        {
            // todo: Once fixed, try uncomment tests in XmlReaderCreateDtdProcessingDisabled

            var cSharpTest5 = @"
using System.Xml;

public class Xxe5
{
#pragma warning disable 618
    private static XmlReaderSettings Settings = new XmlReaderSettings {DtdProcessing = DtdProcessing.Ignore};
#pragma warning restore 618

    public static void parseUpload(string path)
    {
        XmlReader reader = XmlReader.Create(path, Settings);
    }
}
";

            var visualBasicTest5 = @"
Imports System.Xml

Public Class Xxe5
#Disable Warning BC40000
    Private Shared Settings As New XmlReaderSettings With {.DtdProcessing = DtdProcessing.Ignore}
#Enable Warning BC40000

    Public Shared Sub parseUpload(path As String)
        Dim reader As XmlReader = XmlReader.Create(path, Settings)
    End Sub
End Class
";

            await Verify(cSharpTest5, visualBasicTest5, Expected, Warnings.OnFramework).ConfigureAwait(false);
        }

        [TestCategory("False Positive")]
        [TestMethod]
        public async Task FalsePositives6()
        {
            // todo: Once fixed, try uncomment tests in XmlReaderCreateDtdProcessingDisabled

            var cSharpTest5 = @"
using System.Xml;

public class Xxe5
{
#pragma warning disable 618
    private static XmlReaderSettings Settings = new XmlReaderSettings {DtdProcessing = DtdProcessing.Prohibit};
#pragma warning restore 618

    public static void parseUpload(string path)
    {
        XmlReader reader = XmlReader.Create(path, Settings);
    }
}
";

            var visualBasicTest5 = @"
Imports System.Xml

Public Class Xxe5
#Disable Warning BC40000
    Private Shared Settings As New XmlReaderSettings With {.DtdProcessing = DtdProcessing.Prohibit}
#Enable Warning BC40000

    Public Shared Sub parseUpload(path As String)
        Dim reader As XmlReader = XmlReader.Create(path, Settings)
    End Sub
End Class
";

            await Verify(cSharpTest5, visualBasicTest5, Expected, Warnings.OnFramework).ConfigureAwait(false);
        }

        [TestCategory("False Positive")]
        [TestMethod]
        public async Task FalsePositives7()
        {
            // todo: Once fixed, try uncomment tests in XmlReaderCreateDtdProcessingDisabled

            var cSharpTest5 = @"
using System.Xml;

public class Xxe5
{
#pragma warning disable 618
    private static XmlReaderSettings Settings = new XmlReaderSettings {ProhibitDtd = true};
#pragma warning restore 618

    public static void parseUpload(string path)
    {
        XmlReader reader = XmlReader.Create(path, Settings);
    }
}
";

            var visualBasicTest5 = @"
Imports System.Xml

Public Class Xxe5
#Disable Warning BC40000
    Private Shared Settings As New XmlReaderSettings With {.ProhibitDtd = True}
#Enable Warning BC40000

    Public Shared Sub parseUpload(path As String)
        Dim reader As XmlReader = XmlReader.Create(path, Settings)
    End Sub
End Class
";

            await Verify(cSharpTest5, visualBasicTest5, Expected, Warnings.OnFramework).ConfigureAwait(false);
        }
    }
}
