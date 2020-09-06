using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Test.Config;
using SecurityCodeScan.Test.Helpers;
using DiagnosticVerifier = SecurityCodeScan.Test.Helpers.DiagnosticVerifier;

namespace SecurityCodeScan.Test.InsecureXslt
{
    [TestClass]
    public class XsltSettingsTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string _)
        {
            return new[] { new XsltSettingsAnalyzer() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(System.Xml.Xsl.XsltSettings).Assembly.Location),
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        private readonly DiagnosticResult[] Expected =
        {
            new DiagnosticResult
            {
                Id = "SCS0011",
                Severity = DiagnosticSeverity.Warning
            },
        };

        [TestCategory("Detect")]
        [TestMethod]
        public async Task TrustedXslt()
        {
            var cSharpTest = $@"
using System.Xml;
using System.Xml.Xsl;

namespace VulnerableApp
{{
    class Test
    {{
        static void Foo(string xslPath)
        {{
            // Create a reader to read books.xml
            XmlReader reader = XmlReader.Create(""books.xml"");

            // Create a writer for writing the transformed file.
            XmlWriter writer = XmlWriter.Create(""books.html"");

            // Create and load the transform with script execution enabled.
            XslCompiledTransform transform = new XslCompiledTransform();
            XsltSettings settings = XsltSettings.TrustedXslt;
            transform.Load(xslPath, settings, null);

            // Execute the transformation.
            transform.Transform(reader, writer);
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Xml
Imports System.Xml.Xsl

Namespace VulnerableApp
    Class Test
        Private Shared Sub Foo(xslPath As String)
            Dim reader As XmlReader = XmlReader.Create(""books.xml"")
            Dim writer As XmlWriter = XmlWriter.Create(""books.html"")
            Dim transform As XslCompiledTransform = New XslCompiledTransform()
            Dim settings As XsltSettings = XsltSettings.TrustedXslt
            transform.Load(xslPath, settings, Nothing)
            transform.Transform(reader, writer)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp:
    Method:
      Name: Foo
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);

            testConfig = @"
AuditMode: true

TaintEntryPoints:
  VulnerableApp:
    Method:
      Name: Foo
";

            optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task EnabledConstructor()
        {
            var cSharpTest = $@"
using System.Xml;
using System.Xml.Xsl;

namespace VulnerableApp
{{
    class Test
    {{
        static void Foo(string xslPath)
        {{
            // Create a reader to read books.xml
            XmlReader reader = XmlReader.Create(""books.xml"");

            // Create a writer for writing the transformed file.
            XmlWriter writer = XmlWriter.Create(""books.html"");

            // Create and load the transform with script execution enabled.
            XslCompiledTransform transform = new XslCompiledTransform();
            XsltSettings settings = new XsltSettings(false, true);
            transform.Load(xslPath, settings, null);

            // Execute the transformation.
            transform.Transform(reader, writer);
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Xml
Imports System.Xml.Xsl

Namespace VulnerableApp
    Class Test
        Private Shared Sub Foo(xslPath As String)
            Dim reader As XmlReader = XmlReader.Create(""books.xml"")
            Dim writer As XmlWriter = XmlWriter.Create(""books.html"")
            Dim transform As XslCompiledTransform = New XslCompiledTransform()
            Dim settings As XsltSettings = New XsltSettings(False, True)
            transform.Load(xslPath, settings, Nothing)
            transform.Transform(reader, writer)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp:
    Method:
      Name: Foo
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);

            testConfig = @"
AuditMode: true

TaintEntryPoints:
  VulnerableApp:
    Method:
      Name: Foo
";

            optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task EnabledConstructorFlow()
        {
            var cSharpTest = $@"
using System.Xml;
using System.Xml.Xsl;

namespace VulnerableApp
{{
    class Test
    {{
        static void Foo(string xslPath)
        {{
            // Create a reader to read books.xml
            XmlReader reader = XmlReader.Create(""books.xml"");

            // Create a writer for writing the transformed file.
            XmlWriter writer = XmlWriter.Create(""books.html"");

            // Create and load the transform with script execution enabled.
            XslCompiledTransform transform = new XslCompiledTransform();
            var flag = true;
            XsltSettings settings = new XsltSettings(false, flag);
            transform.Load(xslPath, settings, null);

            // Execute the transformation.
            transform.Transform(reader, writer);
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Xml
Imports System.Xml.Xsl

Namespace VulnerableApp
    Class Test
        Private Shared Sub Foo(xslPath As String)
            Dim reader As XmlReader = XmlReader.Create(""books.xml"")
            Dim writer As XmlWriter = XmlWriter.Create(""books.html"")
            Dim transform As XslCompiledTransform = New XslCompiledTransform()
            Dim flag = True
            Dim settings As XsltSettings = New XsltSettings(False, flag)
            transform.Load(xslPath, settings, Nothing)
            transform.Transform(reader, writer)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp:
    Method:
      Name: Foo
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);

            testConfig = @"
AuditMode: true

TaintEntryPoints:
  VulnerableApp:
    Method:
      Name: Foo
";

            optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task EnabledConstructorUnknown()
        {
            var cSharpTest = $@"
using System.Xml;
using System.Xml.Xsl;

namespace VulnerableApp
{{
    class Test
    {{
        static void Foo(string xslPath, bool flag)
        {{
            // Create a reader to read books.xml
            XmlReader reader = XmlReader.Create(""books.xml"");

            // Create a writer for writing the transformed file.
            XmlWriter writer = XmlWriter.Create(""books.html"");

            // Create and load the transform with script execution enabled.
            XslCompiledTransform transform = new XslCompiledTransform();
            XsltSettings settings = new XsltSettings(false, flag);
            transform.Load(xslPath, settings, null);

            // Execute the transformation.
            transform.Transform(reader, writer);
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Xml
Imports System.Xml.Xsl

Namespace VulnerableApp
    Class Test
        Private Shared Sub Foo(xslPath As String, flag As Boolean)
            Dim reader As XmlReader = XmlReader.Create(""books.xml"")
            Dim writer As XmlWriter = XmlWriter.Create(""books.html"")
            Dim transform As XslCompiledTransform = New XslCompiledTransform()
            Dim settings As XsltSettings = New XsltSettings(False, flag)
            transform.Load(xslPath, settings, Nothing)
            transform.Transform(reader, writer)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp:
    Method:
      Name: Foo
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);

            testConfig = @"
AuditMode: true

TaintEntryPoints:
  VulnerableApp:
    Method:
      Name: Foo
";

            optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task DisabledConstructor()
        {
            var cSharpTest = $@"
using System.Xml;
using System.Xml.Xsl;

namespace VulnerableApp
{{
    class Test
    {{
        static void Foo(string xslPath)
        {{
            // Create a reader to read books.xml
            XmlReader reader = XmlReader.Create(""books.xml"");

            // Create a writer for writing the transformed file.
            XmlWriter writer = XmlWriter.Create(""books.html"");

            // Create and load the transform with script execution enabled.
            XslCompiledTransform transform = new XslCompiledTransform();
            XsltSettings settings = new XsltSettings(false, false);
            transform.Load(xslPath, settings, null);

            // Execute the transformation.
            transform.Transform(reader, writer);
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Xml
Imports System.Xml.Xsl

Namespace VulnerableApp
    Class Test
        Private Shared Sub Foo(xslPath As String)
            Dim reader As XmlReader = XmlReader.Create(""books.xml"")
            Dim writer As XmlWriter = XmlWriter.Create(""books.html"")
            Dim transform As XslCompiledTransform = New XslCompiledTransform()
            Dim settings As XsltSettings = New XsltSettings(False, False)
            transform.Load(xslPath, settings, Nothing)
            transform.Transform(reader, writer)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp:
    Method:
      Name: Foo
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);

            testConfig = @"
AuditMode: true

TaintEntryPoints:
  VulnerableApp:
    Method:
      Name: Foo
";

            optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task DisabledConstructorFlow()
        {
            var cSharpTest = $@"
using System.Xml;
using System.Xml.Xsl;

namespace VulnerableApp
{{
    class Test
    {{
        static void Foo(string xslPath)
        {{
            // Create a reader to read books.xml
            XmlReader reader = XmlReader.Create(""books.xml"");

            // Create a writer for writing the transformed file.
            XmlWriter writer = XmlWriter.Create(""books.html"");

            // Create and load the transform with script execution enabled.
            XslCompiledTransform transform = new XslCompiledTransform();
            var flag = false;
            XsltSettings settings = new XsltSettings(false, flag);
            transform.Load(xslPath, settings, null);

            // Execute the transformation.
            transform.Transform(reader, writer);
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Xml
Imports System.Xml.Xsl

Namespace VulnerableApp
    Class Test
        Private Shared Sub Foo(xslPath As String)
            Dim reader As XmlReader = XmlReader.Create(""books.xml"")
            Dim writer As XmlWriter = XmlWriter.Create(""books.html"")
            Dim transform As XslCompiledTransform = New XslCompiledTransform()
            Dim flag = False
            Dim settings As XsltSettings = New XsltSettings(False, flag)
            transform.Load(xslPath, settings, Nothing)
            transform.Transform(reader, writer)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp:
    Method:
      Name: Foo
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);

            testConfig = @"
AuditMode: true

TaintEntryPoints:
  VulnerableApp:
    Method:
      Name: Foo
";

            optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task EnabledInitializer()
        {
            var cSharpTest = $@"
using System.Xml;
using System.Xml.Xsl;

namespace VulnerableApp
{{
    class Test
    {{
        static void Foo(string xslPath)
        {{
            // Create a reader to read books.xml
            XmlReader reader = XmlReader.Create(""books.xml"");

            // Create a writer for writing the transformed file.
            XmlWriter writer = XmlWriter.Create(""books.html"");

            // Create and load the transform with script execution enabled.
            XslCompiledTransform transform = new XslCompiledTransform();
            XsltSettings settings = new XsltSettings() {{EnableScript = true}};
            transform.Load(xslPath, settings, null);

            // Execute the transformation.
            transform.Transform(reader, writer);
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Xml
Imports System.Xml.Xsl

Namespace VulnerableApp
    Class Test
        Private Shared Sub Foo(xslPath As String)
            Dim reader As XmlReader = XmlReader.Create(""books.xml"")
            Dim writer As XmlWriter = XmlWriter.Create(""books.html"")
            Dim transform As XslCompiledTransform = New XslCompiledTransform()
            Dim settings As XsltSettings = New XsltSettings() With {{
                .EnableScript = True
            }}
            transform.Load(xslPath, settings, Nothing)
            transform.Transform(reader, writer)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp:
    Method:
      Name: Foo
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);

            testConfig = @"
AuditMode: true

TaintEntryPoints:
  VulnerableApp:
    Method:
      Name: Foo
";

            optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task EnabledProperty()
        {
            var cSharpTest = $@"
using System.Xml;
using System.Xml.Xsl;

namespace VulnerableApp
{{
    class Test
    {{
        static void Foo(string xslPath)
        {{
            // Create a reader to read books.xml
            XmlReader reader = XmlReader.Create(""books.xml"");

            // Create a writer for writing the transformed file.
            XmlWriter writer = XmlWriter.Create(""books.html"");

            // Create and load the transform with script execution enabled.
            XslCompiledTransform transform = new XslCompiledTransform();
            XsltSettings settings = new XsltSettings();
            settings.EnableScript = true;
            transform.Load(xslPath, settings, null);

            // Execute the transformation.
            transform.Transform(reader, writer);
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Xml
Imports System.Xml.Xsl

Namespace VulnerableApp
    Class Test
        Private Shared Sub Foo(xslPath As String)
            Dim reader As XmlReader = XmlReader.Create(""books.xml"")
            Dim writer As XmlWriter = XmlWriter.Create(""books.html"")
            Dim transform As XslCompiledTransform = New XslCompiledTransform()
            Dim settings As XsltSettings = New XsltSettings()
            settings.EnableScript = True
            transform.Load(xslPath, settings, Nothing)
            transform.Transform(reader, writer)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp:
    Method:
      Name: Foo
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);

            testConfig = @"
AuditMode: true

TaintEntryPoints:
  VulnerableApp:
    Method:
      Name: Foo
";

            optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task EnabledPropertyUnknown()
        {
            var cSharpTest = $@"
using System.Xml;
using System.Xml.Xsl;

namespace VulnerableApp
{{
    class Test
    {{
        static void Foo(string xslPath, bool flag)
        {{
            // Create a reader to read books.xml
            XmlReader reader = XmlReader.Create(""books.xml"");

            // Create a writer for writing the transformed file.
            XmlWriter writer = XmlWriter.Create(""books.html"");

            // Create and load the transform with script execution enabled.
            XslCompiledTransform transform = new XslCompiledTransform();
            XsltSettings settings = new XsltSettings();
            settings.EnableScript = flag;
            transform.Load(xslPath, settings, null);

            // Execute the transformation.
            transform.Transform(reader, writer);
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Xml
Imports System.Xml.Xsl

Namespace VulnerableApp
    Class Test
        Private Shared Sub Foo(xslPath As String, flag As Boolean)
            Dim reader As XmlReader = XmlReader.Create(""books.xml"")
            Dim writer As XmlWriter = XmlWriter.Create(""books.html"")
            Dim transform As XslCompiledTransform = New XslCompiledTransform()
            Dim settings As XsltSettings = New XsltSettings()
            settings.EnableScript = flag
            transform.Load(xslPath, settings, Nothing)
            transform.Transform(reader, writer)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp:
    Method:
      Name: Foo
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);

            testConfig = @"
AuditMode: true

TaintEntryPoints:
  VulnerableApp:
    Method:
      Name: Foo
";

            optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task DisabledInitializer()
        {
            var cSharpTest = $@"
using System.Xml;
using System.Xml.Xsl;

namespace VulnerableApp
{{
    class Test
    {{
        static void Foo(string xslPath)
        {{
            // Create a reader to read books.xml
            XmlReader reader = XmlReader.Create(""books.xml"");

            // Create a writer for writing the transformed file.
            XmlWriter writer = XmlWriter.Create(""books.html"");

            // Create and load the transform with script execution enabled.
            XslCompiledTransform transform = new XslCompiledTransform();
            XsltSettings settings = new XsltSettings() {{EnableScript = false}};
            transform.Load(xslPath, settings, null);

            // Execute the transformation.
            transform.Transform(reader, writer);
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Xml
Imports System.Xml.Xsl

Namespace VulnerableApp
    Class Test
        Private Shared Sub Foo(xslPath As String)
            Dim reader As XmlReader = XmlReader.Create(""books.xml"")
            Dim writer As XmlWriter = XmlWriter.Create(""books.html"")
            Dim transform As XslCompiledTransform = New XslCompiledTransform()
            Dim settings As XsltSettings = New XsltSettings() With {{
                .EnableScript = False
            }}
            transform.Load(xslPath, settings, Nothing)
            transform.Transform(reader, writer)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp:
    Method:
      Name: Foo
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);

            testConfig = @"
AuditMode: true

TaintEntryPoints:
  VulnerableApp:
    Method:
      Name: Foo
";

            optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task DisabledProperty()
        {
            var cSharpTest = $@"
using System.Xml;
using System.Xml.Xsl;

namespace VulnerableApp
{{
    class Test
    {{
        static void Foo(string xslPath)
        {{
            // Create a reader to read books.xml
            XmlReader reader = XmlReader.Create(""books.xml"");

            // Create a writer for writing the transformed file.
            XmlWriter writer = XmlWriter.Create(""books.html"");

            // Create and load the transform with script execution enabled.
            XslCompiledTransform transform = new XslCompiledTransform();
            XsltSettings settings = new XsltSettings();
            settings.EnableScript = false;
            transform.Load(xslPath, settings, null);

            // Execute the transformation.
            transform.Transform(reader, writer);
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Xml
Imports System.Xml.Xsl

Namespace VulnerableApp
    Class Test
        Private Shared Sub Foo(xslPath As String)
            Dim reader As XmlReader = XmlReader.Create(""books.xml"")
            Dim writer As XmlWriter = XmlWriter.Create(""books.html"")
            Dim transform As XslCompiledTransform = New XslCompiledTransform()
            Dim settings As XsltSettings = New XsltSettings()
            settings.EnableScript = False
            transform.Load(xslPath, settings, Nothing)
            transform.Transform(reader, writer)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp:
    Method:
      Name: Foo
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);

            testConfig = @"
AuditMode: true

TaintEntryPoints:
  VulnerableApp:
    Method:
      Name: Foo
";

            optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task Default()
        {
            var cSharpTest = $@"
using System.Xml;
using System.Xml.Xsl;

namespace VulnerableApp
{{
    class Test
    {{
        static void Foo(string xslPath)
        {{
            // Create a reader to read books.xml
            XmlReader reader = XmlReader.Create(""books.xml"");

            // Create a writer for writing the transformed file.
            XmlWriter writer = XmlWriter.Create(""books.html"");

            // Create and load the transform with script execution enabled.
            XslCompiledTransform transform = new XslCompiledTransform();
            XsltSettings settings = new XsltSettings();
            transform.Load(xslPath, settings, null);

            // Execute the transformation.
            transform.Transform(reader, writer);
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Xml
Imports System.Xml.Xsl

Namespace VulnerableApp
    Class Test
        Private Shared Sub Foo(xslPath As String)
            Dim reader As XmlReader = XmlReader.Create(""books.xml"")
            Dim writer As XmlWriter = XmlWriter.Create(""books.html"")
            Dim transform As XslCompiledTransform = New XslCompiledTransform()
            Dim settings As XsltSettings = New XsltSettings()
            transform.Load(xslPath, settings, Nothing)
            transform.Transform(reader, writer)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp:
    Method:
      Name: Foo
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);

            testConfig = @"
AuditMode: true

TaintEntryPoints:
  VulnerableApp:
    Method:
      Name: Foo
";

            optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
        }
    }
}
