using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Soap;
using System.Threading.Tasks;
using System.Web.UI;
using System.Activities;
using System.Messaging;
using System.Resources;
using System.Runtime.Serialization.Json;
using System.Xml.Serialization;
using fastJSON;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Config;
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test.Taint
{
    [TestClass]
    public class UnsafeDeserializationTests : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string _)
        {
            return new[] { new DeserializationTaintAnalyzer() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(SoapFormatter).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(ObjectStateFormatter).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(NetDataContractSerializer).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(DataContractSerializer).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(DataContractJsonSerializer).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(LosFormatter).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Activity).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(BinaryMessageFormatter).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(JSON).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(XmlSerializer).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(XmlMessageFormatter).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(ServiceStack.Text.JsonSerializer).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(ResourceReader).Assembly.Location)
        };

        private DiagnosticResult Expected = new DiagnosticResult()
        {
            Id       = "SCS0028",
            Severity = DiagnosticSeverity.Warning
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestCategory("Safe")]
        [TestMethod]
        public async Task BinaryFormatterDeepCloneNoWarning()
        {
            const string cSharpTest = @"
using System.Runtime.Serialization.Formatters.Binary;
using System.IO;

public class A
{
    public T DeepClone<T>(T obj)
    {
        using (var ms = new MemoryStream())
        {
            var formatter = new BinaryFormatter();
            formatter.Serialize(ms, obj);
            ms.Position = 0;

            return (T)formatter.Deserialize(ms);
        }
    }
}
";

            const string visualBasicTest = @"
Imports System.Runtime.Serialization.Formatters.Binary
Imports System.IO

Public Class A

    Public Function DeepClone(Of T)(ByVal obj As T) As T
        Using ms = New MemoryStream()
            Dim formatter = New BinaryFormatter()
            formatter.Serialize(ms, obj)
            ms.Position = 0
            Return CType(formatter.Deserialize(ms), T)
        End Using
    End Function
End Class
";

            var testConfig = @"
TaintEntryPoints:
  A:
    Method:
      Name: DeepClone
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("Deserialize",                     "")]
        [DataRow("Deserialize",                     ", null")]
        [DataRow("UnsafeDeserialize",               ", null")]
        [DataRow("UnsafeDeserializeMethodResponse", ", null, null")]
        public async Task DetectBinaryFormatterDeserializationMethods(string method, string additionalParams)
        {
            var cSharpTest = $@"
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace VulnerableApp
{{
    public class Test
    {{
        public void TestDeserialization(Stream input)
        {{
            var formatter = new BinaryFormatter();
            formatter.{method}(input{additionalParams});
        }}
    }}
}}
";

            var vbAdditionalParams = additionalParams.CSharpReplaceToVBasic();

            var visualBasicTest = $@"
Imports System.IO
Imports System.Runtime.Serialization.Formatters.Binary

Namespace VulnerableApp
    Public Class Test
        Public Sub TestDeserialization(input As Stream)
            Dim formatter = New BinaryFormatter()
            formatter.{method}(input{vbAdditionalParams})
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp.Test:
    Method:
      Name: TestDeserialization
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(12), optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(9), optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectBinaryMessageFormatterReadMethod()
        {
            const string cSharpTest = @"
using System.Messaging;

namespace VulnerableApp
{
    public class Test
    {
        public void TestDeserialization(Message input)
        {
            var formatter = new BinaryMessageFormatter();
            formatter.Read(input);
        }
    }
}
";

            const string visualBasicTest = @"
Imports System.Messaging

Namespace VulnerableApp
    Public Class Test
        Public Sub TestDeserialization(input As Message)
            Dim formatter = New BinaryMessageFormatter()
            formatter.Read(input)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp.Test:
    Method:
      Name: TestDeserialization
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(11), optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(8), optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("")]
        [DataRow(", null")]
        public async Task DetectSoapFormatterDeserializeMethods(string additionalParams)
        {
            var cSharpTest = $@"
using System.IO;
using System.Runtime.Serialization.Formatters.Soap;

namespace VulnerableApp
{{
    public class Test
    {{
        public void TestDeserialization(Stream input)
        {{
            var formatter = new SoapFormatter();
            formatter.Deserialize(input{additionalParams});
        }}
    }}
}}
";

            var vbAdditionalParams = additionalParams.CSharpReplaceToVBasic();

            var visualBasicTest = $@"
Imports System.IO
Imports System.Runtime.Serialization.Formatters.Soap

Namespace VulnerableApp
    Public Class Test
        Public Sub TestDeserialization(input As Stream)
            Dim formatter = New SoapFormatter()
            formatter.Deserialize(input{vbAdditionalParams})
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp.Test:
    Method:
      Name: TestDeserialization
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(12), optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(9), optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("string")]
        [DataRow("System.IO.Stream")]
        public async Task DetectObjectStateFormatterDeserializeMethods(string inputType)
        {
            var cSharpTest = $@"
using System.Web.UI;

namespace VulnerableApp
{{
    public class Test
    {{
        public void TestDeserialization({inputType} input)
        {{
            var formatter = new ObjectStateFormatter();
            formatter.Deserialize(input);
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Web.UI

Namespace VulnerableApp
    Public Class Test
        Public Sub TestDeserialization(input As {inputType})
            Dim formatter = New ObjectStateFormatter()
            formatter.Deserialize(input)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp.Test:
    Method:
      Name: TestDeserialization
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(11), optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(8), optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("Deserialize", "System.IO.Stream",               "")]
        [DataRow("ReadObject",  "System.IO.Stream",               "")]
        [DataRow("ReadObject",  "System.Xml.XmlDictionaryReader", "")]
        [DataRow("ReadObject",  "System.Xml.XmlDictionaryReader", ", false")]
        [DataRow("ReadObject",  "System.Xml.XmlReader",           "")]
        [DataRow("ReadObject",  "System.Xml.XmlReader",           ", false")]
        public async Task DetectNetDataContractSerializerDeserializationMethods(string methodName, string inputType, string additionalParams)
        {
            var cSharpTest = $@"
using System.Runtime.Serialization;

namespace VulnerableApp
{{
    public class Test
    {{
        public void TestDeserialization({inputType} input)
        {{
            var formatter = new NetDataContractSerializer();
            formatter.{methodName}(input{additionalParams});
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Runtime.Serialization

Namespace VulnerableApp
    Public Class Test
        Public Sub TestDeserialization(input As {inputType})
            Dim formatter = New NetDataContractSerializer()
            formatter.{methodName}(input{additionalParams})
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp.Test:
    Method:
      Name: TestDeserialization
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(11), optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(8), optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("System.IO.Stream",               "")]
        [DataRow("System.Xml.XmlDictionaryReader", "")]
        [DataRow("System.Xml.XmlDictionaryReader", ", false")]
        [DataRow("System.Xml.XmlReader",           "")]
        [DataRow("System.Xml.XmlReader",           ", false")]
        public async Task DetectDataContractSerializerReadObjectMethods(string inputType, string additionalParams)
        {
            var cSharpTest = $@"
using System.Runtime.Serialization;

namespace VulnerableApp
{{
    public class Test
    {{
        public void TestDeserialization({inputType} input)
        {{
            var formatter = new DataContractSerializer(typeof(Test));
            formatter.ReadObject(input{additionalParams});
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Runtime.Serialization

Namespace VulnerableApp
    Public Class Test
        Public Sub TestDeserialization(input As {inputType})
            Dim formatter = New DataContractSerializer(GetType(Test))
            formatter.ReadObject(input{additionalParams})
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp.Test:
    Method:
      Name: TestDeserialization
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(11), optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(8), optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectDataContractSerializerConstructor()
        {
            const string cSharpTest = @"
using System;
using System.Runtime.Serialization;

namespace VulnerableApp
{
    public class Test
    {
        public void TestDeserialization(Type objectType)
        {
            var formatter = new DataContractSerializer(objectType);
        }
    }
}
";

            const string visualBasicTest = @"
Imports System
Imports System.Runtime.Serialization

Namespace VulnerableApp
    Public Class Test
        Public Sub TestDeserialization(objectType as Type)
            Dim formatter = New DataContractSerializer(objectType)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp.Test:
    Method:
      Name: TestDeserialization
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(11), optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(8), optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("System.IO.Stream",               "")]
        [DataRow("System.Xml.XmlDictionaryReader", "")]
        [DataRow("System.Xml.XmlDictionaryReader", ", false")]
        [DataRow("System.Xml.XmlReader",           "")]
        [DataRow("System.Xml.XmlReader",           ", false")]
        public async Task DetectDataContractJsonSerializerReadObjectMethods(string inputType, string additionalParams)
        {
            var cSharpTest = $@"
using System.Runtime.Serialization.Json;

namespace VulnerableApp
{{
    public class Test
    {{
        public void TestDeserialization({inputType} input)
        {{
            var formatter = new DataContractJsonSerializer(typeof(Test));
            formatter.ReadObject(input{additionalParams});
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Runtime.Serialization.Json

Namespace VulnerableApp
    Public Class Test
        Public Sub TestDeserialization(input As {inputType})
            Dim formatter = New DataContractJsonSerializer(GetType(Test))
            formatter.ReadObject(input{additionalParams})
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp.Test:
    Method:
      Name: TestDeserialization
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(11), optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(8), optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectDataContractJsonSerializerConstructor()
        {
            const string cSharpTest = @"
using System;
using System.Runtime.Serialization.Json;

namespace VulnerableApp
{
    public class Test
    {
        public void TestDeserialization(Type objectType)
        {
            var formatter = new DataContractJsonSerializer(objectType);
        }
    }
}
";

            const string visualBasicTest = @"
Imports System
Imports System.Runtime.Serialization.Json

Namespace VulnerableApp
    Public Class Test
        Public Sub TestDeserialization(objectType as Type)
            Dim formatter = New DataContractJsonSerializer(objectType)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp.Test:
    Method:
      Name: TestDeserialization
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(11), optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(8), optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task DetectDataContractJsonSerializerConstructorTypeof()
        {
            const string cSharpTest = @"
using System.Runtime.Serialization.Json;

namespace VulnerableApp
{
    public class Test
    {
        public void TestDeserialization()
        {
            var formatter = new DataContractJsonSerializer(typeof(Test));
        }
    }
}
";

            const string visualBasicTest = @"
Imports System.Runtime.Serialization.Json

Namespace VulnerableApp
    Public Class Test
        Public Sub TestDeserialization()
            Dim formatter = New DataContractJsonSerializer(GetType(Test))
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp.Test:
    Method:
      Name: TestDeserialization
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig("AuditMode: true\r\n" + testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, null, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, null, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("System.IO.Stream",     "")]
        [DataRow("System.IO.TextReader", "")]
        [DataRow("System.Xml.XmlReader", "")]
        [DataRow("System.Xml.XmlReader", ", \"\"")]
        [DataRow("System.Xml.XmlReader", ", new System.Xml.Serialization.XmlDeserializationEvents()")]
        [DataRow("System.Xml.XmlReader", ", \"\", new System.Xml.Serialization.XmlDeserializationEvents()")]
        public async Task DetectXmlSerializerDeserializeMethods(string inputType, string additionalParams)
        {
            var cSharpTest = $@"
using System.Xml.Serialization;

namespace VulnerableApp
{{
    public class Test
    {{
        public void TestDeserialization({inputType} input)
        {{
            var formatter = new XmlSerializer(typeof(Test));
            formatter.Deserialize(input{additionalParams});
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Xml.Serialization

Namespace VulnerableApp
    Public Class Test
        Public Sub TestDeserialization(input As {inputType})
            Dim formatter = New XmlSerializer(GetType(Test))
            formatter.Deserialize(input{additionalParams})
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp.Test:
    Method:
      Name: TestDeserialization
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(11), optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(8), optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectXmlSerializerConstructor()
        {
            const string cSharpTest = @"
using System;
using System.Xml.Serialization;

namespace VulnerableApp
{
    public class Test
    {
        public void TestDeserialization(Type objectType)
        {
            var formatter = new XmlSerializer(objectType);
        }
    }
}
";

            const string visualBasicTest = @"
Imports System
Imports System.Xml.Serialization

Namespace VulnerableApp
    Public Class Test
        Public Sub TestDeserialization(objectType as Type)
            Dim formatter = New XmlSerializer(objectType)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp.Test:
    Method:
      Name: TestDeserialization
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(11), optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(8), optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectXmlMessageFormatterReadMethod()
        {
            const string cSharpTest = @"
using System.Messaging;

namespace VulnerableApp
{
    public class Test
    {
        public void TestDeserialization(Message input)
        {
            var formatter = new XmlMessageFormatter();
            formatter.Read(input);
        }
    }
}
";

            const string visualBasicTest = @"
Imports System.Messaging

Namespace VulnerableApp
    Public Class Test
        Public Sub TestDeserialization(input As Message)
            Dim formatter = New XmlMessageFormatter()
            formatter.Read(input)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp.Test:
    Method:
      Name: TestDeserialization
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(11), optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(8), optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("System.IO.Stream")]
        [DataRow("string")]
        [DataRow("System.IO.TextReader")]
        public async Task DetectLosFormatterDeserializeMethod(string inputType)
        {
            var cSharpTest = $@"
using System.Web.UI;

namespace VulnerableApp
{{
    public class Test
    {{
        public void TestDeserialization({inputType} input)
        {{
            var formatter = new LosFormatter();
            formatter.Deserialize(input);
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Web.UI

Namespace VulnerableApp
    Public Class Test
        Public Sub TestDeserialization(input As {inputType})
            Dim formatter = New LosFormatter()
            formatter.Deserialize(input)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp.Test:
    Method:
      Name: TestDeserialization
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(11), optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(8), optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectJSONToObjectMethod()
        {
            const string cSharpTest = @"
using fastJSON;

namespace VulnerableApp
{
    public class Test
    {
        public void TestDeserialization(string input)
        {
            JSON.ToObject(input);
        }
    }
}
";

            const string visualBasicTest = @"
Imports fastJSON

Namespace VulnerableApp
    Public Class Test
        Public Sub TestDeserialization(input As String)
            JSON.ToObject(input)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp.Test:
    Method:
      Name: TestDeserialization
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(10), optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(7), optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectJSONToObjectGenericMethod()
        {
            const string cSharpTest = @"
using fastJSON;

namespace VulnerableApp
{
    public class Test
    {
        public void TestDeserialization(string input)
        {
            JSON.ToObject<Test>(input);
        }
    }
}
";

            const string visualBasicTest = @"
Imports fastJSON

Namespace VulnerableApp
    Public Class Test
        Public Sub TestDeserialization(input As String)
            JSON.ToObject(Of Test)(input)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp.Test:
    Method:
      Name: TestDeserialization
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(10), optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(7), optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("DeserializeFromString", "string",               "System.Type")]
        [DataRow("DeserializeFromReader", "System.IO.TextReader", "System.Type")]
        [DataRow("DeserializeFromStream", "System.Type",          "System.IO.Stream")]
        public async Task DetectServiceStackJsonSerializerDeserializeMethods(string method, string firstParam, string secondParam)
        {
            var cSharpTest = $@"
using ServiceStack.Text;

namespace VulnerableApp
{{
    public class Test
    {{
        public void TestDeserialization({firstParam} param1, {secondParam} param2)
        {{
            JsonSerializer.{method}(param1, param2);
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports ServiceStack.Text

Namespace VulnerableApp
    Public Class Test
        Public Sub TestDeserialization(param1 As {firstParam}, param2 as {secondParam})
            JsonSerializer.{method}(param1, param2)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp.Test:
    Method:
      Name: TestDeserialization
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, new[] { Expected.WithLocation(10), Expected.WithLocation(10) }, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new[] { Expected.WithLocation(7), Expected.WithLocation(7) }, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("DeserializeFromString", "string")]
        [DataRow("DeserializeFromReader", "System.IO.TextReader")]
        [DataRow("DeserializeFromStream", "System.IO.Stream")]
        public async Task DetectServiceStackJsonSerializerDeserializeGenericMethods(string method, string inputType)
        {
            var cSharpMethod      = method + "<Test>";
            var visualBasicMethod = method + "(Of Test)";

            var cSharpTest = $@"
using ServiceStack.Text;

namespace VulnerableApp
{{
    public class Test
    {{
        public void TestDeserialization({inputType} input)
        {{
            JsonSerializer.{cSharpMethod}(input);
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports ServiceStack.Text

Namespace VulnerableApp
    Public Class Test
        Public Sub TestDeserialization(input As {inputType})
            JsonSerializer.{visualBasicMethod}(input)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp.Test:
    Method:
      Name: TestDeserialization
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(10), optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(7), optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("DeserializeFromString", "string",               "System.Type")]
        [DataRow("DeserializeFromReader", "System.IO.TextReader", "System.Type")]
        [DataRow("DeserializeFromStream", "System.Type",          "System.IO.Stream")]
        public async Task DetectServiceStackTypeSerializerDeserializeMethods(string method, string firstParam, string secondParam)
        {
            var cSharpTest = $@"
using ServiceStack.Text;

namespace VulnerableApp
{{
    public class Test
    {{
        public void TestDeserialization({firstParam} param1, {secondParam} param2)
        {{
            TypeSerializer.{method}(param1, param2);
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports ServiceStack.Text

Namespace VulnerableApp
    Public Class Test
        Public Sub TestDeserialization(param1 As {firstParam}, param2 as {secondParam})
            TypeSerializer.{method}(param1, param2)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp.Test:
    Method:
      Name: TestDeserialization
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, new[] { Expected.WithLocation(10), Expected.WithLocation(10) }, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new[] { Expected.WithLocation(7), Expected.WithLocation(7) }, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("DeserializeFromString", "string")]
        [DataRow("DeserializeFromReader", "System.IO.TextReader")]
        [DataRow("DeserializeFromStream", "System.IO.Stream")]
        public async Task DetectServiceStackTypeSerializerDeserializeGenericMethods(string method, string inputType)
        {
            var cSharpMethod      = method + "<Test>";
            var visualBasicMethod = method + "(Of Test)";

            var cSharpTest = $@"
using ServiceStack.Text;

namespace VulnerableApp
{{
    public class Test
    {{
        public void TestDeserialization({inputType} input)
        {{
            TypeSerializer.{cSharpMethod}(input);
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports ServiceStack.Text

Namespace VulnerableApp
    Public Class Test
        Public Sub TestDeserialization(input As {inputType})
            TypeSerializer.{visualBasicMethod}(input)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp.Test:
    Method:
      Name: TestDeserialization
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(10), optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(7), optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("DeserializeFromString", "string")]
        [DataRow("DeserializeFromStream", "System.IO.Stream")]
        public async Task DetectServiceStackCsvSerializerDeserializeMethods(string method, string inputType)
        {
            var cSharpTest = $@"
using System;
using ServiceStack.Text;

namespace VulnerableApp
{{
    public class Test
    {{
        public void TestDeserialization({inputType} input, Type type)
        {{
            CsvSerializer.{method}(type, input);
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System
Imports ServiceStack.Text

Namespace VulnerableApp
    Public Class Test
        Public Sub TestDeserialization(input As {inputType}, type as Type)
            CsvSerializer.{method}(type, input)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp.Test:
    Method:
      Name: TestDeserialization
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, new[] { Expected.WithLocation(11), Expected.WithLocation(11) }, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new[] { Expected.WithLocation(8), Expected.WithLocation(8) }, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("DeserializeFromString", "string")]
        [DataRow("DeserializeFromReader", "System.IO.TextReader")]
        [DataRow("DeserializeFromStream", "System.IO.Stream")]
        public async Task DetectServiceStackCsvSerializerDeserializeGenericMethods(string method, string inputType)
        {
            var cSharpMethod      = method + "<Test>";
            var visualBasicMethod = method + "(Of Test)";

            var cSharpTest = $@"
using ServiceStack.Text;

namespace VulnerableApp
{{
    public class Test
    {{
        public void TestDeserialization({inputType} input)
        {{
            CsvSerializer.{cSharpMethod}(input);
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports ServiceStack.Text

Namespace VulnerableApp
    Public Class Test
        Public Sub TestDeserialization(input As {inputType})
            CsvSerializer.{visualBasicMethod}(input)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp.Test:
    Method:
      Name: TestDeserialization
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(10), optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(7), optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("DeserializeFromString", "string",               "System.Type")]
        [DataRow("DeserializeFromStream", "System.Type",          "System.IO.Stream")]
        public async Task DetectServiceStackXmlSerializerDeserializeMethods(string method, string firstParam, string secondParam)
        {
            var cSharpTest = $@"
using ServiceStack.Text;

namespace VulnerableApp
{{
    public class Test
    {{
        public void TestDeserialization({firstParam} param1, {secondParam} param2)
        {{
            XmlSerializer.{method}(param1, param2);
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports ServiceStack.Text

Namespace VulnerableApp
    Public Class Test
        Public Sub TestDeserialization(param1 As {firstParam}, param2 as {secondParam})
            XmlSerializer.{method}(param1, param2)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp.Test:
    Method:
      Name: TestDeserialization
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, new[] { Expected.WithLocation(10), Expected.WithLocation(10) }, optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new[] { Expected.WithLocation(7), Expected.WithLocation(7) }, optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("DeserializeFromString", "string")]
        [DataRow("DeserializeFromReader", "System.IO.TextReader")]
        [DataRow("DeserializeFromStream", "System.IO.Stream")]
        public async Task DetectServiceStackXmlSerializerDeserializeGenericMethods(string method, string inputType)
        {
            var cSharpMethod = method + "<Test>";
            var visualBasicMethod = method + "(Of Test)";

            var cSharpTest = $@"
using ServiceStack.Text;

namespace VulnerableApp
{{
    public class Test
    {{
        public void TestDeserialization({inputType} input)
        {{
            XmlSerializer.{cSharpMethod}(input);
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports ServiceStack.Text

Namespace VulnerableApp
    Public Class Test
        Public Sub TestDeserialization(input As {inputType})
            XmlSerializer.{visualBasicMethod}(input)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp.Test:
    Method:
      Name: TestDeserialization
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(10), optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(7), optionsWithProjectConfig).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [DataTestMethod]
        [DataRow("System.IO.Stream")]
        [DataRow("string")]
        public async Task DetectResourceReaderCreations(string inputType)
        {
            var cSharpTest = $@"
using System.Resources;

namespace VulnerableApp
{{
    public class Test
    {{
        public void TestDeserialization({inputType} input)
        {{
            var formatter = new ResourceReader(input);
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Resources

Namespace VulnerableApp
    Public Class Test
        Public Sub TestDeserialization(input As {inputType})
            Dim formatter = New ResourceReader(input)
        End Sub
    End Class
End Namespace
";

            var testConfig = @"
TaintEntryPoints:
  VulnerableApp.Test:
    Method:
      Name: TestDeserialization
";

            var optionsWithProjectConfig = ConfigurationTest.CreateAnalyzersOptionsWithConfig(testConfig);
            await VerifyCSharpDiagnostic(cSharpTest, Expected.WithLocation(10), optionsWithProjectConfig).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, Expected.WithLocation(7), optionsWithProjectConfig).ConfigureAwait(false);
        }
    }
}
