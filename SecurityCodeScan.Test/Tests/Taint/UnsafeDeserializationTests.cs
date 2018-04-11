using System;
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
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test.Taint
{
    [TestClass]
    public class UnsafeDeserializationTests : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new DiagnosticAnalyzer[] { new TaintAnalyzer() };
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

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestMethod]
        public async Task BinaryFormatterDeepCloneNoWarning()
        {
            var cSharpTest = @"
using System.Runtime.Serialization.Formatters.Binary;
using System.IO;

class A
{
    public static T DeepClone<T>(T obj)
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

            var visualBasicTest = @"
Imports System.Runtime.Serialization.Formatters.Binary
Imports System.IO

Class A

    Public Shared Function DeepClone(Of T)(ByVal obj As T) As T
        Using ms = New MemoryStream()
            Dim formatter = New BinaryFormatter()
            formatter.Serialize(ms, obj)
            ms.Position = 0
            Return CType(formatter.Deserialize(ms), T)
        End Using
    End Function
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

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
    class Test
    {{
        static void TestDeserialization(Stream input)
        {{
            var formatter = new BinaryFormatter();
            formatter.{method}(input{additionalParams});
        }}
    }}
}}
";

            var vbAdditionalParams = additionalParams.Replace("null", "Nothing");

            var visualBasicTest = $@"
Imports System.IO
Imports System.Runtime.Serialization.Formatters.Binary

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As Stream)
            Dim formatter = New BinaryFormatter()
            formatter.{method}(input{vbAdditionalParams})
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 12)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 9)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectBinaryMessageFormatterReadMethod()
        {
            var cSharpTest = @"
using System.Messaging;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(Message input)
        {
            var formatter = new BinaryMessageFormatter();
            formatter.Read(input);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Messaging

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As Message)
            Dim formatter = New BinaryMessageFormatter()
            formatter.Read(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 11)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 8)).ConfigureAwait(false);
        }

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
    class Test
    {{
        static void TestDeserialization(Stream input)
        {{
            var formatter = new SoapFormatter();
            formatter.Deserialize(input{additionalParams});
        }}
    }}
}}
";

            var vbAdditionalParams = additionalParams.Replace("null", "Nothing");

            var visualBasicTest = $@"
Imports System.IO
Imports System.Runtime.Serialization.Formatters.Soap

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As Stream)
            Dim formatter = New SoapFormatter()
            formatter.Deserialize(input{vbAdditionalParams})
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 12)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 9)).ConfigureAwait(false);
        }

        [DataTestMethod]
        [DataRow("string")]
        [DataRow("System.IO.Stream")]
        public async Task DetectObjectStateFormatterDeserializeMethods(string inputType)
        {
            var cSharpTest = $@"
using System.Web.UI;

namespace VulnerableApp
{{
    class Test
    {{
        static void TestDeserialization({inputType} input)
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
    Class Test
        Private Sub TestDeserialization(input As {inputType})
            Dim formatter = New ObjectStateFormatter()
            formatter.Deserialize(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 11)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 8)).ConfigureAwait(false);
        }

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
    class Test
    {{
        static void TestDeserialization({inputType} input)
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
    Class Test
        Private Sub TestDeserialization(input As {inputType})
            Dim formatter = New NetDataContractSerializer()
            formatter.{methodName}(input{additionalParams})
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 11)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 8)).ConfigureAwait(false);
        }

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
    class Test
    {{
        static void TestDeserialization({inputType} input)
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
    Class Test
        Private Sub TestDeserialization(input As {inputType})
            Dim formatter = New DataContractSerializer(GetType(Test))
            formatter.ReadObject(input{additionalParams})
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 11)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 8)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectDataContractSerializerConstructor()
        {
            var cSharpTest = @"
using System;
using System.Runtime.Serialization;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(Type objectType)
        {
            var formatter = new DataContractSerializer(objectType);
        }
    }
}
";

            var visualBasicTest = @"
Imports System
Imports System.Runtime.Serialization

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(objectType as Type)
            Dim formatter = New DataContractSerializer(objectType)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 11)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 8)).ConfigureAwait(false);
        }

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
    class Test
    {{
        static void TestDeserialization({inputType} input)
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
    Class Test
        Private Sub TestDeserialization(input As {inputType})
            Dim formatter = New DataContractJsonSerializer(GetType(Test))
            formatter.ReadObject(input{additionalParams})
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 11)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 8)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectDataContractJsonSerializerConstructor()
        {
            var cSharpTest = @"
using System;
using System.Runtime.Serialization.Json;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(Type objectType)
        {
            var formatter = new DataContractJsonSerializer(objectType);
        }
    }
}
";

            var visualBasicTest = @"
Imports System
Imports System.Runtime.Serialization.Json

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(objectType as Type)
            Dim formatter = New DataContractJsonSerializer(objectType)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 11)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 8)).ConfigureAwait(false);
        }


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
    class Test
    {{
        static void TestDeserialization({inputType} input)
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
    Class Test
        Private Sub TestDeserialization(input As {inputType})
            Dim formatter = New XmlSerializer(GetType(Test))
            formatter.Deserialize(input{additionalParams})
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 11)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 8)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectXmlSerializerConstructor()
        {
            var cSharpTest = @"
using System;
using System.Xml.Serialization;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(Type objectType)
        {
            var formatter = new XmlSerializer(objectType);
        }
    }
}
";

            var visualBasicTest = @"
Imports System
Imports System.Xml.Serialization

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(objectType as Type)
            Dim formatter = New XmlSerializer(objectType)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 11)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 8)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectXmlMessageFormatterReadMethod()
        {
            var cSharpTest = @"
using System.Messaging;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(Message input)
        {
            var formatter = new XmlMessageFormatter();
            formatter.Read(input);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Messaging

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As Message)
            Dim formatter = New XmlMessageFormatter()
            formatter.Read(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 11)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 8)).ConfigureAwait(false);
        }

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
    class Test
    {{
        static void TestDeserialization({inputType} input)
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
    Class Test
        Private Sub TestDeserialization(input As {inputType})
            Dim formatter = New LosFormatter()
            formatter.Deserialize(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 11)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 8)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectJSONToObjectMethod()
        {
            var cSharpTest = @"
using fastJSON;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(string input)
        {
            JSON.ToObject(input);
        }
    }
}
";

            var visualBasicTest = @"
Imports fastJSON

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As String)
            JSON.ToObject(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 10)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 7)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectJSONToObjectGenericMethod()
        {
            var cSharpTest = @"
using fastJSON;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(string input)
        {
            JSON.ToObject<Test>(input);
        }
    }
}
";

            var visualBasicTest = @"
Imports fastJSON

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As String)
            JSON.ToObject(Of Test)(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 10)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 7)).ConfigureAwait(false);
        }

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
    class Test
    {{
        static void TestDeserialization({firstParam} param1, {secondParam} param2)
        {{
            JsonSerializer.{method}(param1, param2);
        }}
    }}
}}
";

            Console.WriteLine(cSharpTest);

            var visualBasicTest = $@"
Imports ServiceStack.Text

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(param1 As {firstParam}, param2 as {secondParam})
            JsonSerializer.{method}(param1, param2)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, new[] { expected.WithLocation("Test0.cs", 10), expected.WithLocation("Test0.cs", 10) }).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new[] { expected.WithLocation("Test0.vb", 7), expected.WithLocation("Test0.vb", 7) }).ConfigureAwait(false);
        }

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
    class Test
    {{
        static void TestDeserialization({inputType} input)
        {{
            JsonSerializer.{cSharpMethod}(input);
        }}
    }}
}}
";

            Console.WriteLine(cSharpTest);

            var visualBasicTest = $@"
Imports ServiceStack.Text

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As {inputType})
            JsonSerializer.{visualBasicMethod}(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 10)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 7)).ConfigureAwait(false);
        }


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
    class Test
    {{
        static void TestDeserialization({firstParam} param1, {secondParam} param2)
        {{
            TypeSerializer.{method}(param1, param2);
        }}
    }}
}}
";

            Console.WriteLine(cSharpTest);

            var visualBasicTest = $@"
Imports ServiceStack.Text

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(param1 As {firstParam}, param2 as {secondParam})
            TypeSerializer.{method}(param1, param2)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, new[] { expected.WithLocation("Test0.cs", 10), expected.WithLocation("Test0.cs", 10) }).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new[] { expected.WithLocation("Test0.vb", 7), expected.WithLocation("Test0.vb", 7) }).ConfigureAwait(false);
        }

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
    class Test
    {{
        static void TestDeserialization({inputType} input)
        {{
            TypeSerializer.{cSharpMethod}(input);
        }}
    }}
}}
";

            Console.WriteLine(cSharpTest);

            var visualBasicTest = $@"
Imports ServiceStack.Text

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As {inputType})
            TypeSerializer.{visualBasicMethod}(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 10)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 7)).ConfigureAwait(false);
        }

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
    class Test
    {{
        static void TestDeserialization({inputType} input, Type type)
        {{
            CsvSerializer.{method}(type, input);
        }}
    }}
}}
";

            Console.WriteLine(cSharpTest);

            var visualBasicTest = $@"
Imports System
Imports ServiceStack.Text

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As {inputType}, type as Type)
            CsvSerializer.{method}(type, input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, new[] { expected.WithLocation("Test0.cs", 11), expected.WithLocation("Test0.cs", 11) }).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new[] { expected.WithLocation("Test0.vb", 8), expected.WithLocation("Test0.vb", 8) }).ConfigureAwait(false);
        }

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
    class Test
    {{
        static void TestDeserialization({inputType} input)
        {{
            CsvSerializer.{cSharpMethod}(input);
        }}
    }}
}}
";

            Console.WriteLine(cSharpTest);

            var visualBasicTest = $@"
Imports ServiceStack.Text

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As {inputType})
            CsvSerializer.{visualBasicMethod}(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 10)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 7)).ConfigureAwait(false);
        }

        [DataTestMethod]
        [DataRow("DeserializeFromString", "string",               "System.Type")]
        [DataRow("DeserializeFromStream", "System.Type",          "System.IO.Stream")]
        public async Task DetectServiceStackXmlSerializerDeserializeMethods(string method, string firstParam, string secondParam)
        {
            var cSharpTest = $@"
using ServiceStack.Text;

namespace VulnerableApp
{{
    class Test
    {{
        static void TestDeserialization({firstParam} param1, {secondParam} param2)
        {{
            XmlSerializer.{method}(param1, param2);
        }}
    }}
}}
";

            Console.WriteLine(cSharpTest);

            var visualBasicTest = $@"
Imports ServiceStack.Text

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(param1 As {firstParam}, param2 as {secondParam})
            XmlSerializer.{method}(param1, param2)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, new[] { expected.WithLocation("Test0.cs", 10), expected.WithLocation("Test0.cs", 10) }).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new[] { expected.WithLocation("Test0.vb", 7), expected.WithLocation("Test0.vb", 7) }).ConfigureAwait(false);
        }

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
    class Test
    {{
        static void TestDeserialization({inputType} input)
        {{
            XmlSerializer.{cSharpMethod}(input);
        }}
    }}
}}
";

            Console.WriteLine(cSharpTest);

            var visualBasicTest = $@"
Imports ServiceStack.Text

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As {inputType})
            XmlSerializer.{visualBasicMethod}(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 10)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 7)).ConfigureAwait(false);
        }

        [DataTestMethod]
        [DataRow("System.IO.Stream")]
        [DataRow("string")]
        public async Task DetectResourceReaderCreations(string inputType)
        {
            var cSharpTest = $@"
using System.Resources;

namespace VulnerableApp
{{
    class Test
    {{
        static void TestDeserialization({inputType} input)
        {{
            var formatter = new ResourceReader(input);
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports System.Resources

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As {inputType})
            Dim formatter = New ResourceReader(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 10)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 7)).ConfigureAwait(false);
        }
    }
}
