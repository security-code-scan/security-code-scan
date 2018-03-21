using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Soap;
using System.Threading.Tasks;
using System.Web.UI;
using System.Activities;
using System.Messaging;
using System.Runtime.Serialization.Json;
using System.Web.Script.Serialization;
using System.Xml.Serialization;
using fastJSON;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Helpers;
using Newtonsoft.Json;

namespace SecurityCodeScan.Test.Tests.Taint
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
            MetadataReference.CreateFromFile(typeof(JavaScriptSerializer).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(JsonSerializer).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(BinaryMessageFormatter).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(JSON).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(XmlSerializer).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(XmlMessageFormatter).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(ServiceStack.Text.JsonSerializer).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestMethod]
        public async Task DetectBinaryFormatterDeserializeMethod()
        {
            var cSharpTest = @"
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(Stream input)
        {
            var formatter = new BinaryFormatter();
            formatter.Deserialize(input);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.IO
Imports System.Runtime.Serialization.Formatters.Binary

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As Stream)
            Dim formatter = New BinaryFormatter()
            formatter.Deserialize(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectBinaryFormatterDeserializeMethod1()
        {
            var cSharpTest = @"
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(Stream input)
        {
            var formatter = new BinaryFormatter();
            formatter.Deserialize(input, null);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.IO
Imports System.Runtime.Serialization.Formatters.Binary

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As Stream)
            Dim formatter = New BinaryFormatter()
            formatter.Deserialize(input, Nothing)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectBinaryFormatterUnsafeDeserializeMethod()
        {
            var cSharpTest = @"
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(Stream input)
        {
            var formatter = new BinaryFormatter();
            formatter.UnsafeDeserialize(input, null);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.IO
Imports System.Runtime.Serialization.Formatters.Binary

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As Stream)
            Dim formatter = New BinaryFormatter()
            formatter.UnsafeDeserialize(input, Nothing)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectBinaryFormatterUnsafeDeserializeMethodResponseMethod()
        {
            var cSharpTest = @"
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(Stream input)
        {
            var formatter = new BinaryFormatter();
            formatter.UnsafeDeserializeMethodResponse(input, null, null);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.IO
Imports System.Runtime.Serialization.Formatters.Binary

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As Stream)
            Dim formatter = New BinaryFormatter()
            formatter.UnsafeDeserializeMethodResponse(input, Nothing, Nothing)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
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
                Id       = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

    [TestMethod]
        public async Task DetectSoapFormatterDeserializeMethod()
        {
            var cSharpTest = @"
using System.IO;
using System.Runtime.Serialization.Formatters.Soap;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(Stream input)
        {
            var formatter = new SoapFormatter();
            formatter.Deserialize(input);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.IO
Imports System.Runtime.Serialization.Formatters.Soap

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As Stream)
            Dim formatter = New SoapFormatter()
            formatter.Deserialize(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectSoapFormatterDeserializeMethod1()
        {
            var cSharpTest = @"
using System.IO;
using System.Runtime.Serialization.Formatters.Soap;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(Stream input)
        {
            var formatter = new SoapFormatter();
            formatter.Deserialize(input, null);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.IO
Imports System.Runtime.Serialization.Formatters.Soap

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As Stream)
            Dim formatter = New SoapFormatter()
            formatter.Deserialize(input, Nothing)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectObjectStateFormatterDeserializeMethod()
        {
            var cSharpTest = @"
using System.IO;
using System.Web.UI;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(Stream input)
        {
            var formatter = new ObjectStateFormatter();
            formatter.Deserialize(input);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.IO
Imports System.Web.UI

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As Stream)
            Dim formatter = New ObjectStateFormatter()
            formatter.Deserialize(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectObjectStateFormatterDeserializeMethod1()
        {
            var cSharpTest = @"
using System.Web.UI;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(string input)
        {
            var formatter = new ObjectStateFormatter();
            formatter.Deserialize(input);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Web.UI

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As String)
            Dim formatter = New ObjectStateFormatter()
            formatter.Deserialize(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectNetDataContractSerializerDeserializeMethod()
        {
            var cSharpTest = @"
using System.IO;
using System.Runtime.Serialization;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(Stream input)
        {
            var formatter = new NetDataContractSerializer();
            formatter.Deserialize(input);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.IO
Imports System.Runtime.Serialization

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As Stream)
            Dim formatter = New NetDataContractSerializer()
            formatter.Deserialize(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectNetDataContractSerializerReadObjectMethod()
        {
            var cSharpTest = @"
using System.IO;
using System.Runtime.Serialization;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(Stream input)
        {
            var formatter = new NetDataContractSerializer();
            formatter.ReadObject(input);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.IO
Imports System.Runtime.Serialization

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As Stream)
            Dim formatter = New NetDataContractSerializer()
            formatter.ReadObject(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectNetDataContractSerializerReadObjectMethod1()
        {
            var cSharpTest = @"
using System.Xml;
using System.Runtime.Serialization;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(XmlDictionaryReader input)
        {
            var formatter = new NetDataContractSerializer();
            formatter.ReadObject(input);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Xml
Imports System.Runtime.Serialization

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As XmlDictionaryReader)
            Dim formatter = New NetDataContractSerializer()
            formatter.ReadObject(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectNetDataContractSerializerReadObjectMethod2()
        {
            var cSharpTest = @"
using System.Xml;
using System.Runtime.Serialization;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(XmlDictionaryReader input)
        {
            var formatter = new NetDataContractSerializer();
            formatter.ReadObject(input, false);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Xml
Imports System.Runtime.Serialization

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As XmlDictionaryReader)
            Dim formatter = New NetDataContractSerializer()
            formatter.ReadObject(input, false)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectNetDataContractSerializerReadObjectMethod3()
        {
            var cSharpTest = @"
using System.Xml;
using System.Runtime.Serialization;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(XmlReader input)
        {
            var formatter = new NetDataContractSerializer();
            formatter.ReadObject(input);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Xml
Imports System.Runtime.Serialization

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As XmlReader)
            Dim formatter = New NetDataContractSerializer()
            formatter.ReadObject(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectNetDataContractSerializerReadObjectMethod4()
        {
            var cSharpTest = @"
using System.Xml;
using System.Runtime.Serialization;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(XmlReader input)
        {
            var formatter = new NetDataContractSerializer();
            formatter.ReadObject(input, false);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Xml
Imports System.Runtime.Serialization

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As XmlReader)
            Dim formatter = New NetDataContractSerializer()
            formatter.ReadObject(input, false)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectDataContractSerializerReadObjectMethod()
        {
            var cSharpTest = @"
using System.IO;
using System.Runtime.Serialization;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(Stream input)
        {
            var formatter = new DataContractSerializer(typeof(Test));
            formatter.ReadObject(input);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.IO
Imports System.Runtime.Serialization

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As Stream)
            Dim formatter = New DataContractSerializer(GetType(Test))
            formatter.ReadObject(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectDataContractSerializerReadObjectMethodAndConstructor()
        {
            var cSharpTest = @"
using System;
using System.Xml;
using System.Runtime.Serialization;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(XmlDictionaryReader input, Type objectType)
        {
            var formatter = new DataContractSerializer(objectType);
            formatter.ReadObject(input);
        }
    }
}
";

            var visualBasicTest = @"
Imports System
Imports System.Xml
Imports System.Runtime.Serialization

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As XmlDictionaryReader, objectType as Type)
            Dim formatter = New DataContractSerializer(objectType)
            formatter.ReadObject(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, new []{expected, expected}).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new []{expected, expected}).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectDataContractJsonSerializerReadObjectMethod()
        {
            var cSharpTest = @"
using System.IO;
using System.Runtime.Serialization.Json;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(Stream input)
        {
            var formatter = new DataContractJsonSerializer(typeof(Test));
            formatter.ReadObject(input);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.IO
Imports System.Runtime.Serialization.Json

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As Stream)
            Dim formatter = New DataContractJsonSerializer(GetType(Test))
            formatter.ReadObject(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectDataContractJsonSerializerReadObjectMethodAndConstructor()
        {
            var cSharpTest = @"
using System;
using System.Xml;
using System.Runtime.Serialization.Json;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(XmlDictionaryReader input, Type objectType)
        {
            var formatter = new DataContractJsonSerializer(objectType);
            formatter.ReadObject(input);
        }
    }
}
";

            var visualBasicTest = @"
Imports System
Imports System.Xml
Imports System.Runtime.Serialization.Json

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As XmlDictionaryReader, objectType as Type)
            Dim formatter = New DataContractJsonSerializer(objectType)
            formatter.ReadObject(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, new []{expected, expected}).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new []{expected, expected}).ConfigureAwait(false);
        }


        [TestMethod]
        public async Task DetectXmlSerializerDeserializeMethod()
        {
            var cSharpTest = @"
using System.IO;
using System.Xml.Serialization;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(Stream input)
        {
            var formatter = new XmlSerializer(typeof(Test));
            formatter.Deserialize(input);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.IO
Imports System.Xml.Serialization

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As Stream)
            Dim formatter = New XmlSerializer(GetType(Test))
            formatter.Deserialize(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectXmlSerializerDeserializeMethodAndConstructor()
        {
            var cSharpTest = @"
using System;
using System.Xml;
using System.Xml.Serialization;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(XmlDictionaryReader input, Type objectType)
        {
            var formatter = new XmlSerializer(objectType);
            formatter.Deserialize(input);
        }
    }
}
";

            var visualBasicTest = @"
Imports System
Imports System.Xml
Imports System.Xml.Serialization

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As XmlDictionaryReader, objectType as Type)
            Dim formatter = New XmlSerializer(objectType)
            formatter.Deserialize(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, new[] { expected, expected }).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new[] { expected, expected }).ConfigureAwait(false);
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
                Id       = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectLosFormatterDeserializeMethod()
        {
            var cSharpTest = @"
using System.IO;
using System.Web.UI;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(Stream input)
        {
            var formatter = new LosFormatter();
            formatter.Deserialize(input);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.IO
Imports System.Web.UI

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As Stream)
            Dim formatter = New LosFormatter()
            formatter.Deserialize(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectLosFormatterDeserializeMethod1()
        {
            var cSharpTest = @"
using System.Web.UI;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(string input)
        {
            var formatter = new LosFormatter();
            formatter.Deserialize(input);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.Web.UI

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As String)
            Dim formatter = New LosFormatter()
            formatter.Deserialize(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectLosFormatterDeserializeMethod2()
        {
            var cSharpTest = @"
using System.IO;
using System.Web.UI;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(TextReader input)
        {
            var formatter = new LosFormatter();
            formatter.Deserialize(input);
        }
    }
}
";

            var visualBasicTest = @"
Imports System.IO
Imports System.Web.UI

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As TextReader)
            Dim formatter = New LosFormatter()
            formatter.Deserialize(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
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
                Id       = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
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
                Id       = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectServiceStackJsonSerializerSerializeToStringMethod()
        {
            var cSharpTest = @"
using ServiceStack.Text;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(string input)
        {
            JsonSerializer.DeserializeFromString<Test>(input);
        }
    }
}
";

            var visualBasicTest = @"
Imports ServiceStack.Text

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As String)
            JsonSerializer.DeserializeFromString(Of Test)(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectServiceStackTypeSerializerSerializeToStringMethod()
        {
            var cSharpTest = @"
using ServiceStack.Text;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(string input)
        {
            TypeSerializer.DeserializeFromString<Test>(input);
        }
    }
}
";

            var visualBasicTest = @"
Imports ServiceStack.Text

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As String)
            TypeSerializer.DeserializeFromString(Of Test)(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectServiceStackCsvSerializerSerializeToStringMethod()
        {
            var cSharpTest = @"
using ServiceStack.Text;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(string input)
        {
            CsvSerializer.DeserializeFromString<Test>(input);
        }
    }
}
";

            var visualBasicTest = @"
Imports ServiceStack.Text

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(input As String)
            CsvSerializer.DeserializeFromString(Of Test)(input)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectJavaScriptSerializerWithSimpleTypeResolverUsed()
        {
            var cSharpTest = @"
using System.Web.Script.Serialization;

namespace VulnerableApp
{
    class Test
    {
        private JavaScriptSerializer serializer = new JavaScriptSerializer(new SimpleTypeResolver());
    }
}
";

            var visualBasicTest = @"
Imports System.Web.Script.Serialization

Namespace VulnerableApp
    Class Test
        Private Dim serializer = new JavaScriptSerializer(new SimpleTypeResolver())
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task IgnoreJavaScriptSerializerUsed()
        {
            var cSharpTest = @"
using System.Web.Script.Serialization;

namespace VulnerableApp
{
    class Test
    {
        private JavaScriptSerializer serializer = new JavaScriptSerializer();
    }
}
";

            var visualBasicTest = @"
Imports System.Web.Script.Serialization

Namespace VulnerableApp
    Class Test
        Private Dim serializer = new JavaScriptSerializer()
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [DataTestMethod]
        [DataRow("Objects")]
        [DataRow("Arrays")]
        [DataRow("All")]
        [DataRow("Auto")]
        public async Task DetectJSonSerializerTypeNameHandlingNotNoneOnProperty(string property)
        {
            var cSharpTest = $@"
using Newtonsoft.Json;

namespace VulnerableApp
{{
    class Test
    {{
        [JsonProperty(TypeNameHandling = TypeNameHandling.{property})]
        private string Property {{ get; set; }}
    }}
}}
";

            var visualBasicTest = $@"
Imports Newtonsoft.Json

Namespace VulnerableApp
    Class Test
        <JsonProperty(TypeNameHandling := TypeNameHandling.{property})>
        Public Property TestProperty As String
            Get
                Return ""Test""
            End Get
            Set(value As String)
            End Set
        End Property
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task IgnoreJSonSerializerTypeNameHandlingNoneOnProperty()
        {
            var cSharpTest = @"
using Newtonsoft.Json;

namespace VulnerableApp
{
    class Test
    {
        [JsonProperty(TypeNameHandling = TypeNameHandling.None)]
        private string Property { get; set; }
    }
}
";

            var visualBasicTest = @"
Imports Newtonsoft.Json

Namespace VulnerableApp
    Class Test
        <JsonProperty(TypeNameHandling := TypeNameHandling.None)>
        Public Property TestProperty As String
            Get
                Return ""Test""
            End Get
            Set(value As String)
            End Set
        End Property
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [DataTestMethod]
        [DataRow("Objects")]
        [DataRow("Arrays")]
        [DataRow("All")]
        [DataRow("Auto")]
        public async Task DetectJSonSerializerTypeNameHandlingNotNone(string property)
        {
            var cSharpTest = $@"
using Newtonsoft.Json;

namespace VulnerableApp
{{
    class Test
    {{
        static void TestDeserialization()
        {{
             var settings = new JsonSerializerSettings
                {{
                    TypeNameHandling = TypeNameHandling.{property}
                }};
        }}
    }}
}}
";

            var visualBasicTest = $@"
Imports Newtonsoft.Json

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization()
            Dim settings = New JsonSerializerSettings With _
                {{
                    .TypeNameHandling = TypeNameHandling.{property}
                }}
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0035",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 12)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 9)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task IgnoreJSonSerializerTypeNameHandlingNone()
        {
            var cSharpTest = @"
using Newtonsoft.Json;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization()
        {
             var settings = new JsonSerializerSettings
                {
                    TypeNameHandling = TypeNameHandling.None
                };
        }
    }
}
";

            var visualBasicTest = @"
Imports Newtonsoft.Json

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization()
            Dim settings = New JsonSerializerSettings With _
                {
                    .TypeNameHandling = TypeNameHandling.None
                }
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

    }
}
