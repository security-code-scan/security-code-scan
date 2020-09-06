using System.Collections.Generic;
using System.Threading.Tasks;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Test.Helpers;
using System.Web.Script.Serialization;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using SecurityCodeScan.Analyzers.Taint;

namespace SecurityCodeScan.Test
{
    [TestClass]
    public class UnsafeDeserializationAnalyzerTests : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            if (language == LanguageNames.CSharp)
                return new DiagnosticAnalyzer[] { new DeserializationTaintAnalyzer(), new UnsafeDeserializationAnalyzerCSharp() };
            else
                return new DiagnosticAnalyzer[] { new DeserializationTaintAnalyzer(), new UnsafeDeserializationAnalyzerVisualBasic() };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(JavaScriptSerializer).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(JsonSerializer).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Web.Mvc.Controller).Assembly.Location)
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectJavaScriptSerializerWithSimpleTypeResolverUsed()
        {
            var cSharpTest = @"
using System.Web.Script.Serialization;

namespace VulnerableApp
{
    public class Test
    {
        private JavaScriptSerializer serializer = new JavaScriptSerializer(new SimpleTypeResolver());
    }
}
";

            var visualBasicTest = @"
Imports System.Web.Script.Serialization

Namespace VulnerableApp
    Public Class Test
        Private Dim serializer = new JavaScriptSerializer(new SimpleTypeResolver())
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation(8, 51)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation(6, 34)).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectJavaScriptSerializerWithSimpleTypeResolverAsFieldUsed()
        {
            var cSharpTest = @"
using System.Web.Script.Serialization;

namespace VulnerableApp
{
    public class Test
    {
        private static SimpleTypeResolver resolver = new SimpleTypeResolver();
        private static JavaScriptSerializer serializer = new JavaScriptSerializer(resolver);
    }
}
";

            var visualBasicTest = @"
Imports System.Web.Script.Serialization

Namespace VulnerableApp
    Public Class Test
        Private Shared Dim resolver = new SimpleTypeResolver()
        Private Shared Dim serializer = new JavaScriptSerializer(resolver)
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation(9, 58)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation(7, 41)).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task IgnoreJavaScriptSerializerWithNotCompilingParameterUsed()
        {
            var cSharpTest = @"
using System.Web.Script.Serialization;

namespace VulnerableApp
{
    public class Test
    {
        private static JavaScriptSerializer serializer = new JavaScriptSerializer(resolver);
    }
}
";

            var visualBasicTest = @"
Imports System.Web.Script.Serialization

Namespace VulnerableApp
    Public Class Test
        Private Shared Dim serializer = new JavaScriptSerializer(resolver)
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, new DiagnosticResult { Id = "CS0103" }).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new DiagnosticResult { Id = "BC30451" }).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task IgnoreJavaScriptSerializerUsed()
        {
            var cSharpTest = @"
using System.Web.Script.Serialization;

namespace VulnerableApp
{
    public class Test
    {
        private JavaScriptSerializer serializer = new JavaScriptSerializer();
    }
}
";

            var visualBasicTest = @"
Imports System.Web.Script.Serialization

Namespace VulnerableApp
    Public Class Test
        Private Dim serializer = new JavaScriptSerializer()
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
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
    public class Test
    {{
        [JsonProperty(TypeNameHandling = TypeNameHandling.{property})]
        private string Property {{ get; set; }}
    }}
}}
";

            var visualBasicTest = $@"
Imports Newtonsoft.Json

Namespace VulnerableApp
    Public Class Test
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
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation(8, 42)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation(6, 43)).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task IgnoreJSonSerializerTypeNameHandlingNoneOnProperty()
        {
            var cSharpTest = @"
using Newtonsoft.Json;

namespace VulnerableApp
{
    public class Test
    {
        [JsonProperty(TypeNameHandling = TypeNameHandling.None)]
        private string Property { get; set; }
    }
}
";

            var visualBasicTest = @"
Imports Newtonsoft.Json

Namespace VulnerableApp
    Public Class Test
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

        [TestCategory("Safe")]
        [TestMethod]
        [Ignore("ignore the TypeNameHandling on deep clone (although it doesn't clone private members)")]
        public async Task IgnoreJSonSerializerTypeNameHandlingDeepclone()
        {
            var cSharpTest = @"
using Newtonsoft.Json;

namespace VulnerableApp
{
    public class Test
    {
        public T DeepClone<T>(T source)
        {
            var serializeSettings = new JsonSerializerSettings {TypeNameHandling = TypeNameHandling.All};
            var serialized = JsonConvert.SerializeObject(source, serializeSettings);
            return JsonConvert.DeserializeObject<T>(serialized, serializeSettings);
        }
    }
}
";

            await VerifyCSharpDiagnostic(cSharpTest).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
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
    public class Test
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
    Public Class Test
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
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation(12, 40)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation(9, 41)).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectJSonSerializerTypeNameHandlingAllWithNamespace()
        {
            var cSharpTest = @"
namespace VulnerableApp
{
    public class Test
    {
        static void TestDeserialization()
        {
             var settings = new Newtonsoft.Json.JsonSerializerSettings
                {
                    TypeNameHandling = Newtonsoft.Json.TypeNameHandling.All
                };
        }
    }
}
";

            var visualBasicTest = @"
Namespace VulnerableApp
    Public Class Test
        Private Sub TestDeserialization()
            Dim settings = New Newtonsoft.Json.JsonSerializerSettings With _
                {
                    .TypeNameHandling = Newtonsoft.Json.TypeNameHandling.All
                }
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning,
                Message  = "TypeNameHandling is set to the other value than 'None'. It may lead to deserialization vulnerability."
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation(10, 40)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation(7, 41)).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectJSonSerializerTypeNameHandlingAllFromConstant()
        {
            var cSharpTest = @"
using Newtonsoft.Json;

namespace VulnerableApp
{
    public class Test
    {
        static void TestDeserialization()
        {
             var settings = new JsonSerializerSettings
                {
                    TypeNameHandling = (TypeNameHandling)3
                };
        }
    }
}
";

            var visualBasicTest = @"
Imports Newtonsoft.Json

Namespace VulnerableApp
    Public Class Test
        Private Sub TestDeserialization()
            Dim settings = New JsonSerializerSettings With
                {
                    .TypeNameHandling = 3
                }
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation(12, 40)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation(9, 41)).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectJSonSerializerTypeNameHandlingAllAfterSettingsConstruction()
        {
            var cSharpTest = @"
using Newtonsoft.Json;

namespace VulnerableApp
{
    public class Test
    {
        static void TestDeserialization()
        {
             var settings = new JsonSerializerSettings();
             settings.TypeNameHandling = TypeNameHandling.All;
        }
    }
}
";

            var visualBasicTest = @"
Imports Newtonsoft.Json

Namespace VulnerableApp
    Public Class Test
        Private Sub TestDeserialization()
            Dim settings = New JsonSerializerSettings()
             settings.TypeNameHandling = TypeNameHandling.All
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult()
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation(11, 42)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation(8, 42)).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task DetectJsonSerializerTypeNameHandlingUnknownRuntimeValue()
        {
            var cSharpTest = @"
using Newtonsoft.Json;
using System.Web.Mvc;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        public void TestDeserialization(TypeNameHandling param)
        {
                var settings = new JsonSerializerSettings
                {
                    TypeNameHandling = param
                };
        }
    }
}
";

            var visualBasicTest = @"
Imports Newtonsoft.Json
Imports System.Web.Mvc

Namespace VulnerableApp
    Public Class TestController
        Inherits Controller

        Public Sub TestDeserialization(param As TypeNameHandling)
            Dim settings = New JsonSerializerSettings With _
                {
                    .TypeNameHandling = param
                }
        End Sub
    End Class
End Namespace
";
            var expected = new DiagnosticResult
            {
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning,
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation(13, 21)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation(12, 22)).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task IgnoreJSonSerializerTypeNameHandlingNone()
        {
            var cSharpTest = @"
using Newtonsoft.Json;

namespace VulnerableApp
{
    public class Test
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
    Public Class Test
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

        [TestCategory("Safe")]
        [TestMethod]
        public async Task IgnoreJSonSerializerTypeNameHandlingNonCompilingStringValue()
        {
            var cSharpTest = @"
using Newtonsoft.Json;

namespace VulnerableApp
{
    public class Test
    {
        static void TestDeserialization()
        {
             var settings = new JsonSerializerSettings
                {
                    TypeNameHandling = ""test""
                };
        }
    }
}
";

            var visualBasicTest = @"
Imports Newtonsoft.Json

Namespace VulnerableApp
    Public Class Test
        Private Sub TestDeserialization()
            Dim settings = New JsonSerializerSettings With _
                {
                    .TypeNameHandling = ""test""
                }
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, new DiagnosticResult { Id = "CS0029" }.WithLocation(12)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestCategory("Safe")]
        [TestMethod]
        public async Task IgnoreJsonSerializerTypeNameHandlingNonCompilingTypeAssigned()
        {
            var cSharpTest = @"
using Newtonsoft.Json;

namespace VulnerableApp
{
    public class Test
    {
        static void TestDeserialization()
        {
                var settings = new JsonSerializerSettings
                {
                    TypeNameHandling = new System.Exception()
                };
        }
    }
}
";

            var visualBasicTest = @"
Imports Newtonsoft.Json

Namespace VulnerableApp
    Public Class Test
        Private Sub TestDeserialization()
            Dim settings = New JsonSerializerSettings With _
                {
                    .TypeNameHandling = new System.Exception()
                }
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, new DiagnosticResult { Id = "CS0029" }.WithLocation(12)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new DiagnosticResult { Id = "BC30311" }.WithLocation(9)).ConfigureAwait(false);
        }

        [TestCategory("Detect")]
        [TestMethod]
        public async Task GivenAliasDirective_DetectDiagnostic()
        {
            var cSharpTest = @"
using System.Web.Script.Serialization;
using JSS = System.Web.Script.Serialization.JavaScriptSerializer;

namespace VulnerableApp
{
    public class Test
    {
        private JSS serializer = new JSS(new SimpleTypeResolver());
    }
}
";
            var visualBasicTest = @"
Imports System.Web.Script.Serialization
Imports JSS = System.Web.Script.Serialization.JavaScriptSerializer

Namespace VulnerableApp
    Public Class Test
        Private Dim serializer = new JSS(new SimpleTypeResolver())
    End Class
End Namespace
";
            var expected = new DiagnosticResult()
            {
                Id = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation(9, 34)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation(7, 34)).ConfigureAwait(false);
        }
    }
}
