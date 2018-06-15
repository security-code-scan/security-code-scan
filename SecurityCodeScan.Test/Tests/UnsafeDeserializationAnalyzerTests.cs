using System.Collections.Generic;
using System.Linq;
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
            return new DiagnosticAnalyzer[]
            {
                new UnsafeDeserializationAnalyzerCSharp(),
                new UnsafeDeserializationAnalyzerVisualBasic(),
                new TaintAnalyzerCSharp(),
                new TaintAnalyzerVisualBasic()
            };
        }

        private static readonly PortableExecutableReference[] References =
        {
            MetadataReference.CreateFromFile(typeof(JavaScriptSerializer).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(JsonSerializer).Assembly.Location),
        };

        protected override IEnumerable<MetadataReference> GetAdditionalReferences() => References;

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
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 8, 51)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 6, 34)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectJavaScriptSerializerWithSimpleTypeResolverAsFieldUsed()
        {
            var cSharpTest = @"
using System.Web.Script.Serialization;

namespace VulnerableApp
{
    class Test
    {
        private static SimpleTypeResolver resolver = new SimpleTypeResolver();
        private static JavaScriptSerializer serializer = new JavaScriptSerializer(resolver);
    }
}
";

            var visualBasicTest = @"
Imports System.Web.Script.Serialization

Namespace VulnerableApp
    Class Test
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

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 9, 58)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 7, 41)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task IgnoreJavaScriptSerializerWithNotCompilingParameterUsed()
        {
            var cSharpTest = @"
using System.Web.Script.Serialization;

namespace VulnerableApp
{
    class Test
    {
        private static JavaScriptSerializer serializer = new JavaScriptSerializer(resolver);
    }
}
";

            var visualBasicTest = @"
Imports System.Web.Script.Serialization

Namespace VulnerableApp
    Class Test
        Private Shared Dim serializer = new JavaScriptSerializer(resolver)
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, new DiagnosticResult { Id = "CS0103" }).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new DiagnosticResult { Id = "BC30451" }).ConfigureAwait(false);
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
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 8, 42)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 6, 43)).ConfigureAwait(false);
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

        [TestMethod]
        [Ignore] // todo: ignore the TypeNameHandling on deep clone (although it doesn't clone private members)
        public async Task IgnoreJSonSerializerTypeNameHandlingDeepclone()
        {
            var cSharpTest = @"
using Newtonsoft.Json;

namespace VulnerableApp
{
    class Test
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
                Id       = "SCS0028",
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 12, 40)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 9, 41)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectJSonSerializerTypeNameHandlingAllWithNamespace()
        {
            var cSharpTest = @"
namespace VulnerableApp
{
    class Test
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
    Class Test
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
                Severity = DiagnosticSeverity.Warning
            };

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 10, 40)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 7, 41)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectJSonSerializerTypeNameHandlingAllFromConstant()
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
                    TypeNameHandling = (TypeNameHandling)3
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

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 12, 40)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 9, 41)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectJSonSerializerTypeNameHandlingAllAfterSettingsConstruction()
        {
            var cSharpTest = @"
using Newtonsoft.Json;

namespace VulnerableApp
{
    class Test
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
    Class Test
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

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 11, 42)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 8, 42)).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task DetectJsonSerializerTypeNameHandlingUnknownRuntimeValue()
        {
            var cSharpTest = @"
using Newtonsoft.Json;

namespace VulnerableApp
{
    class Test
    {
        static void TestDeserialization(TypeNameHandling param)
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

Namespace VulnerableApp
    Class Test
        Private Sub TestDeserialization(param As TypeNameHandling)
            Dim settings = New JsonSerializerSettings With _
                {
                    .TypeNameHandling = param
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

            await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 12, 21)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 9, 21)).ConfigureAwait(false);
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

        [DataTestMethod]
        [DataRow("TypeNameHandling.Test", new[] { "CS0117" },            new[] { "BC30456" })]
        [DataRow("foo()",                 new[] { "CS0029" },            new[] { "BC30311" })]
        [DataRow("foo2(xyz)",             new[] { "SCS0028", "CS0103" }, new[] { "SCS0028", "BC30451" })]
        public async Task JSonSerializerTypeNameHandlingNonCompilingValue(string right, string[] csErrors, string[] vbErrors)
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
                    TypeNameHandling = {right}
                }};
        }}

        static Test foo()
        {{
            return null;
        }}

        static TypeNameHandling foo2(string a)
        {{
            return TypeNameHandling.All;
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
                    .TypeNameHandling = {right}
                }}
        End Sub

        Private Function foo() As Test
            Return Nothing
        End Function

        Private Function foo2(a As String) As TypeNameHandling
            Return TypeNameHandling.All
        End Function
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest,
                                         csErrors.Select(x => new DiagnosticResult { Id = x }.WithLocation("Test0.cs", 12)).ToArray())
                .ConfigureAwait(false);

            await VerifyVisualBasicDiagnostic(visualBasicTest,
                                              vbErrors.Select(x => new DiagnosticResult { Id = x }.WithLocation("Test0.vb", 9)).ToArray())
                .ConfigureAwait(false);
        }

        [TestMethod]
        public async Task IgnoreJSonSerializerTypeNameHandlingNonCompilingStringValue()
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
                    TypeNameHandling = ""test""
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
                    .TypeNameHandling = ""test""
                }
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, new DiagnosticResult { Id = "CS0029" }.WithLocation("Test0.cs", 12)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest).ConfigureAwait(false);
        }

        [TestMethod]
        public async Task IgnoreJsonSerializerTypeNameHandlingNonCompilingTypeAssigned()
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
                    TypeNameHandling = new System.Exception()
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
                    .TypeNameHandling = new System.Exception()
                }
        End Sub
    End Class
End Namespace
";

            await VerifyCSharpDiagnostic(cSharpTest, new DiagnosticResult { Id = "CS0029" }.WithLocation("Test0.cs", 12)).ConfigureAwait(false);
            await VerifyVisualBasicDiagnostic(visualBasicTest, new DiagnosticResult { Id = "BC30311" }.WithLocation("Test0.vb", 9)).ConfigureAwait(false);
        }
    }
}
