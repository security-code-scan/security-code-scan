using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityCodeScan.Analyzers;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test.Tests
{
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
    using System.Web.Script.Serialization;
    using System.Xml.Serialization;
    using fastJSON;
    using Microsoft.CodeAnalysis;
    using Microsoft.CodeAnalysis.Diagnostics;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Newtonsoft.Json;

    namespace SecurityCodeScan.Test.Tests.Taint
    {
        [TestClass]
        public class UnsafeDeserializationAnalyzerTests : DiagnosticVerifier
        {
            protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
            {
                return new DiagnosticAnalyzer[] { new UnsafeDeserializationAnalyzer() };
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
                    Id = "SCS0028",
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
                    Id = "SCS0028",
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
                    Id = "SCS0028",
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
                    Id = "SCS0028",
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
                    Id = "SCS0028",
                    Severity = DiagnosticSeverity.Warning
                };

                await VerifyCSharpDiagnostic(cSharpTest, expected.WithLocation("Test0.cs", 10, 40)).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, expected.WithLocation("Test0.vb", 7, 41)).ConfigureAwait(false);
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

            [TestMethod]
            public async Task IgnoreJSonSerializerTypeNameHandlingNonCompilingVallue()
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
                    TypeNameHandling = TypeNameHandling.Test
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
                    .TypeNameHandling = TypeNameHandling.Test
                }
        End Sub
    End Class
End Namespace
";

                await VerifyCSharpDiagnostic(cSharpTest, new DiagnosticResult { Id = "CS0117" }.WithLocation("Test0.cs", 12)).ConfigureAwait(false);
                await VerifyVisualBasicDiagnostic(visualBasicTest, new DiagnosticResult { Id = "BC30456" }.WithLocation("Test0.vb", 9)).ConfigureAwait(false);
            }

        }
    }

}
