using System;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using SecurityCodeScan.Analyzers;

namespace SecurityCodeScan.Test
{
    [TestClass]
    public class WebConfigAnalyzerTest : ExternalFileAnalyzerTest
    {
        public WebConfigAnalyzerTest()
        {
            Initialize(new WebConfigAnalyzer());
        }

        [TestCategory("Detect")]
        [DataRow("<pages validateRequest=\"false\"></pages>", "<pages validateRequest=\"false\">")]
        [DataRow("<pages validateRequest=\" False \"></pages>", "<pages validateRequest=\" False \">")]
        [DataRow("<pages validateRequest=\"false\" />",       "<pages validateRequest=\"false\" />")]
        [DataRow("<pages validateRequest=\" False \" />",       "<pages validateRequest=\" False \" />")]
        [DataTestMethod]
        public async Task ValidateRequestVulnerable(string element, string expectedNode)
        {
            var config = $@"
<configuration>
    <system.web>
        {element}
    </system.web>
</configuration>
";

            var path = Guid.NewGuid().ToString();
            var expected = new
            {
                Id      = WebConfigAnalyzer.RuleValidateRequest.Id,
                Message = String.Format(WebConfigAnalyzer.RuleValidateRequest.MessageFormat.ToString(),
                                        path,
                                        4,
                                        expectedNode)
            };

            var diagnostics = await Analyze(config, path).ConfigureAwait(false);
            diagnostics.Verify(call => call(It.Is<Diagnostic>(d => d.Id                  == expected.Id
                                                                   && d.GetMessage(null) == expected.Message)));
        }

        [TestCategory("Safe")]
        [DataRow("<pages validateRequest=\"true\"></pages>")]
        [DataRow("<pages validateRequest=\" True \"></pages>")]
        [DataRow("<pages></pages>")]
        [TestMethod]
        public async Task ValidateRequestSafe(string element)
        {
            var config = $@"
<configuration>
    <not>
        <pages validateRequest=""false""></pages>
    </not>
    <system.web>
        {element}
    </system.web>
</configuration>
";

            var diagnostics = await Analyze(config, Guid.NewGuid().ToString()).ConfigureAwait(false);
            diagnostics.Verify(call => call(It.Is<Diagnostic>(d => d.Id == WebConfigAnalyzer.RuleValidateRequest.Id)), Times.Never);
        }

        [TestCategory("Detect")]
        [DataRow("<httpRuntime requestValidationMode=\"2.0\"></httpRuntime>", "<httpRuntime requestValidationMode=\"2.0\">")]
        [DataRow("<httpRuntime requestValidationMode=\" 2.0\" />",             "<httpRuntime requestValidationMode=\" 2.0\" />")]
        [DataRow("<httpRuntime requestValidationMode=\" 3.0\"></httpRuntime>", "<httpRuntime requestValidationMode=\" 3.0\">")]
        [DataRow("<httpRuntime requestValidationMode=\"3.0\" />",             "<httpRuntime requestValidationMode=\"3.0\" />")]
        [DataRow("<httpRuntime requestValidationMode=\"3.5\"></httpRuntime>", "<httpRuntime requestValidationMode=\"3.5\">")]
        [DataRow("<httpRuntime requestValidationMode=\"3.5\" />",             "<httpRuntime requestValidationMode=\"3.5\" />")]
        [DataTestMethod]
        public async Task RequestValidationModeVulnerable(string element, string expectedNode)
        {
            var config = $@"
<configuration>
    <system.web>
        {element}
    </system.web>
</configuration>
";

            var path     = Guid.NewGuid().ToString();
            var expected = new
            {
                Id      = WebConfigAnalyzer.RuleRequestValidationMode.Id,
                Message = String.Format(WebConfigAnalyzer.RuleRequestValidationMode.MessageFormat.ToString(),
                                        path,
                                        4,
                                        expectedNode)
            };

            var diagnostics = await Analyze(config, path).ConfigureAwait(false);
            diagnostics.Verify(call => call(It.Is<Diagnostic>(d => d.Id                  == expected.Id
                                                                   && d.GetMessage(null) == expected.Message)));
        }

        [TestCategory("Safe")]
        [DataRow("<httpRuntime requestValidationMode=\"4.0\"></httpRuntime>")]
        [DataRow("<httpRuntime requestValidationMode=\"4.5\"></httpRuntime>")]
        [DataRow("<httpRuntime></httpRuntime>")]
        [TestMethod]
        public async Task RequestValidationModeSafe(string element)
        {
            var config = $@"
<configuration>
    <not>
        <httpRuntime requestValidationMode=""false""></httpRuntime>
    </not>
    <system.web>
        {element}
    </system.web>
</configuration>
";

            var diagnostics = await Analyze(config, Guid.NewGuid().ToString()).ConfigureAwait(false);
            diagnostics.Verify(call => call(It.Is<Diagnostic>(d => d.Id == WebConfigAnalyzer.RuleRequestValidationMode.Id)), Times.Never);
        }

        [TestCategory("Detect")]
        [DataRow("<httpRuntime requestValidationMode=\"2.0\"></httpRuntime>", "<httpRuntime requestValidationMode=\"2.0\">")]
        [DataRow("<httpRuntime requestValidationMode=\" 2.0\" />", "<httpRuntime requestValidationMode=\" 2.0\" />")]
        [DataRow("<httpRuntime requestValidationMode=\" 3.0\"></httpRuntime>", "<httpRuntime requestValidationMode=\" 3.0\">")]
        [DataRow("<httpRuntime requestValidationMode=\"3.0\" />", "<httpRuntime requestValidationMode=\"3.0\" />")]
        [DataRow("<httpRuntime requestValidationMode=\"3.5\"></httpRuntime>", "<httpRuntime requestValidationMode=\"3.5\">")]
        [DataRow("<httpRuntime requestValidationMode=\"3.5\" />", "<httpRuntime requestValidationMode=\"3.5\" />")]
        [DataTestMethod]
        public async Task RequestValidationModeLocationVulnerable(string element, string expectedNode)
        {
            var config = $@"
<configuration>
    <location path=""about"">
        <system.web>
            {element}
        </system.web>
    </location>
    <location path=""contact"">
        <system.web>
            {element}
        </system.web>
    </location>
</configuration>
";

            var path = Guid.NewGuid().ToString();
            var expected = new
            {
                Id = WebConfigAnalyzer.RuleRequestValidationMode.Id,
                Message = String.Format(WebConfigAnalyzer.RuleRequestValidationMode.MessageFormat.ToString(),
                                        path,
                                        5,
                                        expectedNode)
            };
            var expected2 = new
            {
                Id      = WebConfigAnalyzer.RuleRequestValidationMode.Id,
                Message = String.Format(WebConfigAnalyzer.RuleRequestValidationMode.MessageFormat.ToString(),
                                        path,
                                        10,
                                        expectedNode)
            };

            var diagnostics = await Analyze(config, path).ConfigureAwait(false);
            diagnostics.Verify(call => call(It.Is<Diagnostic>(d => d.Id                  == expected.Id)), Times.Exactly(2));
            diagnostics.Verify(call => call(It.Is<Diagnostic>(d => d.Id                  == expected.Id
                                                                   && d.GetMessage(null) == expected.Message)), Times.Once);
            diagnostics.Verify(call => call(It.Is<Diagnostic>(d => d.Id                  == expected2.Id
                                                                   && d.GetMessage(null) == expected2.Message)), Times.Once);
        }

        [TestCategory("Safe")]
        [DataRow("<httpRuntime requestValidationMode=\"4.0\"></httpRuntime>")]
        [DataRow("<httpRuntime requestValidationMode=\"4.5\"></httpRuntime>")]
        [DataRow("<httpRuntime></httpRuntime>")]
        [TestMethod]
        public async Task RequestValidationModeLocationSafe(string element)
        {
            var config = $@"
<configuration>
    <not>
        <httpRuntime requestValidationMode=""false""></httpRuntime>
    </not>
    <location path=""about"">
        <system.web>
            {element}
        </system.web>
    </location>
</configuration>
";

            var diagnostics = await Analyze(config, Guid.NewGuid().ToString()).ConfigureAwait(false);
            diagnostics.Verify(call => call(It.Is<Diagnostic>(d => d.Id == WebConfigAnalyzer.RuleRequestValidationMode.Id)), Times.Never);
        }

        [TestCategory("Detect")]
        [DataRow("<pages enableEventValidation=\"false\"></pages>", "<pages enableEventValidation=\"false\">")]
        [DataRow("<pages enableEventValidation=\" False \"></pages>", "<pages enableEventValidation=\" False \">")]
        [DataRow("<pages enableEventValidation=\"false\" />",       "<pages enableEventValidation=\"false\" />")]
        [DataRow("<pages enableEventValidation=\" False \" />",       "<pages enableEventValidation=\" False \" />")]
        [DataTestMethod]
        public async Task EnableEventValidationVulnerable(string element, string expectedNode)
        {
            var config = $@"
<configuration>
    <system.web>
        {element}
    </system.web>
</configuration>
";

            var path = Guid.NewGuid().ToString();
            var expected = new
            {
                Id = WebConfigAnalyzer.RuleEnableEventValidation.Id,
                Message = String.Format(WebConfigAnalyzer.RuleEnableEventValidation.MessageFormat.ToString(),
                                        path,
                                        4,
                                        expectedNode)
            };

            var diagnostics = await Analyze(config, path).ConfigureAwait(false);
            diagnostics.Verify(call => call(It.Is<Diagnostic>(d => d.Id                  == expected.Id)), Times.Once);
            diagnostics.Verify(call => call(It.Is<Diagnostic>(d => d.Id                  == expected.Id
                                                                   && d.GetMessage(null) == expected.Message)), Times.Once);
        }

        [TestCategory("Safe")]
        [DataRow("<pages enableEventValidation=\"true\"></pages>")]
        [DataRow("<pages enableEventValidation=\" True \"></pages>")]
        [DataRow("<pages></pages>")]
        [TestMethod]
        public async Task EnableEventValidationSafe(string element)
        {
            var config = $@"
<configuration>
    <not>
        <pages enableEventValidation=""false""></pages>
    </not>
    <system.web>
        {element}
    </system.web>
</configuration>
";

            var diagnostics = await Analyze(config, Guid.NewGuid().ToString()).ConfigureAwait(false);
            diagnostics.Verify(call => call(It.Is<Diagnostic>(d => d.Id == WebConfigAnalyzer.RuleEnableEventValidation.Id)), Times.Never);
        }

        [TestCategory("Detect")]
        [DataRow("<pages viewStateEncryptionMode=\"Auto\"></pages>", "<pages viewStateEncryptionMode=\"Auto\"></pages>",
            "<pages viewStateEncryptionMode=\"Auto\">", 9)]
        [DataRow("<pages viewStateEncryptionMode=\" auto \"></pages>", "<pages viewStateEncryptionMode=\" auto \"></pages>",
            "<pages viewStateEncryptionMode=\" auto \">", 9)]
        [DataRow("<pages viewStateEncryptionMode=\"Auto\" />", "<pages viewStateEncryptionMode=\"Auto\" />",
            "<pages viewStateEncryptionMode=\"Auto\" />", 9)]
        [DataRow("<pages viewStateEncryptionMode=\"auto\" />", "<pages viewStateEncryptionMode=\"auto\" />",
            "<pages viewStateEncryptionMode=\"auto\" />", 9)]
        [DataRow("<pages viewStateEncryptionMode=\"Never\"></pages>", "<pages viewStateEncryptionMode=\"Never\"></pages>",
            "<pages viewStateEncryptionMode=\"Never\">", 9)]
        [DataRow("<pages viewStateEncryptionMode=\"never\"></pages>", "<pages viewStateEncryptionMode=\"never\"></pages>",
            "<pages viewStateEncryptionMode=\"never\">", 9)]
        [DataRow("<pages viewStateEncryptionMode=\"Never\" />", "<pages viewStateEncryptionMode=\"Never\" />",
            "<pages viewStateEncryptionMode=\"Never\" />", 9)]
        [DataRow("<pages viewStateEncryptionMode=\" never \" />", "<pages viewStateEncryptionMode=\" never \" />",
            "<pages viewStateEncryptionMode=\" never \" />", 9)]
        [DataRow("<pages></pages>", "<pages></pages>", "<pages>", 9)]
        [DataRow("", "<pages></pages>", "<system.web>", 8)]
        [DataRow("<pages viewStateEncryptionMode=\"Always\"></pages>",
            "<pages viewStateEncryptionMode=\"Auto\"></pages>",
            "<pages viewStateEncryptionMode=\"Auto\">", 5)]
        [DataTestMethod]
        public async Task ViewStateEncryptionModeVulnerable(string mainElement, string locationElement, string expectedNode, int line)
        {
            var config = $@"
<configuration>
    <location path=""about"">
        <system.web>
            {locationElement}
        </system.web>
    </location>
    <system.web>
        {mainElement}
    </system.web>
</configuration>
";

            var path = Guid.NewGuid().ToString();
            var expected = new
            {
                Id = WebConfigAnalyzer.RuleViewStateEncryptionMode.Id,
                Message = String.Format(WebConfigAnalyzer.RuleViewStateEncryptionMode.MessageFormat.ToString(),
                                        path,
                                        line,
                                        expectedNode)
            };

            var diagnostics = await Analyze(config, path).ConfigureAwait(false);
            diagnostics.Verify(call => call(It.Is<Diagnostic>(d => d.Id                  == expected.Id)), Times.Once);
            diagnostics.Verify(call => call(It.Is<Diagnostic>(d => d.Id                  == expected.Id
                                                                   && d.GetMessage(null) == expected.Message)), Times.Once);
        }

        [TestCategory("Safe")]
        [DataRow("<pages viewStateEncryptionMode=\"Always\"></pages>")]
        [DataRow("<pages viewStateEncryptionMode=\"always\"></pages>")]
        [TestMethod]
        public async Task ViewStateEncryptionModeSafe(string element)
        {
            var config = $@"
<configuration>
    <not>
        <pages viewStateEncryptionMode=""Never""></pages>
    </not>
    <system.web>
        {element}
    </system.web>
</configuration>
";

            var diagnostics = await Analyze(config, Guid.NewGuid().ToString()).ConfigureAwait(false);
            diagnostics.Verify(call => call(It.Is<Diagnostic>(d => d.Id == WebConfigAnalyzer.RuleViewStateEncryptionMode.Id)), Times.Never);
        }

        [TestCategory("Detect")]
        [DataRow("<pages enableViewStateMac=\"false\"></pages>", "<pages enableViewStateMac=\"false\">")]
        [DataRow("<pages enableViewStateMac=\" False \"></pages>", "<pages enableViewStateMac=\" False \">")]
        [DataRow("<pages enableViewStateMac=\"false\" />",       "<pages enableViewStateMac=\"false\" />")]
        [DataRow("<pages enableViewStateMac=\" False \" />",       "<pages enableViewStateMac=\" False \" />")]
        [DataTestMethod]
        public async Task EnableViewStateMacVulnerable(string element, string expectedNode)
        {
            var config = $@"
<configuration>
    <system.web>
        {element}
    </system.web>
</configuration>
";

            var path = Guid.NewGuid().ToString();
            var expected = new
            {
                Id = WebConfigAnalyzer.RuleEnableViewStateMac.Id,
                Message = String.Format(WebConfigAnalyzer.RuleEnableViewStateMac.MessageFormat.ToString(),
                                        path,
                                        4,
                                        expectedNode)
            };

            var diagnostics = await Analyze(config, path).ConfigureAwait(false);
            diagnostics.Verify(call => call(It.Is<Diagnostic>(d => d.Id                  == expected.Id)), Times.Once);
            diagnostics.Verify(call => call(It.Is<Diagnostic>(d => d.Id                  == expected.Id
                                                                   && d.GetMessage(null) == expected.Message)), Times.Once);
        }

        [TestCategory("Safe")]
        [DataRow("<pages enableViewStateMac=\"true\"></pages>")]
        [DataRow("<pages enableViewStateMac=\" True \"></pages>")]
        [DataRow("<pages></pages>")]
        [TestMethod]
        public async Task EnableViewStateMacSafe(string element)
        {
            var config = $@"
<configuration>
    <not>
        <pages enableViewStateMac=""false""></pages>
    </not>
    <system.web>
        {element}
    </system.web>
</configuration>
";

            var diagnostics = await Analyze(config, Guid.NewGuid().ToString()).ConfigureAwait(false);
            diagnostics.Verify(call => call(It.Is<Diagnostic>(d => d.Id == WebConfigAnalyzer.RuleEnableViewStateMac.Id)), Times.Never);
        }
    }
}
