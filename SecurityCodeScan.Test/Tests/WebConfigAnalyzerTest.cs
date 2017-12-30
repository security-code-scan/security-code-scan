using System;
using System.Text;
using System.Threading;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using SecurityCodeScan.Analyzers;

namespace SecurityCodeScan.Test.Tests
{
    [TestClass]
    public class WebConfigAnalyzerTest
    {
        //ValidateRequest

        [TestMethod]
        public void ValidateRequestFalseVulnerable1()
        {
            string config = @"
<configuration>
<pages validateRequest=""false"">
</pages>
</configuration>
";
            
            analyzeConfiguration(config).Verify(call => call(It.IsAny<Diagnostic>()));
        }

        [TestMethod]
        public void ValidateRequestFalseVulnerable2()
        {
            string config = @"
<configuration>
<pages validateRequest=""False"">
</pages>
</configuration>
";

            analyzeConfiguration(config).Verify(call => call(It.IsAny<Diagnostic>()));
        }

        [TestMethod]
        public void ValidateRequestFalsePositive1()
        {
            string config = @"
<configuration>
<pages validateRequest=""true"">
</pages>
</configuration>
";

            analyzeConfiguration(config).Verify(call => call(It.IsAny<Diagnostic>()),Times.Never);
        }

        [TestMethod]
        public void ValidateRequestFalsePositive2()
        {
            string config = @"
<configuration>
<pages>
</pages>
</configuration>
";

            analyzeConfiguration(config).Verify(call => call(It.IsAny<Diagnostic>()), Times.Never);
        }

        //EnableEventValidation
        
        [TestMethod]
        public void EnableEventValidationVulnerable1()
        {
            string config = @"
<configuration>
<pages EnableEventValidation=""false"">
</pages>
</configuration>
";

            analyzeConfiguration(config).Verify(call => call(It.IsAny<Diagnostic>()));
        }

        [TestMethod]
        public void EnableEventValidationVulnerable2()
        {
            string config = @"
<configuration>
<pages enableEventValidation=""False"">
</pages>
</configuration>
";

            analyzeConfiguration(config).Verify(call => call(It.IsAny<Diagnostic>()));
        }

        [TestMethod]
        public void EnableEventValidationFalsePositive1()
        {
            string config = @"
<configuration>
<pages enableEventValidation=""true"">
</pages>
</configuration>
";

            analyzeConfiguration(config).Verify(call => call(It.IsAny<Diagnostic>()), Times.Never);
        }

        [TestMethod]
        public void EnableEventValidationFalsePositive2()
        {
            string config = @"
<configuration>
<pages>
</pages>
</configuration>
";

            analyzeConfiguration(config).Verify(call => call(It.IsAny<Diagnostic>()), Times.Never);
        }

        //ViewStateEncryptionMode

        [TestMethod]
        public void ViewStateEncryptionModeVulnerable1()
        {
            string config = @"
<configuration>
<pages ViewStateEncryptionMode=""auto"">
</pages>
</configuration>
";

            analyzeConfiguration(config).Verify(call => call(It.IsAny<Diagnostic>()));
        }

        [TestMethod]
        public void ViewStateEncryptionModeVulnerable2()
        {
            string config = @"
<configuration>
<pages ViewStateEncryptionMode=""Never"">
</pages>
</configuration>
";

            analyzeConfiguration(config).Verify(call => call(It.IsAny<Diagnostic>()));
        }

        [TestMethod]
        public void ViewStateEncryptionModeFalsePositive1()
        {
            string config = @"
<configuration>
<pages ViewStateEncryptionMode=""Always"">
</pages>
</configuration>
";

            analyzeConfiguration(config).Verify(call => call(It.IsAny<Diagnostic>()), Times.Never);
        }

        [TestMethod]
        public void ViewStateEncryptionModeFalsePositive2()
        {
            string config = @"
<configuration>
<pages>
</pages>
</configuration>
";

            analyzeConfiguration(config).Verify(call => call(It.IsAny<Diagnostic>()), Times.Never);
        }

        //EnableViewStateMac
        
        [TestMethod]
        public void EnableViewStateMacVulnerable1()
        {
            string config = @"
<configuration>
<pages enableViewStateMac=""false"">
</pages>
</configuration>
";

            analyzeConfiguration(config).Verify(call => call(It.IsAny<Diagnostic>()));
        }

        [TestMethod]
        public void EnableViewStateMacVulnerable2()
        {
            string config = @"
<configuration>
<pages enableViewStateMac=""False"">
</pages>
</configuration>
";

            analyzeConfiguration(config).Verify(call => call(It.IsAny<Diagnostic>()));
        }

        [TestMethod]
        public void EnableViewStateMacFalsePositive1()
        {
            string config = @"
<configuration>
<pages enableViewStateMac=""True"">
</pages>
</configuration>
";

            analyzeConfiguration(config).Verify(call => call(It.IsAny<Diagnostic>()), Times.Never);
        }

        [TestMethod]
        public void EnableViewStateMacFalsePositive2()
        {
            string config = @"
<configuration>
<pages>
</pages>
</configuration>
";

            analyzeConfiguration(config).Verify(call => call(It.IsAny<Diagnostic>()), Times.Never);
        }


        private Mock<Action<Diagnostic>> analyzeConfiguration(string config)
        {
            var analyzer = new WebConfigAnalyzer();

            var additionalTextMock = new Mock<AdditionalText>();
            additionalTextMock.Setup(text => text.Path).Returns("YOLO"); //The path is read when the diagnostic is report

            var diagnosticReportMock = new Mock<Action<Diagnostic>>(MockBehavior.Loose); //Will recorded the reported diagnostic..

            var compilation = new CompilationAnalysisContext(null, //
                null, diagnosticReportMock.Object, //
                d => true, CancellationToken.None);

            analyzer.AnalyzeConfigurationFile(config, additionalTextMock.Object, compilation);
            return diagnosticReportMock;
        }


    }

}
