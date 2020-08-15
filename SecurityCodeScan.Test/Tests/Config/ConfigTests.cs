using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Config;
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test.Config
{
    [TestClass]
    public class ConfigTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            return Enumerable.Empty<DiagnosticAnalyzer>();
        }

        [TestMethod]
        public void HandlingNewerConfigs()
        {
            var options = ConfigurationTest.CreateAnalyzersOptionsWithConfig(@"
Unknown: false
");
            // should not throw
            new Configuration(ConfigurationManager.GetProjectConfiguration(options.AdditionalFiles), null);
        }

        [TestMethod]
        public void ConflictingSanitizers1()
        {
            var options = ConfigurationTest.CreateAnalyzersOptionsWithConfig(@"
Sanitizers:

  - Type: System.Web.HttpUtility2
    TaintTypes:
      - SCS0029
    Methods:
      - Name: HtmlEncode

  - Type: System.Web.HttpUtility2
    TaintTypes:
      - SCS0029
    Methods:
      - Name: HtmlEncode
        ArgumentCount: 1
        InOut: [{""value"": "".Return""}, {""s"": "".Return""}]
      - Name: HtmlEncode
        ArgumentCount: 2
        InOut:
            [{ ""s"": ""output""}]

");
            Assert.ThrowsException<ArgumentException>(() => new Configuration(ConfigurationManager.GetProjectConfiguration(options.AdditionalFiles), null).TaintConfiguration);
        }

        [TestMethod]
        public void ConflictingSanitizers2()
        {
            var options = ConfigurationTest.CreateAnalyzersOptionsWithConfig(@"
Sanitizers:

  - Type: System.Web.HttpServerUtility2
    TaintTypes:
      - SCS0029
    Methods:
      - Name: HtmlEncode
        ArgumentCount: 1
        InOut: [{""s"": "".Return""}]
      - Name: HtmlEncode
        ArgumentCount: 2
        InOut:
            [{""s"": ""output""}]

  - Type: System.Web.HttpServerUtility2
    TaintTypes:
      - SCS0029
    Methods:
      - Name: UrlEncode

");
            Assert.ThrowsException<ArgumentException>(() => new Configuration(ConfigurationManager.GetProjectConfiguration(options.AdditionalFiles), null).TaintConfiguration);
        }

        [TestMethod]
        public void DifferentConfigVersion_Exception()
        {
            var options = ConfigurationTest.CreateAnalyzersOptionsWithConfig("MinimumPasswordValidatorProperties: 0", new Version(1,2));
            Assert.ThrowsException<ArgumentException>(() => new Configuration(ConfigurationManager.GetProjectConfiguration(options.AdditionalFiles), null));
        }
    }
}
