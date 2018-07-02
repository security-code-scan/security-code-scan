using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Config;
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test.Config
{
    [TestClass]
    public class ConfigTest : ConfigurationTest
    {
        public ConfigTest()
        {
            Manager              = ConfigurationManager.Instance;
            StartupConfiguration = Manager.GetProjectConfiguration(ImmutableArray<AdditionalText>.Empty);
        }

        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers(string language)
        {
            return Enumerable.Empty<DiagnosticAnalyzer>();
        }

        private readonly ConfigurationManager Manager;
        private readonly Configuration        StartupConfiguration;

        [TestMethod]
        public async Task EmptyUserConfig_NoChanges()
        {
            var options   = await CreateAnalyzersOptionsWithConfig("");
            var newConfig = Manager.GetProjectConfiguration(options.AdditionalFiles);

            //ensuring that field count matches count of properties tested below (test should fail and be updated if someone adds new field in Configuration)
            Assert.AreEqual(8, typeof(Configuration).GetFields().Length);

            Assert.AreEqual(StartupConfiguration.Behavior.Count,                            newConfig.Behavior.Count);
            Assert.AreEqual(StartupConfiguration.Sinks.Count,                               newConfig.Sinks.Count);
            Assert.AreEqual(StartupConfiguration.MinimumPasswordValidatorProperties,        newConfig.MinimumPasswordValidatorProperties);
            Assert.AreEqual(StartupConfiguration.PasswordValidatorRequiredLength,           newConfig.PasswordValidatorRequiredLength);
            Assert.AreEqual(StartupConfiguration.PasswordValidatorRequiredProperties.Count, newConfig.PasswordValidatorRequiredProperties.Count);
            Assert.AreEqual(StartupConfiguration.PasswordFields.Count,                      newConfig.PasswordFields.Count);
            Assert.AreEqual(StartupConfiguration.ConstantFields.Count,                      newConfig.ConstantFields.Count);
            Assert.AreEqual(StartupConfiguration.AntiCsrfAttributes.Count,                  newConfig.AntiCsrfAttributes.Count);
        }

        [TestMethod]
        public async Task MergingUserConfig_NoChanges()
        {
            var options   = await CreateAnalyzersOptionsWithConfig("Sinks:");
            var newConfig = Manager.GetProjectConfiguration(options.AdditionalFiles);

            // ensuring that field count matches count of properties tested below
            Assert.AreEqual(8, typeof(Configuration).GetFields().Length);

            Assert.AreEqual(StartupConfiguration.Behavior.Count,                            newConfig.Behavior.Count);
            Assert.AreEqual(StartupConfiguration.Sinks.Count,                               newConfig.Sinks.Count);
            Assert.AreEqual(StartupConfiguration.MinimumPasswordValidatorProperties,        newConfig.MinimumPasswordValidatorProperties);
            Assert.AreEqual(StartupConfiguration.PasswordValidatorRequiredLength,           newConfig.PasswordValidatorRequiredLength);
            Assert.AreEqual(StartupConfiguration.PasswordValidatorRequiredProperties.Count, newConfig.PasswordValidatorRequiredProperties.Count);
            Assert.AreEqual(StartupConfiguration.PasswordFields.Count,                      newConfig.PasswordFields.Count);
            Assert.AreEqual(StartupConfiguration.ConstantFields.Count,                      newConfig.ConstantFields.Count);
            Assert.AreEqual(StartupConfiguration.AntiCsrfAttributes.Count,                  newConfig.AntiCsrfAttributes.Count);
        }
    }
}
