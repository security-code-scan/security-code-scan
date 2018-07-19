using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Config;

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
        public void EmptyUserConfig_NoChanges()
        {
            var options   = CreateAnalyzersOptionsWithConfig("");
            var newConfig = Manager.GetProjectConfiguration(options.AdditionalFiles);

            //ensuring that field count matches count of properties tested below (test should fail and be updated if someone adds new field in Configuration)
            Assert.AreEqual(9, typeof(Configuration).GetFields().Length);

            Assert.AreEqual(StartupConfiguration.AuditMode,                                 newConfig.AuditMode);
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
        public void MergingUserConfig_NoChanges()
        {
            var options   = CreateAnalyzersOptionsWithConfig("Sinks:");
            var newConfig = Manager.GetProjectConfiguration(options.AdditionalFiles);

            // ensuring that field count matches count of properties tested below
            Assert.AreEqual(9, typeof(Configuration).GetFields().Length);

            Assert.AreEqual(StartupConfiguration.AuditMode,                                 newConfig.AuditMode);
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
        public void DifferentConfigVersion_ChangesIgnored()
        {
            var options   = CreateAnalyzersOptionsWithConfig("MinimumPasswordValidatorProperties: 0", new Version(1,2));
            var newConfig = Manager.GetProjectConfiguration(options.AdditionalFiles);

            Assert.AreNotEqual(StartupConfiguration.MinimumPasswordValidatorProperties, 0);
            Assert.AreEqual(StartupConfiguration.MinimumPasswordValidatorProperties, newConfig.MinimumPasswordValidatorProperties);
        }
    }
}
