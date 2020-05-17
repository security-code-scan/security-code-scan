using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Reflection;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityCodeScan.Config;
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test.Config
{
    [TestClass]
    public class ConfigTest : DiagnosticVerifier
    {
        public ConfigTest()
        {
            Manager              = new ConfigurationManager();
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
            var options   = ConfigurationTest.CreateAnalyzersOptionsWithConfig("");
            var newConfig = Manager.GetProjectConfiguration(options.AdditionalFiles);

            //ensuring that field count matches count of properties tested below (test should fail and be updated if someone adds new field in Configuration)
            Assert.AreEqual(12, typeof(Configuration).GetProperties(BindingFlags.Instance | BindingFlags.Public).Length);

            Assert.AreEqual(StartupConfiguration.ReportAnalysisCompletion,                  newConfig.ReportAnalysisCompletion);
            Assert.AreEqual(StartupConfiguration.AuditMode,                                 newConfig.AuditMode);
            Assert.AreEqual(StartupConfiguration.Behavior.Count,                            newConfig.Behavior.Count);
            Assert.AreEqual(StartupConfiguration.TaintEntryPoints.Count,                    newConfig.TaintEntryPoints.Count);
            Assert.AreEqual(StartupConfiguration.MinimumPasswordValidatorProperties,        newConfig.MinimumPasswordValidatorProperties);
            Assert.AreEqual(StartupConfiguration.PasswordValidatorRequiredLength,           newConfig.PasswordValidatorRequiredLength);
            Assert.AreEqual(StartupConfiguration.PasswordValidatorRequiredProperties.Count, newConfig.PasswordValidatorRequiredProperties.Count);
            Assert.AreEqual(StartupConfiguration.PasswordFields.Count,                      newConfig.PasswordFields.Count);
            Assert.AreEqual(StartupConfiguration.ConstantFields.Count,                      newConfig.ConstantFields.Count);
            Assert.AreEqual(StartupConfiguration.CsrfGoups.Count,                           newConfig.CsrfGoups.Count);
            Assert.AreEqual(StartupConfiguration.TaintTypeNameToBit.Count,                  newConfig.TaintTypeNameToBit.Count);
        }

        [TestMethod]
        public void HandlingNewerConfigs1()
        {
            var options = ConfigurationTest.CreateAnalyzersOptionsWithConfig(@"
Unknown: false

Behavior:
");
            // should not throw
            Manager.GetProjectConfiguration(options.AdditionalFiles);
        }

        [TestMethod]
        public void HandlingNewerConfigs2()
        {
            var options = ConfigurationTest.CreateAnalyzersOptionsWithConfig(@"
Behavior:
  fdgfgfgfg:
    Namespace: Test
    ClassName: Test
    Unknown: Abc
    Name: Test
    Method:
      ArgTypes: (System.String)
      Returns:
        Taint: HtmlEscaped
        TaintFromArguments: [0]
");
            // should not throw
            Manager.GetProjectConfiguration(options.AdditionalFiles);
        }

        [TestMethod]
        public void MergingUserConfig_NoChanges()
        {
            var options   = ConfigurationTest.CreateAnalyzersOptionsWithConfig("Behavior:");
            var newConfig = Manager.GetProjectConfiguration(options.AdditionalFiles);

            // ensuring that field count matches count of properties tested below
            Assert.AreEqual(12, typeof(Configuration).GetProperties(BindingFlags.Instance | BindingFlags.Public).Length);

            Assert.AreEqual(StartupConfiguration.ReportAnalysisCompletion,                  newConfig.ReportAnalysisCompletion);
            Assert.AreEqual(StartupConfiguration.AuditMode,                                 newConfig.AuditMode);
            Assert.AreEqual(StartupConfiguration.Behavior.Count,                            newConfig.Behavior.Count);
            Assert.AreEqual(StartupConfiguration.TaintEntryPoints.Count,                    newConfig.TaintEntryPoints.Count);
            Assert.AreEqual(StartupConfiguration.MinimumPasswordValidatorProperties,        newConfig.MinimumPasswordValidatorProperties);
            Assert.AreEqual(StartupConfiguration.PasswordValidatorRequiredLength,           newConfig.PasswordValidatorRequiredLength);
            Assert.AreEqual(StartupConfiguration.PasswordValidatorRequiredProperties.Count, newConfig.PasswordValidatorRequiredProperties.Count);
            Assert.AreEqual(StartupConfiguration.PasswordFields.Count,                      newConfig.PasswordFields.Count);
            Assert.AreEqual(StartupConfiguration.ConstantFields.Count,                      newConfig.ConstantFields.Count);
            Assert.AreEqual(StartupConfiguration.CsrfGoups.Count,                           newConfig.CsrfGoups.Count);
            Assert.AreEqual(StartupConfiguration.TaintTypeNameToBit.Count,                  newConfig.TaintTypeNameToBit.Count);
        }

        [TestMethod]
        public void DifferentConfigVersion_Exception()
        {
            var options   = ConfigurationTest.CreateAnalyzersOptionsWithConfig("MinimumPasswordValidatorProperties: 0", new Version(1,2));
            Assert.ThrowsException<ArgumentException>(() => Manager.GetProjectConfiguration(options.AdditionalFiles));
        }

        [DataTestMethod]
        [DataRow(" ()",                                     true)]
        [DataRow("() ",                                     true)]
        [DataRow("",                                        true)]
        [DataRow("(",                                       true)]
        [DataRow(")",                                       true)]
        [DataRow("((",                                      true)]
        [DataRow("))",                                      true)]
        [DataRow(")(",                                      true)]
        [DataRow("())",                                     true)]
        [DataRow("(System.String)",                         false)]
        [DataRow("( System.String)",                        true)]
        [DataRow("(System.String aaa)",                     true)]
        [DataRow("(string)",                                true)]
        [DataRow("(System.String,  System.String)",         true)]
        [DataRow("(System.String, System.String)",          false)]
        [DataRow("(System.String, out System.String)",      false)]
        [DataRow("(this System.String, System.String)",     true)]
        [DataRow("(System.String, params System.String[])", false)]
        [DataRow("(System.String[])",                       false)]
        public void ArgTypesValidation(string payload, bool shouldThrow)
        {
            var options   = ConfigurationTest.CreateAnalyzersOptionsWithConfig($@"
Behavior:
  Bla:
    Namespace: NS
    ClassName: CL
    Name: Foo
    Method:
      ArgTypes: ""{payload}""
");

            if (shouldThrow)
                Assert.ThrowsException<Exception>(() => Manager.GetProjectConfiguration(options.AdditionalFiles));
            else
                Manager.GetProjectConfiguration(options.AdditionalFiles);
        }

        [DataTestMethod]
        [DataRow("[aaa]",     false)]
        [DataRow("[aaa,aaa]", true)]
        // The test checks if an exception is thrown when custom taint type limit is reached. Taint type names are represented as numbers
        // Remove a number if a new built-in taint type was added.
        [DataRow("[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56]", true)]
        [DataRow("[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55]",    false)]
        public void SanitizerTypesValidation(string payload, bool shouldThrow)
        {
            var options = ConfigurationTest.CreateAnalyzersOptionsWithConfig($@"
TaintTypes: {payload}");

            if (shouldThrow)
                Assert.ThrowsException<Exception>(() => Manager.GetProjectConfiguration(options.AdditionalFiles));
            else
                Manager.GetProjectConfiguration(options.AdditionalFiles);
        }
    }
}
