using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using SecurityCodeScan.Test.Helpers;

namespace SecurityCodeScan.Test.Config
{
    public abstract class ConfigurationTest : DiagnosticVerifier
    {
        private readonly List<string> FilePaths = new List<string>();
        private const string ConfigName = "SecurityCodeScan.config.yml";
        private readonly Version ConfigVersion = new Version(1,0);
        private const string ConfigText = "Version: {0}\n\r{1}";
        protected async Task<AnalyzerOptions> CreateAnalyzersOptionsWithConfig(string configSource, Version version = null)
        {
            var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            FilePaths.Add(path);

            Directory.CreateDirectory(path);

            var filePath = Path.Combine(path, ConfigName);
            using (var file = File.CreateText(filePath))
            {
                var configText = string.Format(ConfigText, version != null ? version : ConfigVersion, configSource);
                await file.WriteAsync(configText).ConfigureAwait(false);
            }

            var additionalTextMock = new Mock<AdditionalText>();
            additionalTextMock.Setup(text => text.Path).Returns(filePath); //return path to our just created config file
            var additionalFileText = ImmutableArray.Create(additionalTextMock.Object);

            return new AnalyzerOptions(additionalFileText);
        }

        [ClassCleanup]
        public void DeleteConfig()
        {
            foreach (var path in FilePaths)
            {
                File.Delete(Path.Combine(path, ConfigName));
                Directory.Delete(path);
            }
        }
    }
}
