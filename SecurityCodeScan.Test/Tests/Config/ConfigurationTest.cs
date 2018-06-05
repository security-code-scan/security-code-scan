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
        private readonly string ConfigName = "SecurityCodeScan.config.yml";
        protected async Task<AnalyzerOptions> CreateAnalyzersOptionsWithConfig(string configSource)
        {
            var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            FilePaths.Add(path);

            Directory.CreateDirectory(path);

            var filePath = Path.Combine(path, ConfigName);
            using (var file = File.CreateText(filePath))
            {
                await file.WriteAsync(configSource).ConfigureAwait(false);
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
