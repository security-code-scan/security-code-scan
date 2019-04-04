using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting.Logging;
using Moq;
using SecurityCodeScan.Analyzers;

public class ExternalFileAnalyzerTest
{
    private IExternalFileAnalyzer Analyzer;

    internal void Initialize(IExternalFileAnalyzer analyzer)
    {
        Analyzer = analyzer;
    }

    protected async Task<Mock<Action<Diagnostic>>> Analyze(string source, string path, CancellationToken cancellationToken = default(CancellationToken))
    {
        var additionalTextMock = new Mock<AdditionalText>();
        additionalTextMock.Setup(text => text.Path).Returns(path); //The path is read when the diagnostic is reported
        additionalTextMock.Setup(text => text.GetText(cancellationToken)).Returns(SourceText.From(source));

        var diagnosticReportMock = new Mock<Action<Diagnostic>>(MockBehavior.Loose); //Will record the reported diagnostic...
        diagnosticReportMock.Setup(x => x(It.IsAny<Diagnostic>()))
                            .Callback<Diagnostic>(diagnostic =>
                            {
                                if (diagnostic != null)
                                    Logger.LogMessage("Was: \"{0}\"", diagnostic.GetMessage());
                            });

        var compilation = new CompilationAnalysisContext(null,
                                                         null,
                                                         diagnosticReportMock.Object,
                                                         d => true,
                                                         cancellationToken);

        var file = File.CreateText(path);
        try
        {
            await file.WriteAsync(source).ConfigureAwait(false);
            file.Close();

            Analyzer.AnalyzeFile(additionalTextMock.Object, compilation);
        }
        finally
        {
            file.Dispose();
            File.Delete(path);
        }

        return diagnosticReportMock;
    }
}
