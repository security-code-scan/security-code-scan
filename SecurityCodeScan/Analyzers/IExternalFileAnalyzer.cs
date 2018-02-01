using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace SecurityCodeScan.Analyzers
{
    public interface IExternalFileAnalyzer
    {
        void AnalyzeFile(AdditionalText file, CompilationAnalysisContext context);
    }
}
