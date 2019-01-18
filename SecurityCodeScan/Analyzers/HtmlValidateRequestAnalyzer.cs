using System;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;

namespace SecurityCodeScan.Analyzers
{
    [SecurityAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    internal class HtmlValidateRequestAnalyzer : SecurityAnalyzer, IExternalFileAnalyzer
    {
        public static readonly DiagnosticDescriptor RuleValidateRequest = LocaleUtil.GetDescriptor("SCS0021");

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(RuleValidateRequest);

        public override void Initialize(ISecurityAnalysisContext context)
        {
            context.RegisterCompilationAction(OnCompilationAction);
        }

        private void OnCompilationAction(CompilationAnalysisContext ctx)
        {
            foreach (AdditionalText file in ctx.Options
                                               .AdditionalFiles
                                               .Where(file =>
                                                      {
                                                          var ext = Path.GetExtension(file.Path);
                                                          return 0 == String.Compare(ext, ".aspx", StringComparison.OrdinalIgnoreCase);
                                                      }))
            {
                AnalyzeFile(file, ctx);
            }
        }

        private static readonly Regex Regex = new Regex(@"<%\s*@\s*Page[^>]+validateRequest\s*=\s*""\s*false\s*""",
                                                        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase,
                                                        TimeSpan.FromSeconds(60));

        public void AnalyzeFile(AdditionalText file, CompilationAnalysisContext context)
        {
            var text    = file.GetText();
            var content = text.ToString();
            foreach (Match match in Regex.Matches(content))
            {
                context.ReportDiagnostic(ExternalDiagnostic.Create(RuleValidateRequest,
                                                                   file.Path,
                                                                   text.Lines.GetLinePosition(match.Index).Line + 1,
                                                                   match.Value));
            }
        }
    }
}
