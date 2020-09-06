using System.Collections.Immutable;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using Analyzer.Utilities;
using Analyzer.Utilities.Extensions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Config;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class XsltSettingsAnalyzer : DiagnosticAnalyzer
    {
        public const            string               DiagnosticId = "SCS0011";
        private static readonly DiagnosticDescriptor Rule         = LocaleUtil.GetDescriptor(DiagnosticId);

        private const string  XsltSettingsTypeName = "System.Xml.Xsl.XsltSettings";
        private const string  EnableScriptName = "EnableScript";

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(Rule);

        public override void Initialize(AnalysisContext context)
        {
            if (!Debugger.IsAttached) // prefer single thread for debugging in development
                context.EnableConcurrentExecution();

            if (context.IsAuditMode())
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
            else
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);

            Analyzer.Initialize(context);
        }

        private class Analyzer
        {
            public static void Initialize(AnalysisContext context)
            {
                if (!Debugger.IsAttached) // prefer single thread for debugging in development
                    context.EnableConcurrentExecution();

                if (context.IsAuditMode())
                    context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
                else
                    context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);

                context.RegisterCompilationStartAction(
                    (CompilationStartAnalysisContext compilationContext) =>
                    {
                        Compilation compilation = compilationContext.Compilation;
                        var wellKnownTypeProvider = WellKnownTypeProvider.GetOrCreate(compilation);

                        if (!wellKnownTypeProvider.TryGetOrCreateTypeByMetadataName(XsltSettingsTypeName, out var type))
                        {
                            return;
                        }

                        var configuration = Configuration.GetOrCreate(compilationContext);

                        compilationContext.RegisterOperationBlockStartAction(
                            operationBlockStartContext =>
                            {
                                ISymbol owningSymbol = operationBlockStartContext.OwningSymbol;
                                AnalyzerOptions options = operationBlockStartContext.Options;
                                CancellationToken cancellationToken = operationBlockStartContext.CancellationToken;
                                if (owningSymbol.IsConfiguredToSkipAnalysis(options, Rule, compilation, cancellationToken))
                                {
                                    return;
                                }

                                operationBlockStartContext.RegisterOperationAction(
                                    ctx =>
                                    {
                                        IAssignmentOperation operation = (IAssignmentOperation)ctx.Operation;
                                        if (!(operation.Target is IPropertyReferenceOperation propertyReferenceOperation))
                                            return;

                                        if (propertyReferenceOperation.Member.ContainingType != type)
                                        {
                                            return;
                                        }

                                        if (propertyReferenceOperation.Member.Name == EnableScriptName &&
                                            ((operation.Value.ConstantValue.HasValue &&
                                             operation.Value.ConstantValue.Value is bool isEnableScript && isEnableScript) ||
                                            !operation.Value.ConstantValue.HasValue && configuration.AuditMode))
                                        {
                                            ctx.ReportDiagnostic(Diagnostic.Create(Rule, operation.Syntax.GetLocation()));
                                        }
                                    },
                                    OperationKind.SimpleAssignment);
                            });
                    });
            }
        }
    }
}
