using System.Collections.Immutable;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using Analyzer.Utilities;
using Analyzer.Utilities.Extensions;
using Analyzer.Utilities.FlowAnalysis.Analysis.PropertySetAnalysis;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.PointsToAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.ValueContentAnalysis;
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

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(Rule);

        public override void Initialize(AnalysisContext context)
        {
            if (!Debugger.IsAttached) // prefer single thread for debugging in development
                context.EnableConcurrentExecution();

            if (context.IsAuditMode())
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
            else
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);

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

                    if (!wellKnownTypeProvider.TryGetOrCreateTypeByMetadataName("System.Xml.Xsl.XsltSettings", out var type))
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
                            if (options.IsConfiguredToSkipAnalysis(Rule, owningSymbol, compilation, cancellationToken))
                            {
                                return;
                            }

                            bool? GetValue(IOperation operation, IOperation value, OperationAnalysisContext operationAnalysisContext)
                            {
                                if (value.ConstantValue.HasValue && value.ConstantValue.Value is bool isEnableScript)
                                    return isEnableScript;

                                if (!operation.TryGetEnclosingControlFlowGraph(out var cfg))
                                    return null;

                                var valueContentResult = ValueContentAnalysis.TryGetOrComputeResult(cfg, owningSymbol, wellKnownTypeProvider,
                                    operationAnalysisContext.Options, Rule, PointsToAnalysisKind.Complete, operationAnalysisContext.CancellationToken);
                                if (valueContentResult == null)
                                    return null;

                                ValueContentAbstractValue abstractValue = valueContentResult[value.Kind, value.Syntax];

                                PropertySetAbstractValueKind kind = PropertySetCallbacks.EvaluateLiteralValues(abstractValue, (object? o) => o is true);
                                if (kind == PropertySetAbstractValueKind.MaybeFlagged || kind == PropertySetAbstractValueKind.Flagged)
                                    return true;

                                kind = PropertySetCallbacks.EvaluateLiteralValues(abstractValue, (object? o) => o is false);
                                if (kind == PropertySetAbstractValueKind.Flagged)
                                    return false;

                                return null;
                            }

                            operationBlockStartContext.RegisterOperationAction(
                                ctx =>
                                {
                                    IAssignmentOperation operation = (IAssignmentOperation)ctx.Operation;
                                    if (!(operation.Target is IPropertyReferenceOperation propertyReferenceOperation))
                                        return;

                                    if (propertyReferenceOperation.Member.ContainingType != type)
                                        return;

                                    if (propertyReferenceOperation.Member.Name == "EnableScript")
                                    {
                                        var enableScript = GetValue(operation, operation.Value, ctx);
                                        if ((enableScript.HasValue && enableScript.Value) ||
                                            !enableScript.HasValue && configuration.AuditMode)
                                        {
                                            ctx.ReportDiagnostic(Diagnostic.Create(Rule, operation.Syntax.GetLocation()));
                                        }
                                    }
                                },
                                OperationKind.SimpleAssignment);

                            operationBlockStartContext.RegisterOperationAction(
                                ctx =>
                                {
                                    var operation = (IPropertyReferenceOperation)ctx.Operation;
                                    if (operation.Property.ContainingType != type || operation.Property.Name != "TrustedXslt")
                                        return;

                                    ctx.ReportDiagnostic(Diagnostic.Create(Rule, operation.Syntax.GetLocation()));
                                },
                                OperationKind.PropertyReference);

                            operationBlockStartContext.RegisterOperationAction(
                                ctx =>
                                {
                                    IObjectCreationOperation invocationOperation = (IObjectCreationOperation)ctx.Operation;
                                    if (invocationOperation.Constructor.ContainingType != type)
                                        return;

                                    var enableScriptArg = invocationOperation.Arguments.FirstOrDefault(x => x.Parameter.Name == "enableScript");
                                    if (enableScriptArg == null)
                                        return;

                                    var enableScript = GetValue(invocationOperation, enableScriptArg.Value, ctx);
                                    if ((enableScript.HasValue && enableScript.Value) ||
                                        !enableScript.HasValue && configuration.AuditMode)
                                    {
                                        ctx.ReportDiagnostic(Diagnostic.Create(Rule, invocationOperation.Syntax.GetLocation()));
                                    }
                                },
                                OperationKind.ObjectCreation);
                        });
                });
        }
    }
}
