using System;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using Analyzer.Utilities;
using Analyzer.Utilities.Extensions;
using Analyzer.Utilities.FlowAnalysis.Analysis.TaintedDataAnalysis;
using Analyzer.Utilities.PooledObjects;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.PointsToAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.ValueContentAnalysis;
using Microsoft.CodeAnalysis.Operations;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Config;

namespace SecurityCodeScan.Analyzers
{
    using ValueContentAnalysisResult = DataFlowAnalysisResult<ValueContentBlockAnalysisResult, ValueContentAbstractValue>;

    [SecurityAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    internal class CommandInjectionTaintAnalyzer : TaintAnalyzer2
    {
        internal static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0001");

        protected override SinkKind SinkKind { get { return SinkKind.ProcessCommand; } }

        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor { get { return Rule; } }
    }

    [SecurityAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    internal class SqlInjectionTaintAnalyzer : TaintAnalyzer2
    {
        internal static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0002");

        protected override SinkKind SinkKind { get { return SinkKind.Sql; } }

        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor { get { return Rule; } }
    }

    [SecurityAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    internal class XPathTaintAnalyzer : TaintAnalyzer2
    {
        internal static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0003");

        protected override SinkKind SinkKind { get { return SinkKind.XPath; } }

        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor { get { return Rule; } }
    }

    [SecurityAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    internal class XmlInjectionTaintAnalyzer : TaintAnalyzer2
    {
        internal static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0007");

        protected override SinkKind SinkKind { get { return SinkKind.Xml; } }

        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor { get { return Rule; } }
    }

    [SecurityAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    internal class PathTraversalTaintAnalyzer : TaintAnalyzer2
    {
        internal static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0018");

        protected override SinkKind SinkKind { get { return SinkKind.FilePathInjection; } }

        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor { get { return Rule; } }
    }

    [SecurityAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    internal class OpenRedirectTaintAnalyzer : TaintAnalyzer2
    {
        internal static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0027");

        protected override SinkKind SinkKind { get { return SinkKind.Redirect; } }

        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor { get { return Rule; } }
    }

    [SecurityAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    internal class LdapTaintAnalyzer : TaintAnalyzer2
    {
        internal static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0031");

        protected override SinkKind SinkKind { get { return SinkKind.Ldap; } }

        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor { get { return Rule; } }
    }

    [SecurityAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    internal class XssTaintAnalyzer : TaintAnalyzer2
    {
        internal static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0029");

        protected override SinkKind SinkKind { get { return SinkKind.Xss; } }

        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor { get { return Rule; } }
    }

    internal abstract class TaintAnalyzer2 : SecurityAnalyzer
    {
        protected abstract DiagnosticDescriptor TaintedDataEnteringSinkDescriptor { get; }

        protected abstract SinkKind SinkKind { get; }

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(TaintedDataEnteringSinkDescriptor);

        public override void Initialize(ISecurityAnalysisContext context)
        {
            context.RegisterCompilationStartAction(
                (CompilationStartAnalysisContext compilationContext, Configuration config) =>
                {
                    Compilation compilation = compilationContext.Compilation;
                    TaintedDataConfig taintedDataConfig = TaintedDataConfig.GetOrCreate(compilation);
                    TaintedDataSymbolMap<SourceInfo> sourceInfoSymbolMap = taintedDataConfig.GetSourceSymbolMap(this.SinkKind);
                    if (sourceInfoSymbolMap.IsEmpty)
                    {
                        return;
                    }

                    TaintedDataSymbolMap<SinkInfo> sinkInfoSymbolMap = taintedDataConfig.GetSinkSymbolMap(this.SinkKind);
                    if (sinkInfoSymbolMap.IsEmpty)
                    {
                        return;
                    }

                    compilationContext.RegisterOperationBlockStartAction(
                        operationBlockStartContext =>
                        {
                            ISymbol owningSymbol = operationBlockStartContext.OwningSymbol;
                            AnalyzerOptions options = operationBlockStartContext.Options;
                            CancellationToken cancellationToken = operationBlockStartContext.CancellationToken;
                            if (owningSymbol.IsConfiguredToSkipAnalysis(options, TaintedDataEnteringSinkDescriptor, compilation, cancellationToken))
                            {
                                return;
                            }

                            WellKnownTypeProvider wellKnownTypeProvider = WellKnownTypeProvider.GetOrCreate(compilation);
                            InterproceduralAnalysisConfiguration interproceduralAnalysisConfiguration = InterproceduralAnalysisConfiguration.Create(
                                                                    options,
                                                                    SupportedDiagnostics,
                                                                    owningSymbol,
                                                                    operationBlockStartContext.Compilation,
                                                                    defaultInterproceduralAnalysisKind: InterproceduralAnalysisKind.ContextSensitive,
                                                                    cancellationToken: cancellationToken);
                            Lazy<ControlFlowGraph?> controlFlowGraphFactory = new Lazy<ControlFlowGraph?>(
                                () => operationBlockStartContext.OperationBlocks.GetControlFlowGraph());
                            Lazy<PointsToAnalysisResult?> pointsToFactory = new Lazy<PointsToAnalysisResult?>(
                                () =>
                                {
                                    if (controlFlowGraphFactory.Value == null)
                                    {
                                        return null;
                                    }

                                    return PointsToAnalysis.TryGetOrComputeResult(
                                                                controlFlowGraphFactory.Value,
                                                                owningSymbol,
                                                                options,
                                                                wellKnownTypeProvider,
                                                                PointsToAnalysisKind.Complete,
                                                                interproceduralAnalysisConfiguration,
                                                                interproceduralAnalysisPredicateOpt: null);
                                });
                            Lazy<(PointsToAnalysisResult?, ValueContentAnalysisResult?)> valueContentFactory = new Lazy<(PointsToAnalysisResult?, ValueContentAnalysisResult?)>(
                                () =>
                                {
                                    if (controlFlowGraphFactory.Value == null)
                                    {
                                        return (null, null);
                                    }

                                    ValueContentAnalysisResult? valuecontentAnalysisResult = ValueContentAnalysis.TryGetOrComputeResult(
                                                                    controlFlowGraphFactory.Value,
                                                                    owningSymbol,
                                                                    options,
                                                                    wellKnownTypeProvider,
                                                                    PointsToAnalysisKind.Complete,
                                                                    interproceduralAnalysisConfiguration,
                                                                    out _,
                                                                    out PointsToAnalysisResult? p);

                                    return (p, valuecontentAnalysisResult);
                                });

                            PooledHashSet<IOperation> rootOperationsNeedingAnalysis = PooledHashSet<IOperation>.GetInstance();

                            operationBlockStartContext.RegisterOperationAction(
                                operationAnalysisContext =>
                                {
                                    IPropertyReferenceOperation propertyReferenceOperation = (IPropertyReferenceOperation)operationAnalysisContext.Operation;
                                    if (sourceInfoSymbolMap.IsSourceProperty(propertyReferenceOperation.Property))
                                    {
                                        lock (rootOperationsNeedingAnalysis)
                                        {
                                            rootOperationsNeedingAnalysis.Add(propertyReferenceOperation.GetRoot());
                                        }
                                    }
                                },
                                OperationKind.PropertyReference);

                            operationBlockStartContext.RegisterOperationAction(
                                operationAnalysisContext =>
                                {
                                    IParameterReferenceOperation parameterReferenceOperation = (IParameterReferenceOperation)operationAnalysisContext.Operation;
                                    if (sourceInfoSymbolMap.IsSourceParameter(parameterReferenceOperation.Parameter))
                                    {
                                        lock (rootOperationsNeedingAnalysis)
                                        {
                                            rootOperationsNeedingAnalysis.Add(parameterReferenceOperation.GetRoot());
                                        }
                                    }
                                },
                                OperationKind.ParameterReference);

                            operationBlockStartContext.RegisterOperationAction(
                                operationAnalysisContext =>
                                {
                                    IInvocationOperation invocationOperation = (IInvocationOperation)operationAnalysisContext.Operation;
                                    if (sourceInfoSymbolMap.IsSourceMethod(
                                            invocationOperation.TargetMethod,
                                            invocationOperation.Arguments,
                                            pointsToFactory,
                                            valueContentFactory,
                                            out _))
                                    {
                                        lock (rootOperationsNeedingAnalysis)
                                        {
                                            rootOperationsNeedingAnalysis.Add(invocationOperation.GetRoot());
                                        }
                                    }
                                },
                                OperationKind.Invocation);

                            if (TaintedDataConfig.HasTaintArraySource(SinkKind))
                            {
                                operationBlockStartContext.RegisterOperationAction(
                                    operationAnalysisContext =>
                                    {
                                        IArrayInitializerOperation arrayInitializerOperation = (IArrayInitializerOperation)operationAnalysisContext.Operation;
                                        if (arrayInitializerOperation.GetAncestor<IArrayCreationOperation>(OperationKind.ArrayCreation)?.Type is IArrayTypeSymbol arrayTypeSymbol
                                            && sourceInfoSymbolMap.IsSourceConstantArrayOfType(arrayTypeSymbol))
                                        {
                                            lock (rootOperationsNeedingAnalysis)
                                            {
                                                rootOperationsNeedingAnalysis.Add(operationAnalysisContext.Operation.GetRoot());
                                            }
                                        }
                                    },
                                    OperationKind.ArrayInitializer);
                            }

                            operationBlockStartContext.RegisterOperationBlockEndAction(
                                operationBlockAnalysisContext =>
                                {
                                    try
                                    {
                                        lock (rootOperationsNeedingAnalysis)
                                        {
                                            if (!rootOperationsNeedingAnalysis.Any())
                                            {
                                                return;
                                            }

                                            if (controlFlowGraphFactory.Value == null)
                                            {
                                                return;
                                            }

                                            foreach (IOperation rootOperation in rootOperationsNeedingAnalysis)
                                            {
                                                TaintedDataAnalysisResult? taintedDataAnalysisResult = TaintedDataAnalysis.TryGetOrComputeResult(
                                                    controlFlowGraphFactory.Value,
                                                    operationBlockAnalysisContext.Compilation,
                                                    operationBlockAnalysisContext.OwningSymbol,
                                                    operationBlockAnalysisContext.Options,
                                                    TaintedDataEnteringSinkDescriptor,
                                                    sourceInfoSymbolMap,
                                                    taintedDataConfig.GetSanitizerSymbolMap(this.SinkKind),
                                                    sinkInfoSymbolMap,
                                                    operationBlockAnalysisContext.CancellationToken);
                                                if (taintedDataAnalysisResult == null)
                                                {
                                                    return;
                                                }

                                                foreach (TaintedDataSourceSink sourceSink in taintedDataAnalysisResult.TaintedDataSourceSinks)
                                                {
                                                    if (!sourceSink.SinkKinds.Contains(this.SinkKind))
                                                    {
                                                        continue;
                                                    }

                                                    foreach (SymbolAccess sourceOrigin in sourceSink.SourceOrigins)
                                                    {
                                                        // Something like:
                                                        // CA3001: Potential SQL injection vulnerability was found where '{0}' in method '{1}' may be tainted by user-controlled data from '{2}' in method '{3}'.
                                                        Diagnostic diagnostic = Diagnostic.Create(
                                                            this.TaintedDataEnteringSinkDescriptor,
                                                            sourceSink.Sink.Location,
                                                            additionalLocations: new Location[] { sourceOrigin.Location },
                                                            messageArgs: new object[] {
                                                        sourceSink.Sink.Symbol.Name,
                                                        sourceSink.Sink.AccessingMethod.ToDisplayString(SymbolDisplayFormat.MinimallyQualifiedFormat),
                                                        sourceOrigin.Symbol.ToDisplayString(SymbolDisplayFormat.MinimallyQualifiedFormat),
                                                        sourceOrigin.AccessingMethod.ToDisplayString(SymbolDisplayFormat.MinimallyQualifiedFormat)});
                                                        operationBlockAnalysisContext.ReportDiagnostic(diagnostic);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    finally
                                    {
                                        rootOperationsNeedingAnalysis.Free();
                                    }
                                });
                        });
                });
        }
    }
}
