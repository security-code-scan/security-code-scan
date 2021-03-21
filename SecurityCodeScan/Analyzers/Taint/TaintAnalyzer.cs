using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
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
using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Config;

namespace SecurityCodeScan.Analyzers.Taint
{
    using ValueContentAnalysisResult = DataFlowAnalysisResult<ValueContentBlockAnalysisResult, ValueContentAbstractValue>;

    internal enum TaintType
    {
        SCS0001 = 100,
        SCS0002,
        SCS0003,
        SCS0015,
        SCS0018,
        SCS0026,
        SCS0027,
        SCS0028,
        SCS0029,
        SCS0031,
    }

    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class CommandInjectionTaintAnalyzer : TaintAnalyzer
    {
        internal static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0001");

        protected override SinkKind SinkKind { get { return (SinkKind)(int)TaintType.SCS0001; } }

        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor { get { return Rule; } }
    }

    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class SqlInjectionTaintAnalyzer : TaintAnalyzer
    {
        internal static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0002");

        protected override SinkKind SinkKind { get { return (SinkKind)(int)TaintType.SCS0002; } }

        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor { get { return Rule; } }
    }

    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class XPathTaintAnalyzer : TaintAnalyzer
    {
        internal static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0003");

        protected override SinkKind SinkKind { get { return (SinkKind)(int)TaintType.SCS0003; } }

        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor { get { return Rule; } }
    }

    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class PathTraversalTaintAnalyzer : TaintAnalyzer
    {
        internal static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0018");

        protected override SinkKind SinkKind { get { return (SinkKind)(int)TaintType.SCS0018; } }

        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor { get { return Rule; } }
    }

    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class OpenRedirectTaintAnalyzer : TaintAnalyzer
    {
        internal static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0027");

        protected override SinkKind SinkKind { get { return (SinkKind)(int)TaintType.SCS0027; } }

        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor { get { return Rule; } }
    }

    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class DeserializationTaintAnalyzer : TaintAnalyzer
    {
        internal static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0028");

        protected override SinkKind SinkKind { get { return (SinkKind)(int)TaintType.SCS0028; } }

        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor { get { return Rule; } }
    }

    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class LdapFilterTaintAnalyzer : TaintAnalyzer
    {
        internal static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0031");

        protected override SinkKind SinkKind { get { return (SinkKind)(int)TaintType.SCS0031; } }

        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor { get { return Rule; } }
    }

    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class LdapPathTaintAnalyzer : TaintAnalyzer
    {
        internal static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0026");

        protected override SinkKind SinkKind { get { return (SinkKind)(int)TaintType.SCS0026; } }

        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor { get { return Rule; } }
    }

    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class XssTaintAnalyzer : TaintAnalyzer
    {
        internal static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0029");

        protected override SinkKind SinkKind { get { return (SinkKind)(int)TaintType.SCS0029; } }

        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor { get { return Rule; } }
    }

    public abstract class TaintAnalyzer : DiagnosticAnalyzer
    {
        protected abstract DiagnosticDescriptor TaintedDataEnteringSinkDescriptor { get; }

        protected abstract SinkKind SinkKind { get; }

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(TaintedDataEnteringSinkDescriptor);

        public override void Initialize(AnalysisContext context)
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
                    var config = Configuration.GetOrCreate(compilationContext);

                    if (config.AuditMode)
                    {
                        TaintedDataSymbolMap<SinkInfo> sinkInfoSymbolMap = config.TaintConfiguration.GetSinkSymbolMap(this.SinkKind);
                        if (sinkInfoSymbolMap.IsEmpty)
                        {
                            return;
                        }

                        Compilation compilation = compilationContext.Compilation;
                        compilationContext.RegisterOperationBlockStartAction(
                            operationBlockStartContext =>
                            {
                                ISymbol owningSymbol = operationBlockStartContext.OwningSymbol;
                                AnalyzerOptions options = operationBlockStartContext.Options;
                                CancellationToken cancellationToken = operationBlockStartContext.CancellationToken;
                                if (options.IsConfiguredToSkipAnalysis(TaintedDataEnteringSinkDescriptor, owningSymbol, compilation, cancellationToken))
                                {
                                    return;
                                }

                                WellKnownTypeProvider wellKnownTypeProvider = WellKnownTypeProvider.GetOrCreate(compilation);

                                void CreateWarning(OperationAnalysisContext operationAnalysisContext, Location location, ISymbol paramSymbol, ISymbol symbol)
                                {
                                    // Something like:
                                    // CA3001: Potential SQL injection vulnerability was found where '{0}' in method '{1}' may be tainted by user-controlled data from '{2}' in method '{3}'.
                                    Diagnostic diagnostic = Diagnostic.Create(
                                                                this.TaintedDataEnteringSinkDescriptor,
                                                                location,
                                                                additionalLocations: new Location[] { location },
                                                                messageArgs: new object[] {
                                                                    paramSymbol.Name,
                                                                    symbol.ToDisplayString(SymbolDisplayFormat.MinimallyQualifiedFormat),
                                                                    symbol.ToDisplayString(SymbolDisplayFormat.MinimallyQualifiedFormat),
                                                                    symbol.ToDisplayString(SymbolDisplayFormat.MinimallyQualifiedFormat)});
                                    operationAnalysisContext.ReportDiagnostic(diagnostic);
                                }

                                bool IsConstant(IOperation operation, IOperation value, OperationAnalysisContext operationAnalysisContext)
                                {
                                    if (value.ConstantValue.HasValue || value is ITypeOfOperation)
                                        return true;

                                    if (!operation.TryGetEnclosingControlFlowGraph(out var cfg))
                                        return false;

                                    var valueContentResult = ValueContentAnalysis.TryGetOrComputeResult(cfg, owningSymbol, wellKnownTypeProvider,
                                        operationAnalysisContext.Options, TaintedDataEnteringSinkDescriptor, PointsToAnalysisKind.Complete, operationAnalysisContext.CancellationToken);
                                    if (valueContentResult == null)
                                        return false;

                                    ValueContentAbstractValue abstractValue = valueContentResult[value.Kind, value.Syntax];
                                    return abstractValue.NonLiteralState == ValueContainsNonLiteralState.No;
                                }

                                operationBlockStartContext.RegisterOperationAction(
                                    operationAnalysisContext =>
                                    {
                                        IAssignmentOperation operation = (IAssignmentOperation)operationAnalysisContext.Operation;
                                        if (!(operation.Target is IPropertyReferenceOperation propertyReferenceOperation))
                                            return;

                                        IEnumerable<SinkInfo>? infosForType = sinkInfoSymbolMap.GetInfosForType(propertyReferenceOperation.Member.ContainingType);
                                        if (infosForType != null &&
                                            infosForType.Any(x => x.SinkProperties.Contains(propertyReferenceOperation.Member.MetadataName)) &&
                                            !IsConstant(operation, operation.Value, operationAnalysisContext))
                                        {
                                            CreateWarning(
                                                operationAnalysisContext,
                                                propertyReferenceOperation.Syntax.GetLocation(),
                                                operation.Value.Type,
                                                propertyReferenceOperation.Member);
                                        }
                                    },
                                    OperationKind.SimpleAssignment);

                                operationBlockStartContext.RegisterOperationAction(
                                    operationAnalysisContext =>
                                    {
                                        IInvocationOperation invocationOperation = (IInvocationOperation)operationAnalysisContext.Operation;
                                        IEnumerable<SinkInfo>? infosForType = sinkInfoSymbolMap.GetInfosForType(invocationOperation.TargetMethod.ContainingType);
                                        if (infosForType == null)
                                            return;

                                        foreach (SinkInfo sinkInfo in infosForType)
                                        {
                                            foreach (IArgumentOperation taintedArgument in invocationOperation.Arguments.Where(x => !IsConstant(x, x.Value, operationAnalysisContext)))
                                            {
                                                if (sinkInfo.SinkMethodParameters.TryGetValue(invocationOperation.TargetMethod.MetadataName, out ImmutableHashSet<string> sinkParameters)
                                                    && sinkParameters.Contains(taintedArgument.Parameter.MetadataName))
                                                {
                                                    CreateWarning(operationAnalysisContext, invocationOperation.Syntax.GetLocation(), taintedArgument.Parameter, invocationOperation.TargetMethod);
                                                    return;
                                                }
                                            }
                                        }
                                    },
                                    OperationKind.Invocation);

                                operationBlockStartContext.RegisterOperationAction(
                                    operationAnalysisContext =>
                                    {
                                        IObjectCreationOperation invocationOperation = (IObjectCreationOperation)operationAnalysisContext.Operation;
                                        IEnumerable<SinkInfo>? infosForType = sinkInfoSymbolMap.GetInfosForType(invocationOperation.Constructor.ContainingType);
                                        if (infosForType == null)
                                            return;

                                        foreach (SinkInfo sinkInfo in infosForType)
                                        {
                                            foreach (IArgumentOperation taintedArgument in invocationOperation.Arguments.Where(x => !IsConstant(x, x.Value, operationAnalysisContext)))
                                            {
                                                if (sinkInfo.IsAnyStringParameterInConstructorASink
                                                    && taintedArgument.Parameter.Type.SpecialType == SpecialType.System_String)
                                                {
                                                    CreateWarning(operationAnalysisContext, invocationOperation.Syntax.GetLocation(), taintedArgument.Parameter, invocationOperation.Constructor);
                                                    return;
                                                }
                                                else if (sinkInfo.SinkMethodParameters.TryGetValue(invocationOperation.Constructor.MetadataName, out ImmutableHashSet<string> sinkParameters)
                                                         && sinkParameters.Contains(taintedArgument.Parameter.MetadataName))
                                                {
                                                    CreateWarning(operationAnalysisContext, invocationOperation.Syntax.GetLocation(), taintedArgument.Parameter, invocationOperation.Constructor);
                                                    return;
                                                }
                                            }
                                        }
                                    },
                                    OperationKind.ObjectCreation);
                            });
                    }
                    else
                    {
                        TaintedDataSymbolMap<SourceInfo> sourceInfoSymbolMap = config.TaintConfiguration.GetSourceSymbolMap(this.SinkKind);
                        if (sourceInfoSymbolMap.IsEmpty)
                        {
                            return;
                        }

                        TaintedDataSymbolMap<SinkInfo> sinkInfoSymbolMap = config.TaintConfiguration.GetSinkSymbolMap(this.SinkKind);
                        if (sinkInfoSymbolMap.IsEmpty)
                        {
                            return;
                        }

                        Compilation compilation = compilationContext.Compilation;
                        compilationContext.RegisterOperationBlockStartAction(
                            operationBlockStartContext =>
                            {
                                ISymbol owningSymbol = operationBlockStartContext.OwningSymbol;
                                AnalyzerOptions options = operationBlockStartContext.Options;
                                CancellationToken cancellationToken = operationBlockStartContext.CancellationToken;
                                if (options.IsConfiguredToSkipAnalysis(TaintedDataEnteringSinkDescriptor, owningSymbol, compilation, cancellationToken))
                                {
                                    return;
                                }

                                WellKnownTypeProvider wellKnownTypeProvider = WellKnownTypeProvider.GetOrCreate(compilation);
                                Lazy<ControlFlowGraph?> controlFlowGraphFactory = new Lazy<ControlFlowGraph?>(
                                    () => operationBlockStartContext.OperationBlocks.GetControlFlowGraph());
                                Lazy<PointsToAnalysisResult?> pointsToFactory = new Lazy<PointsToAnalysisResult?>(
                                    () =>
                                    {
                                        if (controlFlowGraphFactory.Value == null)
                                        {
                                            return null;
                                        }

                                        InterproceduralAnalysisConfiguration interproceduralAnalysisConfiguration = InterproceduralAnalysisConfiguration.Create(
                                                                    options,
                                                                    SupportedDiagnostics,
                                                                    controlFlowGraphFactory.Value,
                                                                    operationBlockStartContext.Compilation,
                                                                    defaultInterproceduralAnalysisKind: InterproceduralAnalysisKind.ContextSensitive,
                                                                    cancellationToken: cancellationToken,
                                                                    defaultMaxInterproceduralMethodCallChain: config.MaxInterproceduralMethodCallChain,
                                                                    defaultMaxInterproceduralLambdaOrLocalFunctionCallChain: config.MaxInterproceduralLambdaOrLocalFunctionCallChain);
                                        return PointsToAnalysis.TryGetOrComputeResult(
                                                                    controlFlowGraphFactory.Value,
                                                                    owningSymbol,
                                                                    options,
                                                                    wellKnownTypeProvider,
                                                                    PointsToAnalysisKind.Complete,
                                                                    interproceduralAnalysisConfiguration,
                                                                    interproceduralAnalysisPredicate: null);
                                    });
                                Lazy<(PointsToAnalysisResult?, ValueContentAnalysisResult?)> valueContentFactory = new Lazy<(PointsToAnalysisResult?, ValueContentAnalysisResult?)>(
                                    () =>
                                    {
                                        if (controlFlowGraphFactory.Value == null)
                                        {
                                            return (null, null);
                                        }

                                        InterproceduralAnalysisConfiguration interproceduralAnalysisConfiguration = InterproceduralAnalysisConfiguration.Create(
                                                                    options,
                                                                    SupportedDiagnostics,
                                                                    controlFlowGraphFactory.Value,
                                                                    operationBlockStartContext.Compilation,
                                                                    defaultInterproceduralAnalysisKind: InterproceduralAnalysisKind.ContextSensitive,
                                                                    cancellationToken: cancellationToken,
                                                                    defaultMaxInterproceduralMethodCallChain: config.MaxInterproceduralMethodCallChain,
                                                                    defaultMaxInterproceduralLambdaOrLocalFunctionCallChain: config.MaxInterproceduralLambdaOrLocalFunctionCallChain);
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

                                var rootOperationsNeedingAnalysis = PooledHashSet<IOperation>.GetInstance();

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

                                if (sourceInfoSymbolMap.RequiresFieldReferenceAnalysis)
                                {
                                    operationBlockStartContext.RegisterOperationAction(
                                    operationAnalysisContext =>
                                    {
                                        IFieldReferenceOperation fieldReferenceOperation = (IFieldReferenceOperation)operationAnalysisContext.Operation;
                                        if (sourceInfoSymbolMap.IsSourceField(fieldReferenceOperation.Field))
                                        {
                                            lock (rootOperationsNeedingAnalysis)
                                            {
                                                rootOperationsNeedingAnalysis.Add(fieldReferenceOperation.GetRoot());
                                            }
                                        }
                                    },
                                    OperationKind.FieldReference);
                                }

                                if (sourceInfoSymbolMap.RequiresParameterReferenceAnalysis)
                                {
                                    operationBlockStartContext.RegisterOperationAction(
                                        operationAnalysisContext =>
                                        {
                                            IParameterReferenceOperation parameterReferenceOperation = (IParameterReferenceOperation)operationAnalysisContext.Operation;
                                            if (sourceInfoSymbolMap.IsSourceParameter(parameterReferenceOperation.Parameter, wellKnownTypeProvider))
                                            {
                                                lock (rootOperationsNeedingAnalysis)
                                                {
                                                    rootOperationsNeedingAnalysis.Add(parameterReferenceOperation.GetRoot());
                                                }
                                            }
                                        },
                                        OperationKind.ParameterReference);
                                }

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

                                if (config.TaintConfiguration.HasTaintArraySource(SinkKind, config))
                                {
                                    operationBlockStartContext.RegisterOperationAction(
                                        operationAnalysisContext =>
                                        {
                                            IArrayInitializerOperation arrayInitializerOperation = (IArrayInitializerOperation)operationAnalysisContext.Operation;
                                            if (arrayInitializerOperation.GetAncestor<IArrayCreationOperation>(OperationKind.ArrayCreation)?.Type is IArrayTypeSymbol arrayTypeSymbol
                                                && sourceInfoSymbolMap.IsSourceConstantArrayOfType(arrayTypeSymbol, arrayInitializerOperation))
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
                                                        config.TaintConfiguration.GetSanitizerSymbolMap(this.SinkKind),
                                                        sinkInfoSymbolMap,
                                                        operationBlockAnalysisContext.CancellationToken,
                                                        config.MaxInterproceduralMethodCallChain,
                                                        config.MaxInterproceduralLambdaOrLocalFunctionCallChain);
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
                                            rootOperationsNeedingAnalysis.Free(compilationContext.CancellationToken);
                                        }
                                    });
                            });
                    }
                });
        }
    }
}
