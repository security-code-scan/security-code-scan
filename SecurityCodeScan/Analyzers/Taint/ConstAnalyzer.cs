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
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.PointsToAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.ValueContentAnalysis;
using Microsoft.CodeAnalysis.Operations;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Config;

namespace SecurityCodeScan.Analyzers.Taint
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class HardcodedPasswordAnalyzer : ConstAnalyzer
    {
        internal static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0015");

        protected override SinkKind SinkKind { get { return (SinkKind)(int)TaintType.SCS0015; } }

        protected override DiagnosticDescriptor TaintedDataEnteringSinkDescriptor { get { return Rule; } }
    }

    public abstract class ConstAnalyzer : DiagnosticAnalyzer
    {
        internal static readonly TaintType[] ConstantTaintTypes = new []
        {
            TaintType.SCS0015,
        };

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
                            var warnings = PooledHashSet<Location>.GetInstance();

                            void CreateWarning(OperationAnalysisContext operationAnalysisContext, Location location, ISymbol symbol)
                            {
                                warnings.Add(location);

                                Diagnostic diagnostic = Diagnostic.Create(
                                                            this.TaintedDataEnteringSinkDescriptor,
                                                            location,
                                                            additionalLocations: new Location[] { location },
                                                            messageArgs: new object[] {
                                                                symbol.ToDisplayString(SymbolDisplayFormat.MinimallyQualifiedFormat),
                                                            });
                                operationAnalysisContext.ReportDiagnostic(diagnostic);
                            }

                            bool IsHardcoded(IOperation operation, IOperation value, OperationAnalysisContext operationAnalysisContext)
                            {
                                bool IsEmptyString(object? value)
                                {
                                    return Equals(value, null) || Equals(value, string.Empty);
                                }

                                if (value.ConstantValue.HasValue && !IsEmptyString(value.ConstantValue.Value))
                                    return true;

                                if (value.Kind == OperationKind.ArrayCreation &&
                                    value is IArrayCreationOperation arrayValue &&
                                    arrayValue.Initializer?.Children.All(x => x.ConstantValue.HasValue) == true)
                                {
                                    return true;
                                }

                                if (!operation.TryGetEnclosingControlFlowGraph(out var cfg))
                                    return false;

                                var valueContentResult = ValueContentAnalysis.TryGetOrComputeResult(cfg, owningSymbol, wellKnownTypeProvider,
                                    operationAnalysisContext.Options, TaintedDataEnteringSinkDescriptor, PointsToAnalysisKind.Complete, operationAnalysisContext.CancellationToken);
                                if (valueContentResult == null)
                                    return false;

                                ValueContentAbstractValue abstractValue = valueContentResult[value.Kind, value.Syntax];
                                if (abstractValue.NonLiteralState != ValueContainsNonLiteralState.No)
                                    return false;

                                if (abstractValue.LiteralValues.All(IsEmptyString))
                                    return false;

                                return true;
                            }

                            operationBlockStartContext.RegisterOperationAction(
                                operationAnalysisContext =>
                                {
                                    var operation = (IAssignmentOperation)operationAnalysisContext.Operation;
                                    if (!(operation.Target is IPropertyReferenceOperation propertyReferenceOperation))
                                        return;

                                    IEnumerable<SinkInfo>? infosForType = sinkInfoSymbolMap.GetInfosForType(propertyReferenceOperation.Member.ContainingType);
                                    if (infosForType != null &&
                                        infosForType.Any(x => x.SinkProperties.Contains(propertyReferenceOperation.Member.MetadataName)) &&
                                        IsHardcoded(operation, operation.Value, operationAnalysisContext))
                                    {
                                        CreateWarning(
                                            operationAnalysisContext,
                                            propertyReferenceOperation.Syntax.GetLocation(),
                                            propertyReferenceOperation.Member);
                                    }
                                },
                                OperationKind.SimpleAssignment);

                            operationBlockStartContext.RegisterOperationAction(
                                operationAnalysisContext =>
                                {
                                    var invocationOperation = (IInvocationOperation)operationAnalysisContext.Operation;
                                    IEnumerable<SinkInfo>? infosForType = sinkInfoSymbolMap.GetInfosForType(invocationOperation.TargetMethod.ContainingType);
                                    if (infosForType == null)
                                        return;

                                    foreach (SinkInfo sinkInfo in infosForType)
                                    {
                                        foreach (IArgumentOperation taintedArgument in invocationOperation.Arguments.Where(x => IsHardcoded(x, x.Value, operationAnalysisContext)))
                                        {
                                            if (sinkInfo.SinkMethodParameters.TryGetValue(invocationOperation.TargetMethod.MetadataName, out ImmutableHashSet<string> sinkParameters)
                                                && sinkParameters.Contains(taintedArgument.Parameter.MetadataName))
                                            {
                                                CreateWarning(
                                                    operationAnalysisContext,
                                                    invocationOperation.Syntax.GetLocation(),
                                                    invocationOperation.TargetMethod);
                                                return;
                                            }
                                        }
                                    }
                                },
                                OperationKind.Invocation);

                            operationBlockStartContext.RegisterOperationAction(
                                operationAnalysisContext =>
                                {
                                    var invocationOperation = (IObjectCreationOperation)operationAnalysisContext.Operation;
                                    IEnumerable<SinkInfo>? infosForType = sinkInfoSymbolMap.GetInfosForType(invocationOperation.Constructor.ContainingType);
                                    if (infosForType == null)
                                        return;

                                    foreach (SinkInfo sinkInfo in infosForType)
                                    {
                                        foreach (IArgumentOperation taintedArgument in invocationOperation.Arguments.Where(x => IsHardcoded(x, x.Value, operationAnalysisContext)))
                                        {
                                            if (sinkInfo.IsAnyStringParameterInConstructorASink
                                                && taintedArgument.Parameter.Type.SpecialType == SpecialType.System_String)
                                            {
                                                CreateWarning(
                                                    operationAnalysisContext,
                                                    invocationOperation.Syntax.GetLocation(),
                                                    taintedArgument.Parameter);
                                                return;
                                            }
                                            else if (sinkInfo.SinkMethodParameters.TryGetValue(invocationOperation.Constructor.MetadataName, out ImmutableHashSet<string> sinkParameters)
                                                        && sinkParameters.Contains(taintedArgument.Parameter.MetadataName))
                                            {
                                                CreateWarning(
                                                    operationAnalysisContext,
                                                    invocationOperation.Syntax.GetLocation(),
                                                    taintedArgument.Parameter);
                                                return;
                                            }
                                        }
                                    }
                                },
                                OperationKind.ObjectCreation);
                        });
                });
        }
    }
}
