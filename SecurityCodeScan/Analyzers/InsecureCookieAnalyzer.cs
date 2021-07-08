using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Linq;
using Analyzer.Utilities;
using Analyzer.Utilities.Extensions;
using Analyzer.Utilities.FlowAnalysis.Analysis.PropertySetAnalysis;
using Analyzer.Utilities.PooledObjects;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.ValueContentAnalysis;
using Microsoft.CodeAnalysis.Operations;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Config;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class CookieAnalyzer : DiagnosticAnalyzer
    {
        public const            string               DiagnosticIdSecure = "SCS0008";
        private static readonly DiagnosticDescriptor RuleSecure         = LocaleUtil.GetDescriptor(DiagnosticIdSecure);

        public const            string               DiagnosticIdHttpOnly = "SCS0009";
        private static readonly DiagnosticDescriptor RuleHttpOnly         = LocaleUtil.GetDescriptor(DiagnosticIdHttpOnly);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(RuleSecure, RuleHttpOnly);

        private static readonly ConstructorMapper ConstructorMapper = new(ImmutableArray.Create(PropertySetAbstractValueKind.Flagged));

        private static readonly HazardousUsageEvaluatorCollection HazardousUsageEvaluators = new HazardousUsageEvaluatorCollection(
            new HazardousUsageEvaluator(
                HazardousUsageEvaluatorKind.Argument,
                PropertySetCallbacks.HazardousIfAllFlaggedAndAtLeastOneKnown));

        public override void Initialize(AnalysisContext context)
        {
            if (!Debugger.IsAttached) // prefer single thread for debugging in development
                context.EnableConcurrentExecution();

            if (context.IsAuditMode())
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
            else
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);

            void Initialize(
                AnalysisContext context,
                DiagnosticDescriptor descriptor,
                string propertyName,
                string cookieTypeName,
                Action<DiagnosticDescriptor, OperationBlockStartAnalysisContext, WellKnownTypeProvider> checkSink = null)
            {
                context.RegisterCompilationStartAction(
                    (CompilationStartAnalysisContext compilationStartAnalysisContext) =>
                    {
                        var wellKnownTypeProvider = WellKnownTypeProvider.GetOrCreate(compilationStartAnalysisContext.Compilation);
                        if (!wellKnownTypeProvider.TryGetOrCreateTypeByMetadataName(cookieTypeName, out var cookieOptionsTypeSymbol))
                            return;

                        var rootOperationsNeedingAnalysis = PooledHashSet<(IOperation, ISymbol)>.GetInstance();

                        compilationStartAnalysisContext.RegisterOperationBlockStartAction(
                            (OperationBlockStartAnalysisContext operationBlockStartAnalysisContext) =>
                            {
                                if (operationBlockStartAnalysisContext.Options.IsConfiguredToSkipAnalysis(
                                        descriptor,
                                        operationBlockStartAnalysisContext.OwningSymbol,
                                        operationBlockStartAnalysisContext.Compilation,
                                        operationBlockStartAnalysisContext.CancellationToken))
                                {
                                    return;
                                }

                                if (checkSink != null)
                                    checkSink(descriptor, operationBlockStartAnalysisContext, wellKnownTypeProvider);

                                operationBlockStartAnalysisContext.RegisterOperationAction(
                                    (OperationAnalysisContext operationAnalysisContext) =>
                                    {
                                        var operation = (IObjectCreationOperation)operationAnalysisContext.Operation;
                                        if (cookieOptionsTypeSymbol.Equals(operation.Type))
                                        {
                                            lock (rootOperationsNeedingAnalysis)
                                            {
                                                rootOperationsNeedingAnalysis.Add((operation.GetRoot(), operationAnalysisContext.ContainingSymbol));
                                            }
                                        }
                                    },
                                    OperationKind.ObjectCreation);
                            });

                        compilationStartAnalysisContext.RegisterCompilationEndAction(
                            (CompilationAnalysisContext compilationAnalysisContext) =>
                            {
                                PooledDictionary<(Location Location, IMethodSymbol? Method), HazardousUsageEvaluationResult>? allResults = null;

                                try
                                {
                                    lock (rootOperationsNeedingAnalysis)
                                    {
                                        if (!rootOperationsNeedingAnalysis.Any())
                                        {
                                            return;
                                        }

                                        var configuration = Configuration.GetOrCreate(compilationStartAnalysisContext);

                                        PropertyMapperCollection propertyMappers = new(
                                            new PropertyMapper(
                                                propertyName,
                                                (ValueContentAbstractValue valueContentAbstractValue) =>
                                                {
                                                    var val = PropertySetCallbacks.EvaluateLiteralValues(valueContentAbstractValue, o => o != null && o.Equals(false));
                                                    return (val == PropertySetAbstractValueKind.Unknown && configuration.AuditMode) ? PropertySetAbstractValueKind.MaybeFlagged : val;
                                                }));

                                        allResults = PropertySetAnalysis.BatchGetOrComputeHazardousUsages(
                                            compilationAnalysisContext.Compilation,
                                            rootOperationsNeedingAnalysis,
                                            compilationAnalysisContext.Options,
                                            cookieTypeName,
                                            ConstructorMapper,
                                            propertyMappers,
                                            HazardousUsageEvaluators,
                                            InterproceduralAnalysisConfiguration.Create(
                                                compilationAnalysisContext.Options,
                                                SupportedDiagnostics,
                                                rootOperationsNeedingAnalysis.First().Item1, // really uses only SyntaxTree that is the same for all operations
                                                compilationAnalysisContext.Compilation,
                                                defaultInterproceduralAnalysisKind: InterproceduralAnalysisKind.ContextSensitive,
                                                cancellationToken: compilationAnalysisContext.CancellationToken));
                                    }

                                    if (allResults == null)
                                    {
                                        return;
                                    }

                                    CheckSink(allResults, descriptor, compilationAnalysisContext, "System.Web.HttpCookieCollection", SystemWebCookieMethods, wellKnownTypeProvider);
                                    CheckSink(allResults, descriptor, compilationAnalysisContext, WellKnownTypeNames.MicrosoftAspNetCoreHttpIResponseCookies, NetCoreCookieMethods, wellKnownTypeProvider);
                                }
                                finally
                                {
                                    rootOperationsNeedingAnalysis.Free(compilationAnalysisContext.CancellationToken);
                                    allResults?.Free(compilationAnalysisContext.CancellationToken);
                                }
                            });

                    });
            }

            Initialize(context, RuleSecure,   "Secure",   WellKnownTypeNames.MicrosoftAspNetCoreHttpCookieOptions, CheckSink);
            Initialize(context, RuleHttpOnly, "HttpOnly", WellKnownTypeNames.MicrosoftAspNetCoreHttpCookieOptions, CheckSink);
            Initialize(context, RuleSecure,   "Secure",   WellKnownTypeNames.SystemWebHttpCookie);
            Initialize(context, RuleHttpOnly, "HttpOnly", WellKnownTypeNames.SystemWebHttpCookie);
        }

        private static readonly ImmutableArray<string> SystemWebCookieMethods = new []{ "Set", "Add" }.ToImmutableArray();
        private static readonly ImmutableArray<string> NetCoreCookieMethods   = new []{ "Append" }.ToImmutableArray();

        private static void CheckSink(
            PooledDictionary<(Location Location, IMethodSymbol? Method), HazardousUsageEvaluationResult>? allResults,
            DiagnosticDescriptor descriptor,
            CompilationAnalysisContext compilationAnalysisContext,
            string typeName,
            ImmutableArray<string> methodNames,
            WellKnownTypeProvider wellKnownTypeProvider)
        {
            if (!wellKnownTypeProvider.TryGetOrCreateTypeByMetadataName(typeName, out var symbol))
                return;

            foreach (KeyValuePair<(Location Location, IMethodSymbol? Method), HazardousUsageEvaluationResult> kvp in allResults)
            {
                DiagnosticDescriptor d;
                switch (kvp.Value)
                {
                    case HazardousUsageEvaluationResult.Flagged:
                    case HazardousUsageEvaluationResult.MaybeFlagged:
                        d = descriptor;
                    break;

                    default:
                        Debug.Fail($"Unhandled result value {kvp.Value}");
                    continue;
                }

                if (kvp.Key.Method.ContainingType != symbol)
                    continue;

                if (!methodNames.Contains(kvp.Key.Method.Name))
                    continue;

                compilationAnalysisContext.ReportDiagnostic(Diagnostic.Create(d, kvp.Key.Location));
            }
        }

        private static void CheckSink(
            DiagnosticDescriptor descriptor,
            OperationBlockStartAnalysisContext operationBlockStartAnalysisContext,
            WellKnownTypeProvider wellKnownTypeProvider)
        {
            if (!wellKnownTypeProvider.TryGetOrCreateTypeByMetadataName(WellKnownTypeNames.MicrosoftAspNetCoreHttpIResponseCookies, out var iResponseCookiesTypeSymbol))
                return;

            operationBlockStartAnalysisContext.RegisterOperationAction(
                (OperationAnalysisContext operationAnalysisContext) =>
                {
                    var invocationOperation = (IInvocationOperation)operationAnalysisContext.Operation;
                    var methodSymbol = invocationOperation.TargetMethod;

                    if (methodSymbol.ContainingType is INamedTypeSymbol namedTypeSymbol &&
                        namedTypeSymbol.Equals(iResponseCookiesTypeSymbol) &&
                        methodSymbol.Name == "Append")
                    {
                        if (methodSymbol.Parameters.Length < 3)
                        {
                            operationAnalysisContext.ReportDiagnostic(invocationOperation.CreateDiagnostic(descriptor));
                        }
                    }
                },
                OperationKind.Invocation);
        }
    }
}
