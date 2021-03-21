using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Threading;
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
    public class WeakPasswordValidatorPropertyAnalyzer : DiagnosticAnalyzer
    {
        private static readonly DiagnosticDescriptor RulePasswordLength             = LocaleUtil.GetDescriptor("SCS0032"); // RequiredLength's value is too small
        private static readonly DiagnosticDescriptor RulePasswordValidators         = LocaleUtil.GetDescriptor("SCS0033"); // Not enough properties set
        private static readonly DiagnosticDescriptor RuleRequiredPasswordValidators = LocaleUtil.GetDescriptor("SCS0034"); // Required property must be set

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(
            RulePasswordLength,
            RulePasswordValidators,
            RuleRequiredPasswordValidators);

        private static HazardousUsageEvaluationResult PropertiesCountEvaluatorCallback(PropertySetAbstractValue abstractValue, int minCount, bool auditMode)
        {
            int maybe = 0;
            int no = 0;
            for (int i = 0; i < abstractValue.KnownValuesCount; ++i)
            {
                switch (abstractValue[i])
                {
                    case PropertySetAbstractValueKind.MaybeFlagged:
                    ++maybe;
                    break;
                    case PropertySetAbstractValueKind.Unflagged:
                    ++no;
                    break;
                }
            }

            int count = no;
            if (!auditMode)
                count += maybe;

            if (count < minCount)
                if (no == 0 && maybe > 0)
                    return HazardousUsageEvaluationResult.MaybeFlagged;
                else
                    return HazardousUsageEvaluationResult.Flagged;
            else
                return HazardousUsageEvaluationResult.Unflagged;
        }

        private static PropertySetAbstractValueKind PropertySetToTrueCallback(ValueContentAbstractValue valueContentAbstractValue, bool auditMode)
        {
            var val = PropertySetCallbacks.EvaluateLiteralValues(valueContentAbstractValue, o => o != null && o.Equals(false));
            if (val == PropertySetAbstractValueKind.Unknown)
                val = auditMode ? PropertySetAbstractValueKind.MaybeFlagged : PropertySetAbstractValueKind.Unflagged;
            return val;
        }

        private static PropertySetAbstractValueKind PropertyLenCallback(ValueContentAbstractValue valueContentAbstractValue, bool auditMode, int minLen)
        {
            var val = PropertySetCallbacks.EvaluateLiteralValues(
                valueContentAbstractValue,
                o => o != null && Convert.ToInt32(o, CultureInfo.InvariantCulture) < minLen);
            if (val == PropertySetAbstractValueKind.Unknown)
                val = auditMode ? PropertySetAbstractValueKind.MaybeFlagged : PropertySetAbstractValueKind.Unflagged;
            return val;
        }

        private static readonly HazardousUsageEvaluatorCollection HazardousUsageEvaluators = new HazardousUsageEvaluatorCollection(
            new HazardousUsageEvaluator(
                HazardousUsageEvaluatorKind.Return,
                PropertySetCallbacks.HazardousIfAllFlaggedAndAtLeastOneKnown),
            new HazardousUsageEvaluator(
                HazardousUsageEvaluatorKind.Initialization,
                PropertySetCallbacks.HazardousIfAllFlaggedAndAtLeastOneKnown),
            new HazardousUsageEvaluator(
                HazardousUsageEvaluatorKind.Argument,
                PropertySetCallbacks.HazardousIfAllFlaggedAndAtLeastOneKnown));

        private static readonly string[] BoolPropertyNames = { "RequireDigit", "RequireLowercase", "RequireNonLetterOrDigit", "RequireUppercase" };
        private static readonly string[] AllPropertyNames  = BoolPropertyNames.Concat("RequiredLength").ToArray();

        private const string ValidatorTypeName = "Microsoft.AspNet.Identity.PasswordValidator";

        public override void Initialize(AnalysisContext context)
        {
            if (!Debugger.IsAttached) // prefer single thread for debugging in development
                context.EnableConcurrentExecution();

            if (context.IsAuditMode())
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
            else
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);

            context.RegisterCompilationStartAction(
                (CompilationStartAnalysisContext compilationStartAnalysisContext) =>
                {
                    Compilation compilation = compilationStartAnalysisContext.Compilation;
                    var wellKnownTypeProvider = WellKnownTypeProvider.GetOrCreate(compilation);

                    if (!wellKnownTypeProvider.TryGetOrCreateTypeByMetadataName(ValidatorTypeName, out var validatorType))
                        return;

                    var rootOperationsNeedingAnalysis = PooledHashSet<(IOperation, ISymbol)>.GetInstance();

                    compilationStartAnalysisContext.RegisterOperationBlockStartAction(
                        operationBlockStartContext =>
                        {
                            ISymbol owningSymbol = operationBlockStartContext.OwningSymbol;
                            AnalyzerOptions options = operationBlockStartContext.Options;
                            CancellationToken cancellationToken = operationBlockStartContext.CancellationToken;
                            if (options.IsConfiguredToSkipAnalysis(RuleRequiredPasswordValidators, owningSymbol, compilation, cancellationToken))
                            {
                                return;
                            }

                            operationBlockStartContext.RegisterOperationAction(
                                (OperationAnalysisContext operationAnalysisContext) =>
                                {
                                    var returnOperation = (IReturnOperation)operationAnalysisContext.Operation;

                                    if (validatorType.Equals(returnOperation.ReturnedValue?.Type))
                                    {
                                        lock (rootOperationsNeedingAnalysis)
                                        {
                                            rootOperationsNeedingAnalysis.Add(
                                                (returnOperation.GetRoot(), operationAnalysisContext.ContainingSymbol));
                                        }
                                    }
                                },
                                OperationKind.Return);

                            operationBlockStartContext.RegisterOperationAction(
                                (OperationAnalysisContext operationAnalysisContext) =>
                                {
                                    var argumentOperation = (IArgumentOperation)operationAnalysisContext.Operation;

                                    if (argumentOperation.Parameter.Type.Equals(validatorType))
                                    {
                                        lock (rootOperationsNeedingAnalysis)
                                        {
                                            rootOperationsNeedingAnalysis.Add((argumentOperation.GetRoot(), operationAnalysisContext.ContainingSymbol));
                                        }
                                    }
                                },
                                OperationKind.Argument);

                            operationBlockStartContext.RegisterOperationAction(
                                ctx =>
                                {
                                    var operation = (IObjectCreationOperation)ctx.Operation;
                                    if (validatorType.Equals(operation.Type))
                                    {
                                        lock (rootOperationsNeedingAnalysis)
                                        {
                                            rootOperationsNeedingAnalysis.Add((operation.GetRoot(), ctx.ContainingSymbol));
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

                                    PooledDictionary<(Location Location, IMethodSymbol? Method), HazardousUsageEvaluationResult>? GetHazardousUsages(
                                        ConstructorMapper constructorMapper,
                                        PropertyMapperCollection propertyMappers,
                                        HazardousUsageEvaluatorCollection hazardousUsageEvaluators)
                                    {
                                        return PropertySetAnalysis.BatchGetOrComputeHazardousUsages(
                                            compilationAnalysisContext.Compilation,
                                            rootOperationsNeedingAnalysis,
                                            compilationAnalysisContext.Options,
                                            ValidatorTypeName,
                                            constructorMapper,
                                            propertyMappers,
                                            hazardousUsageEvaluators,
                                            InterproceduralAnalysisConfiguration.Create(
                                                compilationAnalysisContext.Options,
                                                SupportedDiagnostics,
                                                rootOperationsNeedingAnalysis.First().Item1,
                                                compilationAnalysisContext.Compilation,
                                                defaultInterproceduralAnalysisKind: InterproceduralAnalysisKind.ContextSensitive,
                                                cancellationToken: compilationAnalysisContext.CancellationToken));
                                    }

                                    var configuration = Configuration.GetOrCreate(compilationStartAnalysisContext);

                                    foreach (var requiredProperty in configuration.PasswordValidatorRequiredProperties)
                                    {
                                        allResults?.Free(compilationAnalysisContext.CancellationToken);
                                        allResults = null;
                                        (PropertyMapperCollection propertyMappers, ConstructorMapper constructorMapper) =
                                            BuildRequiredPropertiesMappers((x) => PropertySetToTrueCallback(x, configuration.AuditMode), requiredProperty);
                                        allResults = GetHazardousUsages(constructorMapper, propertyMappers, HazardousUsageEvaluators);
                                        ReportDiagnostics(
                                            RuleRequiredPasswordValidators,
                                            compilationAnalysisContext,
                                            allResults,
                                            configuration.AuditMode,
                                            requiredProperty);
                                    }

                                    allResults?.Free(compilationAnalysisContext.CancellationToken);
                                    allResults = null;
                                    (PropertyMapperCollection propertyMappers2, ConstructorMapper constructorMapper2) =
                                        BuildRequiredPropertiesMappers((x) => PropertyLenCallback(x, configuration.AuditMode, configuration.PasswordValidatorRequiredLength), "RequiredLength");
                                    allResults = GetHazardousUsages(constructorMapper2, propertyMappers2, HazardousUsageEvaluators);
                                    ReportDiagnostics(
                                        RulePasswordLength,
                                        compilationAnalysisContext,
                                        allResults,
                                        configuration.AuditMode,
                                        configuration.PasswordValidatorRequiredLength);

                                    var hazardousUsageEvaluators = new HazardousUsageEvaluatorCollection(
                                        new HazardousUsageEvaluator(
                                            HazardousUsageEvaluatorKind.Return,
                                            (abstractValue) => PropertiesCountEvaluatorCallback(
                                                abstractValue, configuration.MinimumPasswordValidatorProperties, configuration.AuditMode)),
                                        new HazardousUsageEvaluator(
                                            HazardousUsageEvaluatorKind.Initialization,
                                            (abstractValue) => PropertiesCountEvaluatorCallback(
                                                abstractValue, configuration.MinimumPasswordValidatorProperties, configuration.AuditMode)),
                                        new HazardousUsageEvaluator(
                                            HazardousUsageEvaluatorKind.Argument,
                                            (abstractValue) => PropertiesCountEvaluatorCallback(
                                                abstractValue, configuration.MinimumPasswordValidatorProperties, configuration.AuditMode)));
                                    allResults?.Free(compilationAnalysisContext.CancellationToken);
                                    allResults = null;
                                    (PropertyMapperCollection propertyMappers3, ConstructorMapper constructorMapper3) =
                                        BuildRequiredPropertiesMappers((x) => PropertySetToTrueCallback(x, configuration.AuditMode), AllPropertyNames);
                                    allResults = GetHazardousUsages(constructorMapper3, propertyMappers3, hazardousUsageEvaluators);
                                    ReportDiagnostics(
                                        RulePasswordValidators,
                                        compilationAnalysisContext,
                                        allResults,
                                        configuration.AuditMode,
                                        configuration.MinimumPasswordValidatorProperties);
                                }
                            }
                            finally
                            {
                                rootOperationsNeedingAnalysis.Free(compilationAnalysisContext.CancellationToken);
                                allResults?.Free(compilationAnalysisContext.CancellationToken);
                            }
                        });
                });
        }

        private static void ReportDiagnostics(
            DiagnosticDescriptor descriptor,
            CompilationAnalysisContext compilationAnalysisContext,
            PooledDictionary<(Location Location, IMethodSymbol? Method), HazardousUsageEvaluationResult>? allResults,
            bool auditMode,
            params object?[]? messageArgs)
        {
            if (allResults != null)
            {

                foreach (KeyValuePair<(Location Location, IMethodSymbol? Method), HazardousUsageEvaluationResult> kvp in allResults)
                {
                    DiagnosticDescriptor d;
                    switch (kvp.Value)
                    {
                        case HazardousUsageEvaluationResult.Flagged:
                        d = descriptor;
                        break;

                        case HazardousUsageEvaluationResult.MaybeFlagged:
                            {
                                if (auditMode)
                                    d = descriptor;
                                else
                                    continue;
                            }
                        break;

                        default:
                        Debug.Fail($"Unhandled result value {kvp.Value}");
                        continue;
                    }

                    compilationAnalysisContext.ReportDiagnostic(Diagnostic.Create(d, kvp.Key.Location, messageArgs));
                }
            }
        }

        private static (PropertyMapperCollection, ConstructorMapper) BuildRequiredPropertiesMappers(
            PropertyMapper.ValueContentAbstractValueCallback evaluator,
            params string[] requiredProperties)
        {
            int i = 0;
            var propMapperList = new List<PropertyMapper>();
            foreach (var propertyName in requiredProperties)
            {
                propMapperList.Add(new PropertyMapper(propertyName, evaluator, i++));
            }
            return (new PropertyMapperCollection(propMapperList),
                    new(ImmutableArray.CreateRange(Enumerable.Repeat(PropertySetAbstractValueKind.Flagged, propMapperList.Count))));
        }
    }
}
