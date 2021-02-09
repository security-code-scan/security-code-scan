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
    public class WeakPasswordValidatorPropertyAnalyzer : DiagnosticAnalyzer
    {
        private static readonly DiagnosticDescriptor RulePasswordLength                  = LocaleUtil.GetDescriptor("SCS0032"); // RequiredLength's value is too small
        private static readonly DiagnosticDescriptor RulePasswordValidators              = LocaleUtil.GetDescriptor("SCS0033"); // Not enough properties set
        private static readonly DiagnosticDescriptor RuleRequiredPasswordValidators      = LocaleUtil.GetDescriptor("SCS0034"); // Required property must be set

        private static readonly string[] BoolPropertyNames =  { "RequireDigit", "RequireLowercase", "RequireNonLetterOrDigit", "RequireUppercase" };

        private const string ValidatorTypeName = "Microsoft.AspNet.Identity.PasswordValidator";

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(
            RulePasswordLength,
            RulePasswordValidators,
            RuleRequiredPasswordValidators);

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
                    Compilation compilation = compilationContext.Compilation;
                    var wellKnownTypeProvider = WellKnownTypeProvider.GetOrCreate(compilation);

                    if (!wellKnownTypeProvider.TryGetOrCreateTypeByMetadataName(ValidatorTypeName, out var validatorType))
                        return;

                    var configuration = Configuration.GetOrCreate(compilationContext);

                    compilationContext.RegisterOperationBlockStartAction(
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
                                ctx =>
                                {
                                    IObjectCreationOperation invocationOperation = (IObjectCreationOperation)ctx.Operation;
                                    if (invocationOperation.Constructor.ContainingType != validatorType)
                                        return;

                                    var propertiesCount = 0;
                                    var requiredProperties = configuration.PasswordValidatorRequiredProperties;

                                    IAssignmentOperation TryGetInitializerAssignment(string name)
                                    {
                                        return (IAssignmentOperation)invocationOperation.Initializer
                                                                                        ?.Initializers
                                                                                        .FirstOrDefault(initializer => initializer is IAssignmentOperation assignmentOperaiton &&
                                        assignmentOperaiton.Target is IPropertyReferenceOperation propertyReferenceOperation &&
                                        propertyReferenceOperation.Property.Name == name);
                                    }

                                    var requiredLengthInitializer = TryGetInitializerAssignment("RequiredLength");

                                    if (requiredLengthInitializer == null)
                                    {
                                        if (requiredProperties.Contains("RequiredLength"))
                                        {
                                            var diagnostic = Diagnostic.Create(RuleRequiredPasswordValidators, invocationOperation.Syntax.GetLocation(), "RequiredLength");
                                            ctx.ReportDiagnostic(diagnostic);
                                        }
                                    }
                                    else
                                    {
                                        propertiesCount++;
                                        var requiredLength = configuration.PasswordValidatorRequiredLength;

                                        if ((requiredLengthInitializer.Value.ConstantValue.HasValue &&
                                             requiredLengthInitializer.Value.ConstantValue.Value is int intValue && intValue < requiredLength) ||
                                            !requiredLengthInitializer.Value.ConstantValue.HasValue && configuration.AuditMode)
                                        {
                                            ctx.ReportDiagnostic(Diagnostic.Create(RulePasswordLength, invocationOperation.Syntax.GetLocation(), requiredLength));
                                        }
                                    }

                                    foreach (var propertyName in BoolPropertyNames)
                                    {
                                        var initializerAssignment = TryGetInitializerAssignment(propertyName);
                                        if (initializerAssignment == null ||
                                            (initializerAssignment.Value.ConstantValue.HasValue &&
                                             initializerAssignment.Value.ConstantValue.Value is bool isRequired && !isRequired) ||
                                            !initializerAssignment.Value.ConstantValue.HasValue && configuration.AuditMode)
                                        {
                                            if (requiredProperties.Contains(propertyName))
                                            {
                                                ctx.ReportDiagnostic(Diagnostic.Create(RuleRequiredPasswordValidators, invocationOperation.Syntax.GetLocation(), propertyName));
                                            }
                                        }
                                        else
                                        {
                                            propertiesCount++;
                                        }
                                    }

                                    var minimumRequiredProperties = configuration.MinimumPasswordValidatorProperties;
                                    // If the PasswordValidator instance doesn't have enough properties set
                                    if (propertiesCount < minimumRequiredProperties)
                                    {
                                        ctx.ReportDiagnostic(Diagnostic.Create(RulePasswordValidators, invocationOperation.Syntax.GetLocation(), minimumRequiredProperties));
                                    }
                                },
                                OperationKind.ObjectCreation);
                        });
                });
        }
    }
}
