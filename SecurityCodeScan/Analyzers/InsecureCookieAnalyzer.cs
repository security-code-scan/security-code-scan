using System.Collections.Immutable;
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
    [SecurityAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    internal class InsecureCookieAnalyzer : SecurityAnalyzer
    {
        public const            string               DiagnosticIdSecure = "SCS0008";
        private static readonly DiagnosticDescriptor RuleSecure         = LocaleUtil.GetDescriptor(DiagnosticIdSecure);

        public const            string               DiagnosticIdHttpOnly = "SCS0009";
        private static readonly DiagnosticDescriptor RuleHttpOnly         = LocaleUtil.GetDescriptor(DiagnosticIdHttpOnly);

        private const string HttpCookieTypeName = "System.Web.HttpCookie";
        private const string CookieOptionsTypeName = "Microsoft.AspNetCore.Http.CookieOptions";

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(RuleSecure, RuleHttpOnly);

        public override void Initialize(ISecurityAnalysisContext context)
        {
            CookieAnalyzer.Initialize(context, HttpCookieTypeName);
            CookieAnalyzer.Initialize(context, CookieOptionsTypeName);
        }

        private class CookieAnalyzer
        {
            public static void Initialize(ISecurityAnalysisContext context, string type)
            {
                context.RegisterCompilationStartAction(
                    (CompilationStartAnalysisContext compilationContext, Configuration configuration) =>
                    {
                        Compilation compilation = compilationContext.Compilation;
                        var wellKnownTypeProvider = WellKnownTypeProvider.GetOrCreate(compilation);

                        if (!wellKnownTypeProvider.TryGetOrCreateTypeByMetadataName(type, out var cookieType))
                        {
                            return;
                        }

                        compilationContext.RegisterOperationBlockStartAction(
                            operationBlockStartContext =>
                            {
                                ISymbol owningSymbol = operationBlockStartContext.OwningSymbol;
                                AnalyzerOptions options = operationBlockStartContext.Options;
                                CancellationToken cancellationToken = operationBlockStartContext.CancellationToken;
                                if (owningSymbol.IsConfiguredToSkipAnalysis(options, RuleSecure, compilation, cancellationToken))
                                {
                                    return;
                                }

                                operationBlockStartContext.RegisterOperationAction(
                                    ctx =>
                                    {
                                        IObjectCreationOperation invocationOperation = (IObjectCreationOperation)ctx.Operation;
                                        if (invocationOperation.Constructor.ContainingType.GetBaseTypesAndThis().All(x => x != cookieType))
                                        {
                                            return;
                                        }

                                        IAssignmentOperation TryGetInitializerAssignment(string name)
                                        {
                                            return (IAssignmentOperation)invocationOperation.Initializer
                                                                                            ?.Initializers
                                                                                            .FirstOrDefault(initializer => initializer is IAssignmentOperation assignmentOperaiton &&
                                            assignmentOperaiton.Target is IPropertyReferenceOperation propertyReferenceOperation &&
                                            propertyReferenceOperation.Property.Name == name);
                                        }

                                        var isSecureInitializer = TryGetInitializerAssignment("Secure");
                                        if (isSecureInitializer == null)
                                        {
                                            ctx.ReportDiagnostic(Diagnostic.Create(RuleSecure, invocationOperation.Syntax.GetLocation()));
                                        }

                                        var isHttpOnlyInitializer = TryGetInitializerAssignment("HttpOnly");
                                        if (isHttpOnlyInitializer == null)
                                        {
                                            ctx.ReportDiagnostic(Diagnostic.Create(RuleHttpOnly, invocationOperation.Syntax.GetLocation()));
                                        }
                                    },
                                    OperationKind.ObjectCreation);

                                operationBlockStartContext.RegisterOperationAction(
                                    ctx =>
                                    {
                                        IAssignmentOperation operation = (IAssignmentOperation)ctx.Operation;
                                        if (!(operation.Target is IPropertyReferenceOperation propertyReferenceOperation))
                                            return;

                                        if (propertyReferenceOperation.Member.ContainingType.GetBaseTypesAndThis().All(x => x != cookieType))
                                        {
                                            return;
                                        }

                                        if (propertyReferenceOperation.Member.Name == "Secure" &&
                                            ((operation.Value.ConstantValue.HasValue &&
                                             operation.Value.ConstantValue.Value is bool isSecure && !isSecure) ||
                                            !operation.Value.ConstantValue.HasValue && configuration.AuditMode))
                                        {
                                            ctx.ReportDiagnostic(Diagnostic.Create(RuleSecure, operation.Syntax.GetLocation()));
                                        }

                                        if (propertyReferenceOperation.Member.Name == "HttpOnly" &&
                                            ((operation.Value.ConstantValue.HasValue &&
                                             operation.Value.ConstantValue.Value is bool isHttpOnly && !isHttpOnly) ||
                                            !operation.Value.ConstantValue.HasValue && configuration.AuditMode))
                                        {
                                            ctx.ReportDiagnostic(Diagnostic.Create(RuleHttpOnly, operation.Syntax.GetLocation()));
                                        }
                                    },
                                    OperationKind.SimpleAssignment);
                            });
                    });
            }
        }
    }
}
