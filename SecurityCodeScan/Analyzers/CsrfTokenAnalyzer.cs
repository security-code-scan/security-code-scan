#nullable disable
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Config;

namespace SecurityCodeScan.Analyzers
{
    [SecurityAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    internal class AthorizationAttributeDiagnosticAnalyzer : SecurityAnalyzer
    {
        public const           string               DiagnosticId = "SCS0012";
        public static readonly DiagnosticDescriptor Rule         = LocaleUtil.GetDescriptor(DiagnosticId);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(Rule);

        public override void Initialize(ISecurityAnalysisContext context)
        {
            context.RegisterCompilationStartAction(OnCompilationStartAction);
        }

        private void OnCompilationStartAction(CompilationStartAnalysisContext context, Configuration config)
        {
            var analyzer = new AttributeAnalyzer(Rule);
            context.RegisterSymbolAction((ctx) => analyzer.VisitClass(ctx, config.AuthorizeGoups), SymbolKind.NamedType);
        }
    }

    [SecurityAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    internal class CsrfTokenDiagnosticAnalyzer : SecurityAnalyzer
    {
        public const           string               DiagnosticId = "SCS0016";
        public static readonly DiagnosticDescriptor Rule         = LocaleUtil.GetDescriptor(DiagnosticId);

        public override        ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(Rule);

        public override void Initialize(ISecurityAnalysisContext context)
        {
            context.RegisterCompilationStartAction(OnCompilationStartAction);
        }

        private void OnCompilationStartAction(CompilationStartAnalysisContext context, Configuration config)
        {
            var analyzer = new AttributeAnalyzer(Rule);
            context.RegisterSymbolAction((ctx) => analyzer.VisitClass(ctx, config.CsrfGoups), SymbolKind.NamedType);
        }
    }

    internal class AttributeAnalyzer
    {
        private readonly DiagnosticDescriptor Rule;

        public AttributeAnalyzer(DiagnosticDescriptor rule)
        {
            Rule = rule;
        }

        private static bool HasApplicableAttribute(AttributeData attributeData, Dictionary<string, List<AttributeCondition>> attributes)
        {
            if (!attributes.Any())
                return false;

            var name = attributeData.AttributeClass.ToString();

            var args = attributeData.ConstructorArguments;
            var namedArgs = attributeData.NamedArguments;

            if (!attributes.TryGetValue(name, out var conditions))
                return false;

            foreach (var condition in conditions)
            {
                var applies =
                        condition.MustMatch.All(
                            c =>
                            {
                                var expectedVal = c.ExpectedValue;
                                var arg = c.ParameterIndexOrPropertyName;
                                TypedConstant? actualVal;
                                if (arg is int argIx)
                                {
                                    // something very weird is happening, freak out
                                    if (argIx >= args.Length)
                                        return false;

                                    actualVal = args[argIx];
                                }
                                else if (arg is string propName)
                                {
                                    actualVal = null;
                                    foreach (var named in namedArgs)
                                    {
                                        if (named.Key.Equals(propName))
                                        {
                                            actualVal = named.Value;
                                            break;
                                        }
                                    }

                                    if (actualVal == null)
                                        return false;
                                }
                                else
                                {
                                    throw new Exception($"Unexpected ParameterIndexOrPropertyName: {arg}");
                                }

                                if (actualVal.Value.IsNull)
                                    return false;

                                return actualVal.Value.Value.Equals(expectedVal);
                            }
                        );

                if (applies)
                    return true;
            }

            return false;
        }

        private static bool IsAntiForgeryToken(AttributeData attributeData, NamedGroup group)
        => HasApplicableAttribute(attributeData, group.RequiredAttributes);

        public void VisitClass(SymbolAnalysisContext ctx, IReadOnlyCollection<NamedGroup> namedGroups)
        {
            var classSymbol = (ITypeSymbol)ctx.Symbol;
            var diagnostics = new Dictionary<Location, Diagnostic>();

            foreach (var group in namedGroups)
            {
                VisitClass(classSymbol, group, diagnostics);
            }

            foreach (var diagnostic in diagnostics.Values)
            {
                ctx.ReportDiagnostic(diagnostic);
            }
        }

        private void VisitClass(ITypeSymbol classSymbol, NamedGroup group, Dictionary<Location, Diagnostic> diagnostics)
        {
            if (group?.Class?.Names.Any() == true)
            {
                var descendsFromController = classSymbol.IsDerivedFrom(group.Class.Names);
                if (!descendsFromController)
                    return;
            }

            if (AntiforgeryAttributeExists(classSymbol, group))
                return;

            if (IsClassIgnored(classSymbol, group))
                return;

            foreach (var member in classSymbol.GetMembers())
            {
                if (!(member is IMethodSymbol methodSymbol))
                    continue;

                var location = methodSymbol.Locations[0];
                if (diagnostics.ContainsKey(location)) // first NamedGroup in a sequence wins
                    continue;

                if (IsMethodIgnored(methodSymbol, group))
                    continue;

                if (AntiforgeryAttributeExists(methodSymbol, group))
                    continue;

                if (AreParametersSafe(methodSymbol, group))
                    continue;

                diagnostics.Add(location, Diagnostic.Create(group.Message != null ? group.Message : Rule, location));
            }
        }

        private static bool AreParametersSafe(IMethodSymbol methodSymbol, NamedGroup group)
        {
            foreach (var arg in methodSymbol.Parameters)
            {
                if (arg.HasAttribute(attributeData => HasApplicableAttribute(attributeData, group.Parameter.Exclude)))
                {
                    return true;
                }

                if (arg.HasAttribute(attributeData => HasApplicableAttribute(attributeData, group.Parameter.Include)))
                {
                    return false;
                }
            }

            return group.Parameter.Include.Any();
        }

        private static bool IsClassIgnored(ITypeSymbol classSymbol, NamedGroup group)
        {
            if (group.Class == null)
                return false;

            if (!group.Class.Include.Any() && !group.Class.Exclude.Any())
                return false;

            if (classSymbol.HasDerivedClassAttribute(attributeData => HasApplicableAttribute(attributeData, group.Class.Exclude)))
                return true;

            if (group.Class.Include.Any())
                return !classSymbol.HasDerivedClassAttribute(attributeData => HasApplicableAttribute(attributeData, group.Class.Include));

            return false;
        }

        private static bool IsMethodIgnored(IMethodSymbol methodSymbol, NamedGroup group)
        {
            if (!group.Method.Include.Any() && !group.Method.Exclude.Any())
                return false;

            if (methodSymbol.HasDerivedMethodAttribute(attributeData => HasApplicableAttribute(attributeData, group.Method.Exclude)))
                return true;

            if (group.Method.Include.Any())
                return !methodSymbol.HasDerivedMethodAttribute(attributeData => HasApplicableAttribute(attributeData, group.Method.Include));

            return false;
        }

        private static bool AntiforgeryAttributeExists(ITypeSymbol classSymbol, NamedGroup group)
        {
            if (!group.RequiredAttributes.Any())
                return false;

            return classSymbol.HasDerivedClassAttribute(c => IsAntiForgeryToken(c, group));
        }

        private static bool AntiforgeryAttributeExists(IMethodSymbol methodSymbol, NamedGroup group)
        {
            if (!group.RequiredAttributes.Any())
                return false;

            return methodSymbol.HasDerivedMethodAttribute(c => IsAntiForgeryToken(c, group));
        }
    }
}
