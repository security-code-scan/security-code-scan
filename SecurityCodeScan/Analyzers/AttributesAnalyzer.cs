#nullable disable
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Analyzer.Utilities;
using Analyzer.Utilities.Extensions;
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
            var analyzer = new AttributesAnalyzer(Rule, WellKnownTypeProvider.GetOrCreate(context.Compilation));
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
            var analyzer = new AttributesAnalyzer(Rule, WellKnownTypeProvider.GetOrCreate(context.Compilation));
            context.RegisterSymbolAction((ctx) => analyzer.VisitClass(ctx, config.CsrfGoups), SymbolKind.NamedType);
        }
    }

    internal class AttributesAnalyzer
    {
        private readonly DiagnosticDescriptor Rule;

        private readonly WellKnownTypeProvider WellKnownTypeProvider;

        public AttributesAnalyzer(DiagnosticDescriptor rule, WellKnownTypeProvider wellKnownTypeProvider)
        {
            Rule = rule;
            WellKnownTypeProvider = wellKnownTypeProvider;
        }

        private static bool SatisfiesConditon(AttributeData attributeData, List<AttributeCondition> conditions)
        {
            var args = attributeData.ConstructorArguments;
            var namedArgs = attributeData.NamedArguments;

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
                                        return expectedVal == AttributeCondition.NONE;
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

        public void VisitClass(SymbolAnalysisContext ctx, IReadOnlyCollection<NamedGroup> namedGroups)
        {
            var classSymbol = (ITypeSymbol)ctx.Symbol;
            var diagnostics = new Dictionary<Location, Diagnostic>();

            var groupCache = _classIsControllerByCompilation.GetOrCreateValue(ctx.Compilation, (compilation)
                    => new ConcurrentDictionary<NamedGroup, ConcurrentDictionary<INamedTypeSymbol, bool>>());

            foreach (var group in namedGroups)
            {
                if (!groupCache.TryGetValue(group, out var classCache))
                {
                    classCache = new ConcurrentDictionary<INamedTypeSymbol, bool>();
                    if (!groupCache.TryAdd(group, classCache))
                        if (!groupCache.TryGetValue(group, out classCache))
                            throw new Exception("groupCache.TryGetValue failed");
                }

                VisitClass(classSymbol, group, diagnostics, classCache);
            }

            foreach (var diagnostic in diagnostics.Values)
            {
                ctx.ReportDiagnostic(diagnostic);
            }
        }

        /// <summary>
        /// Cached information if the specified symbol is a Asp.Net Controller: (compilation) -> ((named group) - > ((class symbol) -> (is Controller)))
        /// </summary>
        private readonly BoundedCacheWithFactory<Compilation, ConcurrentDictionary<NamedGroup, ConcurrentDictionary<INamedTypeSymbol, bool>>> _classIsControllerByCompilation =
            new BoundedCacheWithFactory<Compilation, ConcurrentDictionary<NamedGroup, ConcurrentDictionary<INamedTypeSymbol, bool>>>();

        private void VisitClass(
            ITypeSymbol classSymbol,
            NamedGroup group,
            Dictionary<Location, Diagnostic> diagnostics,
            ConcurrentDictionary<INamedTypeSymbol, bool> classCache)
        {
            if (!(classSymbol is INamedTypeSymbol typeSymbol))
                return;

            if (RequiredAttributeExists((c) => typeSymbol.TryGetDerivedAttribute(c), group.RequiredAttributes))
                return;

            if (group.Class != null)
            {
                if (!classCache.TryGetValue(typeSymbol, out bool isTheClass))
                {
                    isTheClass = false;

                    bool IsTheClassBySuffix()
                    {
                        if (typeSymbol.Name.EndsWith(group.Class.Suffix.Text, StringComparison.Ordinal))
                        {
                            return true;
                        }
                        else if (group.Class.Suffix.IncludeParent &&
                                 typeSymbol.GetBaseTypes().Any(x => x.Name.EndsWith(group.Class.Suffix.Text, StringComparison.Ordinal)))
                        {
                            return true;
                        }
                        else
                        {
                            return false;
                        }
                    }

                    if (group.Class.Accessibility != null &&
                        group.Class.Accessibility.All(a => a != typeSymbol.DeclaredAccessibility))
                    {
                        isTheClass = false;
                    }
                    else
                    {
                        if (group.Class.Suffix != null &&
                            group.Class.Parent == null)
                        {
                            isTheClass = IsTheClassBySuffix();
                        }
                        else if (group.Class.Parent != null &&
                                 typeSymbol.GetBaseTypesAndThis().Any(x => x == WellKnownTypeProvider.GetOrCreateTypeByMetadataName(group.Class.Parent)))
                        {
                            isTheClass = group.Class.Suffix != null ? IsTheClassBySuffix() : true;
                        }

                        if (group.Class?.Exclude != null &&
                            RequiredAttributeExists((c) => typeSymbol.TryGetDerivedAttribute(c), group.Class.Exclude))
                        {
                            isTheClass = false;
                        }
                        else if (group.Class?.Include != null &&
                                 RequiredAttributeExists((c) => typeSymbol.TryGetDerivedAttribute(c), group.Class.Include))
                        {
                            isTheClass = true;
                        }
                    }

                    classCache.TryAdd(typeSymbol, isTheClass);
                }

                if (!isTheClass)
                {
                    return;
                }
            }

            foreach (var member in classSymbol.GetMembers())
            {
                if (!(member is IMethodSymbol methodSymbol) || methodSymbol.IsPropertyAccessor())
                    continue;

                var location = methodSymbol.Locations[0];
                if (diagnostics.ContainsKey(location)) // first NamedGroup in a sequence wins
                    continue;

                if (group.Method != null)
                {
                    if (group.Method.Static.HasValue && group.Method.Static != methodSymbol.IsStatic)
                        continue;

                    if (group.Method.IncludeConstructor.HasValue && group.Method.IncludeConstructor != methodSymbol.IsConstructor())
                        continue;

                    if (group.Method?.Accessibility?.All(a => a != methodSymbol.DeclaredAccessibility) == true)
                        continue;

                    if (group.Method?.Exclude != null &&
                        RequiredAttributeExists((c) => methodSymbol.TryGetDerivedAttribute(c), group.Method.Exclude))
                    {
                        continue;
                    }
                    else if (group.Method?.Include?.Any() == true &&
                             !RequiredAttributeExists((c) => methodSymbol.TryGetDerivedAttribute(c), group.Method.Include))
                    {
                        continue;
                    }
                }

                if (RequiredAttributeExists((c) => methodSymbol.TryGetDerivedAttribute(c), group.RequiredAttributes))
                    continue;

                if (group.Parameter != null && AreParametersExcluded(methodSymbol, group))
                    continue;

                diagnostics.Add(location, Diagnostic.Create(group.Message != null ? group.Message : Rule, location));
            }
        }

        private bool AreParametersExcluded(IMethodSymbol methodSymbol, NamedGroup group)
        {
            foreach (var parameter in methodSymbol.Parameters)
            {
                if (group.Parameter.Exclude != null &&
                    group.Parameter.Exclude.Any(x => parameter.HasAttribute(WellKnownTypeProvider.GetOrCreateTypeByMetadataName(x.Key))))
                {
                    return true;
                }
                else if (group.Parameter.Include != null &&
                         group.Parameter.Include.Any(x => parameter.HasAttribute(WellKnownTypeProvider.GetOrCreateTypeByMetadataName(x.Key))))
                {
                    return false;
                }
            }

            return group.Parameter.Include.Any();
        }

        private bool RequiredAttributeExists(Func<Func<AttributeData, bool>, AttributeData> tryGetDerivedAttribute, Dictionary<string, List<AttributeCondition>> attributes)
        {
            foreach (var requiredAttribute in attributes)
            {
                var type = WellKnownTypeProvider.GetOrCreateTypeByMetadataName(requiredAttribute.Key);
                if (type == null)
                    continue;

                (bool found, bool satisfies) = RequiredAttributeExists(tryGetDerivedAttribute, type, requiredAttribute.Value);
                if (found)
                    return satisfies;
            }

            return false;
        }

        private (bool found, bool satisfies) RequiredAttributeExists(Func<Func<AttributeData, bool>, AttributeData> tryGetDerivedAttribute, INamedTypeSymbol type, List<AttributeCondition> conditions)
        {
            var hasConditions = conditions.Any(x => x.MustMatch.Count != 0);

            var attr = tryGetDerivedAttribute(c =>
            {
                if (hasConditions)
                    return Equals(c.AttributeClass, type);

                var attributeClass = c.AttributeClass;
                while (attributeClass != null)
                {
                    if (Equals(attributeClass, type))
                        return true;

                    attributeClass = attributeClass.BaseType;
                }

                return false;
            });

            if (attr != null)
                return (true, SatisfiesConditon(attr, conditions));

            return (false, false);
        }
    }
}
