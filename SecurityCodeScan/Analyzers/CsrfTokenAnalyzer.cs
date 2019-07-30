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
    internal class CsrfTokenDiagnosticAnalyzer : SecurityAnalyzer
    {
        public const           string               DiagnosticId = "SCS0016";
        public static readonly DiagnosticDescriptor Rule         = LocaleUtil.GetDescriptor(DiagnosticId);
        public static readonly DiagnosticDescriptor AuditRule    = LocaleUtil.GetDescriptor(DiagnosticId,
                                                                                            titleId: "title_audit",
                                                                                            descriptionId: "description_audit");
        public static readonly DiagnosticDescriptor FromBodyAuditRule = LocaleUtil.GetDescriptor(DiagnosticId,
                                                                                                 titleId: "title_frombody_audit",
                                                                                                 descriptionId: "description_frombody_audit");

        public override         ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(Rule);

        public override void Initialize(ISecurityAnalysisContext context)
        {
            context.RegisterCompilationStartAction(OnCompilationStartAction);
        }

        private void OnCompilationStartAction(CompilationStartAnalysisContext context, Configuration config)
        {
            var analyzer = new CsrfTokenAnalyzer(config);
            context.RegisterSymbolAction(analyzer.VisitClass, SymbolKind.NamedType);
        }

        private class CsrfTokenAnalyzer
        {
            private readonly Configuration      Configuration;

            public CsrfTokenAnalyzer(Configuration configuration)
            {
                Configuration = configuration;
            }
            
            private static bool HasApplicableAttribute(AttributeData attributeData, Dictionary<string, List<CsrfAttributeCondition>> attributes)
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

            private static bool IsAntiForgeryToken(AttributeData attributeData, CsrfNamedGroup group)
            => HasApplicableAttribute(attributeData, group.AntiCsrfAttributes);

            private static bool IsAnonymousAttribute(AttributeData attributeData, CsrfNamedGroup group)
            => HasApplicableAttribute(attributeData, group.AnonymousAttributes);

            private static bool IsVulnerableAttribute(AttributeData attributeData, CsrfNamedGroup group)
            => HasApplicableAttribute(attributeData, group.VulnerableAttributes);

            private static bool IsNonActionAttribute(AttributeData attributeData, CsrfNamedGroup group)
            => HasApplicableAttribute(attributeData, group.NonActionAttributes);

            private static bool IsIgnoreAttribute(AttributeData attributeData, CsrfNamedGroup group)
            => HasApplicableAttribute(attributeData, group.IgnoreAttributes);

            private static bool IsActionAttribute(AttributeData attributeData, CsrfNamedGroup group)
            => HasApplicableAttribute(attributeData, group.ActionAttributes);

            private static bool IsDerivedFromController(ITypeSymbol classSymbol, CsrfNamedGroup group)
            {
                if (!group.Controllers.Any())
                    return false;

                return classSymbol.IsDerivedFrom(group.Controllers);
            }

            public void VisitClass(SymbolAnalysisContext ctx)
            {
                var classSymbol = (ITypeSymbol)ctx.Symbol;
                foreach (var group in Configuration.CsrfGoups)
                {
                    VisitClass(ctx, classSymbol, group);
                }
            }

            private void VisitClass(SymbolAnalysisContext ctx, ITypeSymbol classSymbol, CsrfNamedGroup group)
            {
                /**
                 * Logic for checking
                 *   - Actions (that we need to check) are
                 *     * Public method derived from a registered controller
                 *     * Having a vulnerable attribute attached to it
                 *   - We ignore the action if
                 *     * The controller has an ignore attribute on it
                 *       + Unless the (potential) action is explicitly annotated as an action
                 *     * The controller has an allows anonymous attribute on it
                 *       + Unless the (potential) action is explicitly annotated as an action
                 *     * The action has an ignore attribute on it
                 *     * The action has an allows anonymous attribute on it
                 *   - An action is vulnerable if
                 *     * It doesn't have a suppressing attribute on itself, or on the controller
                 *     * It has an explicitly dangerous attribute on one of it's arguments
                 *     * UNLESS there's an attribute on a parameter that ignores CSRF checking
                 */

                var descendsFromController = IsDerivedFromController(classSymbol, group);
                var couldHaveActionAttribute = group.ActionAttributes.Any();

                var isPotentiallyController = descendsFromController || couldHaveActionAttribute;

                if (!isPotentiallyController)
                    return;

                var controllerExplicitlyIgnored = IsClassIgnored(classSymbol, group);
                var controllerExplicitlyAnonymous = IsClassAnonymous(classSymbol, group);
                var controllerExplicitlySafe = classSymbol.HasDerivedClassAttribute(c => IsAntiForgeryToken(c, group));

                if (controllerExplicitlySafe)
                    return;

                foreach (var member in classSymbol.GetMembers())
                {
                    if (!(member is IMethodSymbol methodSymbol))
                        continue;

                    var methodExplicitlyAction = IsMethodAction(methodSymbol, group);
                    var methodExplicitlyNotAction = IsMethodNonAction(methodSymbol, group);

                    var isAction =
                        !methodExplicitlyNotAction &&
                        (descendsFromController || methodExplicitlyAction);

                    if (!isAction)
                        continue;

                    var actionExplicitlyIgnored = IsMethodIgnored(methodSymbol, group);

                    var ignoreAction =
                        (!Configuration.AuditMode && actionExplicitlyIgnored) ||
                        (controllerExplicitlyIgnored && !methodExplicitlyAction);

                    if (ignoreAction)
                        continue;

                    var actionExplicitlySafe = AntiforgeryAttributeExists(methodSymbol, group);
                    if (actionExplicitlySafe)
                        continue;

                    var actionExplicitlyAllowsAnonymous = IsMethodAnonymous(methodSymbol, group);

                    if (actionExplicitlyAllowsAnonymous)
                        continue;

                    var actionExplicitlyVulnerable = IsMethodVulnerable(methodSymbol, group);

                    var (argsExplicitlyIgnored, argsExplicitlyVulnerable) = GetArgumentState(methodSymbol, group);

                    var actionImplicitAllowsAnonymous =
                        (!Configuration.AuditMode && controllerExplicitlyAnonymous) &&
                        !argsExplicitlyVulnerable;

                    if (actionImplicitAllowsAnonymous)
                        continue;

                    var actionVulnerable = actionExplicitlyVulnerable || argsExplicitlyVulnerable;

                    if (!Configuration.AuditMode)
                    {
                        actionVulnerable &= !argsExplicitlyIgnored;
                    }

                    if (!actionVulnerable)
                        continue;

                    if (controllerExplicitlyIgnored || actionExplicitlyIgnored)
                        ctx.ReportDiagnostic(Diagnostic.Create(AuditRule, methodSymbol.Locations[0]));
                    else if (argsExplicitlyIgnored)
                        ctx.ReportDiagnostic(Diagnostic.Create(FromBodyAuditRule, methodSymbol.Locations[0]));
                    else
                        ctx.ReportDiagnostic(Diagnostic.Create(Rule, methodSymbol.Locations[0]));
                }

                // old!

                //var isClassControllerDerived = IsDerivedFromController(classSymbol, group);

                //// if we're not in a controller, and this group _ONLY_ publishes actions through controllers
                ////   quit early
                //if (!isClassControllerDerived && !group.ActionAttributes.Any())
                //    return;

                //bool isClassIgnored = IsClassIgnored(classSymbol, group);

                //if (!Configuration.AuditMode && isClassIgnored)
                //    return;

                //if (IsClassAnonymous(classSymbol, group))
                //    return;

                //bool classHasAntiForgeryAttribute = classSymbol.HasDerivedClassAttribute(c => IsAntiForgeryToken(c, group));

                //foreach (var member in classSymbol.GetMembers())
                //{
                //    if (!(member is IMethodSymbol methodSymbol))
                //        continue;

                //    var shouldConsiderMethod =
                //        isClassControllerDerived || IsMethodAction(methodSymbol, group);

                //    if (!shouldConsiderMethod)
                //        continue;

                //    var isMethodIgnored = false;
                //    if (!isClassIgnored)
                //        isMethodIgnored = IsMethodIgnored(methodSymbol, group);

                //    if (!Configuration.AuditMode && isMethodIgnored)
                //        continue;

                //    var isArgumentIgnored = false;
                //    if (!isClassIgnored && !isMethodIgnored)
                //        isArgumentIgnored = IsArgumentIgnored(methodSymbol, classSymbol, group);

                //    if (!Configuration.AuditMode && isArgumentIgnored)
                //        continue;

                //    if (!methodSymbol.HasDerivedMethodAttribute(c => IsVulnerableAttribute(c, group)))
                //        continue;

                //    if (methodSymbol.HasDerivedMethodAttribute(c => IsNonActionAttribute(c, group)))
                //        continue;

                //    if (methodSymbol.HasDerivedMethodAttribute(c => IsAnonymousAttribute(c, group)))
                //        continue;

                //    if (!classHasAntiForgeryAttribute && !AntiforgeryAttributeExists(methodSymbol, group))
                //    {
                //        if (isClassIgnored || isMethodIgnored)
                //            ctx.ReportDiagnostic(Diagnostic.Create(AuditRule, methodSymbol.Locations[0]));
                //        else if (isArgumentIgnored)
                //            ctx.ReportDiagnostic(Diagnostic.Create(FromBodyAuditRule, methodSymbol.Locations[0]));
                //        else
                //            ctx.ReportDiagnostic(Diagnostic.Create(Rule, methodSymbol.Locations[0]));
                //    }
                //}
            }

            private static (bool ArgumentsIgnored, bool ArgumentsVulnerable) GetArgumentState(IMethodSymbol methodSymbol, CsrfNamedGroup group)
            {
                var argsExplicitlyIgnored = false;
                var argsExplicitlyVulnerable = false;

                foreach (var arg in methodSymbol.Parameters)
                {
                    if (arg.HasAttribute(c => IsIgnoreAttribute(c, group)))
                    {
                        argsExplicitlyIgnored = true;
                    }

                    if (arg.HasAttribute(c => IsVulnerableAttribute(c, group)))
                    {
                        argsExplicitlyVulnerable = true;
                    }
                }

                return (argsExplicitlyIgnored, argsExplicitlyVulnerable);
            }

            private static bool IsClassIgnored(ITypeSymbol classSymbol, CsrfNamedGroup group)
            {
                if (!group.IgnoreAttributes.Any())
                    return false;

                return classSymbol.HasDerivedClassAttribute(c => IsIgnoreAttribute(c, group));
            }

            private static bool IsClassAnonymous(ITypeSymbol classSymbol, CsrfNamedGroup group)
            {
                if (!group.AnonymousAttributes.Any())
                    return false;

                return classSymbol.HasDerivedClassAttribute(c => IsAnonymousAttribute(c, group));
            }

            private static bool IsMethodAnonymous(IMethodSymbol methodSymbol, CsrfNamedGroup group)
            {
                if (!group.AnonymousAttributes.Any())
                    return false;

                return methodSymbol.HasDerivedMethodAttribute(c => IsAnonymousAttribute(c, group));
            }

            private static bool IsMethodIgnored(IMethodSymbol methodSymbol, CsrfNamedGroup group)
            {
                if (!group.IgnoreAttributes.Any())
                    return false;

                return methodSymbol.HasDerivedMethodAttribute(c => IsIgnoreAttribute(c, group));
            }

            private static bool IsMethodAction(IMethodSymbol methodSymbol, CsrfNamedGroup group)
            {
                if (!group.ActionAttributes.Any())
                    return false;

                return methodSymbol.HasDerivedMethodAttribute(c => IsActionAttribute(c, group));
            }

            private static bool IsMethodVulnerable(IMethodSymbol methodSymbol, CsrfNamedGroup group)
            {
                if (!group.VulnerableAttributes.Any())
                    return false;

                return methodSymbol.HasDerivedMethodAttribute(c => IsVulnerableAttribute(c, group));
            }

            private static bool IsMethodNonAction(IMethodSymbol methodSymbol, CsrfNamedGroup group)
            {
                if (!group.NonActionAttributes.Any())
                    return false;

                return methodSymbol.HasDerivedMethodAttribute(c => IsNonActionAttribute(c, group));
            }

            private static bool AntiforgeryAttributeExists(IMethodSymbol methodSymbol, CsrfNamedGroup group)
            {
                if (!group.AntiCsrfAttributes.Any())
                    return false;

                return methodSymbol.HasDerivedMethodAttribute(c => IsAntiForgeryToken(c, group));
            }
        }
    }
}
