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
            private class AttributeCondition
            {
                public static readonly AttributeCondition TRUE = new AttributeCondition();

                public readonly List<(object ParameterIndexOrPropertyName, object ExpectedValue)> MustMatch;

                public AttributeCondition()
                {
                    MustMatch = new List<(object ParameterIndexOrPropertyName, object ExpectedValue)>();
                }
            }

            private class NamedGroup
            {
                public readonly string Name;

                public readonly HashSet<string> Controllers;
                public readonly List<(string AttributeName, AttributeCondition Condition)> NonActionAttributes;
                public readonly List<(string AttributeName, AttributeCondition Condition)> AnonymousAttributes;
                public readonly List<(string AttributeName, AttributeCondition Condition)> HttpMethodAttributes;
                public readonly List<(string AttributeName, AttributeCondition Condition)> IgnoreAttributes;
                public readonly List<(string AttributeName, AttributeCondition Condition)> AntiCsrfAttributes;
                public readonly List<(string AttributeName, AttributeCondition Condition)> ActionAttributes;

                public NamedGroup(string name)
                {
                    Name = name;

                    Controllers = new HashSet<string>();
                    NonActionAttributes = new List<(string AttributeName, AttributeCondition Condition)>();
                    AnonymousAttributes = new List<(string AttributeName, AttributeCondition Condition)>();
                    HttpMethodAttributes = new List<(string AttributeName, AttributeCondition Condition)>();
                    IgnoreAttributes = new List<(string AttributeName, AttributeCondition Condition)>();
                    AntiCsrfAttributes = new List<(string AttributeName, AttributeCondition Condition)>();
                    ActionAttributes = new List<(string AttributeName, AttributeCondition Condition)>();
                }
            }

            private readonly List<NamedGroup>   Groups;
            private readonly Configuration      Configuration;

            public CsrfTokenAnalyzer(Configuration configuration)
            {
                Configuration = configuration;

                var groups = new List<NamedGroup>();
                
                if (configuration.AntiCsrfAttributes != null)
                {
                    foreach (var set in configuration.AntiCsrfAttributes)
                    {
                        var name = set.Name;
                        var curGroup = groups.SingleOrDefault(g => g.Name == name);
                        if(curGroup == null)
                        {
                            curGroup = new NamedGroup(name);
                            groups.Add(curGroup);
                        }

                        if (set.ControllerName != null)
                        {
                            curGroup.Controllers.Add($"{set.NameSpace}.{set.ControllerName}");
                        }

                        if (set.NonActionAttributes != null)
                        {
                            foreach (var attr in set.NonActionAttributes)
                            {

                                var attrName = $"{set.NameSpace}.{attr.AttributeName}";
                                var condition = CreateAttributeCondition(attr.Condition);
                                curGroup.NonActionAttributes.Add((attrName, condition));
                            }
                        }

                        if (set.AllowAnonymousAttributes != null)
                        {
                            foreach (var attr in set.AllowAnonymousAttributes)
                            {
                                var attrName = $"{set.NameSpace}.{attr.AttributeName}";
                                var condition = CreateAttributeCondition(attr.Condition);
                                curGroup.AnonymousAttributes.Add((attrName, condition));
                            }
                        }

                        if (set.VulnerableAttributes != null)
                        {
                            foreach (var attr in set.VulnerableAttributes)
                            {
                                var attrName = $"{set.NameSpace}.{attr.AttributeName}";
                                var condition = CreateAttributeCondition(attr.Condition);
                                curGroup.HttpMethodAttributes.Add((attrName, condition));
                            }
                        }

                        if (set.IgnoreAttributes != null)
                        {
                            foreach (var attr in set.IgnoreAttributes)
                            {
                                var attrName = $"{set.NameSpace}.{attr.AttributeName}";
                                var condition = CreateAttributeCondition(attr.Condition);
                                curGroup.IgnoreAttributes.Add((attrName, condition));
                            }
                        }

                        if (set.AntiCsrfAttributes != null)
                        {
                            foreach (var attr in set.AntiCsrfAttributes)
                            {
                                var attrName = $"{set.NameSpace}.{attr.AttributeName}";
                                var condition = CreateAttributeCondition(attr.Condition);
                                curGroup.AntiCsrfAttributes.Add((attrName, condition));
                            }
                        }

                        if(set.ActionAttributes != null)
                        {
                            foreach (var attr in set.ActionAttributes)
                            {
                                var attrName = $"{set.NameSpace}.{attr.AttributeName}";
                                var condition = CreateAttributeCondition(attr.Condition);
                                curGroup.ActionAttributes.Add((attrName, condition));
                            }
                        }
                    }
                }

                Groups = groups;
            }
            
            private static AttributeCondition CreateAttributeCondition(Dictionary<object, object> conditions)
            {
                if (conditions == null)
                    return AttributeCondition.TRUE;

                var ret = new AttributeCondition();

                var parsedConditions = new Dictionary<int, object>(conditions.Count);
                foreach (var argument in conditions)
                {
                    if (!(argument.Value is Dictionary<object, object> d))
                        throw new Exception("Invalid condition format, expection dictionary");

                    if (d.Count != 1)
                        throw new Exception("Only one condition per argument is supported");

                    if(!(argument.Key is string arg))
                        throw new Exception("Invalid condition format, expected string");

                    int? idx;

                    if(int.TryParse(arg, out var parsedArg))
                    {
                        if(parsedArg < 0)
                        {
                            throw new Exception("Ordinal condition keys must be non-negative integers");
                        }

                        idx = parsedArg;
                    }
                    else
                    {
                        idx = null;
                    }
                    
                    var condition = d.Single();
                    if(!(condition.Key is string valueKey) || valueKey != "Value")
                        throw new Exception("Only 'Value' conditions are supported");

                    if(!(condition.Value is string conditionValue))
                        throw new Exception("Invalid condition format, expected a string");

                    object key = idx != null ? (object)idx.Value : arg;

                    if (int.TryParse(conditionValue, out var intVal))
                        ret.MustMatch.Add((key, intVal));
                    else if (bool.TryParse(conditionValue, out var boolVal))
                        ret.MustMatch.Add((key, boolVal));
                    else
                        ret.MustMatch.Add((key, conditionValue));
                }

                return ret;
            }

            private static bool HasApplicableAttribute(AttributeData attributeData, List<(string AttributeName, AttributeCondition Condition)> attributes)
            {
                var name = attributeData.AttributeClass.ToString();

                var args = attributeData.ConstructorArguments;
                var namedArgs = attributeData.NamedArguments;

                // todo: don't love iterating like this, switch to a Lookup maybe?
                foreach (var attr in attributes)
                {
                    if (!attr.AttributeName.Equals(name))
                        continue;

                    var condition = attr.Condition;

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
                                        if (named.Key.Equals(arg))
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

            private bool IsAntiForgeryToken(AttributeData attributeData, NamedGroup group)
            => HasApplicableAttribute(attributeData, group.AntiCsrfAttributes);

            private bool IsAnonymousAttribute(AttributeData attributeData, NamedGroup group)
            => HasApplicableAttribute(attributeData, group.AnonymousAttributes);

            private bool IsHttpMethodAttribute(AttributeData attributeData, NamedGroup group)
            => HasApplicableAttribute(attributeData, group.HttpMethodAttributes);

            private bool IsNonActionAttribute(AttributeData attributeData, NamedGroup group)
            => HasApplicableAttribute(attributeData, group.NonActionAttributes);

            private bool IsIgnoreAttribute(AttributeData attributeData, NamedGroup group)
            => HasApplicableAttribute(attributeData, group.IgnoreAttributes);

            private bool IsActionAttribute(AttributeData attributeData, NamedGroup group)
            => HasApplicableAttribute(attributeData, group.ActionAttributes);

            private bool IsDerivedFromController(ITypeSymbol classSymbol, NamedGroup group)
            {
                foreach(var c in group.Controllers)
                {
                    if (classSymbol.IsDerivedFrom(c))
                        return true;
                }

                return false;
            }

            public void VisitClass(SymbolAnalysisContext ctx)
            {
                var classSymbol = (ITypeSymbol)ctx.Symbol;
                foreach (var group in Groups)
                {
                    VisitClass(ctx, classSymbol, group);
                }
            }

            private void VisitClass(SymbolAnalysisContext ctx, ITypeSymbol classSymbol, NamedGroup group)
            {
                var isClassControllerDerived = IsDerivedFromController(classSymbol, group);

                // if we're not in a controller, and this group _ONLY_ publishes actions through controllers
                //   quit early
                if (!isClassControllerDerived && !group.ActionAttributes.Any())
                    return;

                bool isClassIgnored = IsClassIgnored(classSymbol, group);

                if (!Configuration.AuditMode && isClassIgnored)
                    return;

                if (IsClassAnonymous(classSymbol, group))
                    return;

                var antiForgeryAttributes = Configuration.AntiCsrfAttributes;
                bool classHasAntiForgeryAttribute = classSymbol.HasDerivedClassAttribute(c => IsAntiForgeryToken(c, group));
                
                foreach (var member in classSymbol.GetMembers())
                {
                    if (!(member is IMethodSymbol methodSymbol))
                        continue;

                    var shouldConsiderMethod =
                        isClassControllerDerived || IsMethodAction(methodSymbol, group);
                    
                    if (!shouldConsiderMethod)
                        continue;

                    var isMethodIgnored = false;
                    if (!isClassIgnored)
                        isMethodIgnored = IsMethodIgnored(methodSymbol, group);

                    if (!Configuration.AuditMode && isMethodIgnored)
                        continue;

                    var isArgumentIgnored = false;
                    if (!isClassIgnored && !isMethodIgnored)
                        isArgumentIgnored = IsArgumentIgnored(methodSymbol, classSymbol, group);

                    if (!Configuration.AuditMode && isArgumentIgnored)
                        continue;

                    if (!methodSymbol.HasDerivedMethodAttribute(c => IsHttpMethodAttribute(c, group)))
                        continue;

                    if (methodSymbol.HasDerivedMethodAttribute(c => IsNonActionAttribute(c, group)))
                        continue;

                    if (methodSymbol.HasDerivedMethodAttribute(c => IsAnonymousAttribute(c, group)))
                        continue;

                    if (!classHasAntiForgeryAttribute && !AntiforgeryAttributeExists(methodSymbol, group))
                    {
                        if (isClassIgnored || isMethodIgnored)
                            ctx.ReportDiagnostic(Diagnostic.Create(CsrfTokenDiagnosticAnalyzer.AuditRule, methodSymbol.Locations[0]));
                        else if (isArgumentIgnored)
                            ctx.ReportDiagnostic(Diagnostic.Create(CsrfTokenDiagnosticAnalyzer.FromBodyAuditRule, methodSymbol.Locations[0]));
                        else
                            ctx.ReportDiagnostic(Diagnostic.Create(CsrfTokenDiagnosticAnalyzer.Rule, methodSymbol.Locations[0]));
                    }
                }
            }

            private bool IsClassIgnored(ITypeSymbol classSymbol, NamedGroup group)
            => classSymbol.HasDerivedClassAttribute(c => IsIgnoreAttribute(c, group));

            private bool IsClassAnonymous(ITypeSymbol classSymbol, NamedGroup group)
            => classSymbol.HasDerivedClassAttribute(c => IsAnonymousAttribute(c, group));

            private bool IsMethodIgnored(IMethodSymbol methodSymbol, NamedGroup group)
            => methodSymbol.HasDerivedMethodAttribute(c => IsIgnoreAttribute(c, group));

            private bool IsMethodAction(IMethodSymbol methodSymbol, NamedGroup group)
            => methodSymbol.HasDerivedMethodAttribute(c => IsActionAttribute(c, group));

            private bool IsArgumentIgnored(IMethodSymbol methodSymbol, ITypeSymbol classSymbol, NamedGroup group)
            {
                foreach (var parameter in methodSymbol.Parameters)
                {
                    if (parameter.HasAttribute(c => IsIgnoreAttribute(c, group)))
                        return true;

                    if (parameter.HasAttribute(c => IsIgnoreAttribute(c, group)))
                        return false;
                }

                var isApiController = classSymbol.HasDerivedClassAttribute(c => IsIgnoreAttribute(c, group));
                return isApiController;
            }

            private bool AntiforgeryAttributeExists(IMethodSymbol methodSymbol, NamedGroup group)
            => methodSymbol.HasDerivedMethodAttribute(c => IsAntiForgeryToken(c, group));
        }
    }
}
