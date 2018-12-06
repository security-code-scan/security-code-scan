using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Config;

namespace SecurityCodeScan.Analyzers
{
    public abstract class MvcCsrfTokenAnalyzer : CsrfTokenDiagnosticAnalyzer
    {
        protected MvcCsrfTokenAnalyzer() : base("System.Web.Mvc", "System.Web.Mvc") { }
    }

    public abstract class CoreCsrfTokenAnalyzer : CsrfTokenDiagnosticAnalyzer
    {
        protected CoreCsrfTokenAnalyzer() : base("Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Authorization")
        {
            IgnoreAntiforgeryToken = $"{Namespace}.IgnoreAntiforgeryTokenAttribute";
            FromBody               = $"{Namespace}.FromBodyAttribute";

            base.IsClassIgnored    = IsClassIgnored;
            base.IsMethodIgnored   = IsMethodIgnored;
            base.IsArgumentIgnored = IsArgumentIgnored;
        }

        private readonly string IgnoreAntiforgeryToken;
        private readonly string FromBody;

        private new bool IsClassIgnored(ITypeSymbol classSymbol)
        {
            return classSymbol.HasDerivedClassAttribute(attributeData => attributeData.AttributeClass.ToString() == IgnoreAntiforgeryToken);
        }

        private new bool IsMethodIgnored(IMethodSymbol methodSymbol)
        {
            return methodSymbol.HasDerivedMethodAttribute(attributeData => attributeData.AttributeClass.ToString() == IgnoreAntiforgeryToken);
        }

        private new bool IsArgumentIgnored(IMethodSymbol methodSymbol)
        {
            foreach (var parameter in methodSymbol.Parameters)
            {
                if (parameter.HasAttribute(attr => attr.AttributeClass.ToString().Equals(FromBody)))
                    return true;
            }

            return false;
        }
    }

    public abstract class CsrfTokenDiagnosticAnalyzer : DiagnosticAnalyzer
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

        protected CsrfTokenDiagnosticAnalyzer(string nameSpace,
                                              string allowAnonymousNamespace)
        {
            Namespace               = nameSpace;
            AllowAnonymousNamespace = allowAnonymousNamespace;
        }

        protected readonly string                    Namespace;
        private readonly   string                    AllowAnonymousNamespace;
        protected          Func<ITypeSymbol, bool>   IsClassIgnored;
        protected          Func<IMethodSymbol, bool> IsMethodIgnored;
        protected          Func<IMethodSymbol, bool> IsArgumentIgnored;

        public override void Initialize(AnalysisContext analysisContext)
        {
            analysisContext.RegisterCompilationStartAction(
                context =>
                {
                    var analyzer = new CsrfTokenAnalyzer(ConfigurationManager.Instance.GetProjectConfiguration(context.Options.AdditionalFiles),
                                                         Namespace,
                                                         AllowAnonymousNamespace,
                                                         IsClassIgnored,
                                                         IsMethodIgnored,
                                                         IsArgumentIgnored);
                    context.RegisterSymbolAction(analyzer.VisitClass, SymbolKind.NamedType);
                });
        }

        private class CsrfTokenAnalyzer
        {
            public CsrfTokenAnalyzer(Configuration             configuration,
                                     string                    nameSpace,
                                     string                    allowAnonymousNamespace,
                                     Func<ITypeSymbol, bool>   isClassIgnored,
                                     Func<IMethodSymbol, bool> isMethodIgnored,
                                     Func<IMethodSymbol, bool> isArgumentIgnored)
            {
                Configuration     = configuration;
                IsMethodIgnored   = isMethodIgnored;
                IsClassIgnored    = isClassIgnored;
                IsArgumentIgnored = isArgumentIgnored;

                //99% of the occurrences will be HttpPost.. but here are some additional HTTP methods
                //https://msdn.microsoft.com/en-us/library/system.web.mvc.actionmethodselectorattribute(v=vs.118).aspx
                Namespace = nameSpace;
                MethodsHttp = new List<string>
            {
                $"{nameSpace}.HttpPostAttribute",
                $"{nameSpace}.HttpPutAttribute",
                $"{nameSpace}.HttpDeleteAttribute",
                $"{nameSpace}.HttpPatchAttribute",
            };

                AnonymousAttribute = $"{allowAnonymousNamespace}.AllowAnonymousAttribute";
                NonActionAttribute = $"{nameSpace}.NonActionAttribute";
                Controller         = $"{nameSpace}.Controller";
            }

            private readonly string                    Controller;
            private readonly string                    NonActionAttribute;
            private readonly string                    Namespace;
            private readonly string                    AnonymousAttribute;
            private readonly List<string>              MethodsHttp;
            private readonly Configuration             Configuration;
            private readonly Func<ITypeSymbol, bool>   IsClassIgnored;
            private readonly Func<IMethodSymbol, bool> IsMethodIgnored;
            private readonly Func<IMethodSymbol, bool> IsArgumentIgnored;

            private bool HasAntiForgeryToken(AttributeData attributeData, string antiForgeryAttribute)
            {
                return attributeData.AttributeClass.ToString() == antiForgeryAttribute;
            }

            private bool HasAnonymousAttribute(AttributeData attributeData)
            {
                return attributeData.AttributeClass.ToString() == AnonymousAttribute;
            }

            public void VisitClass(SymbolAnalysisContext ctx)
            {
                var classSymbol = (ITypeSymbol)ctx.Symbol;
                if (!classSymbol.IsDerivedFrom(Controller))
                    return;

                bool isClassIgnored = IsClassIgnored != null && IsClassIgnored(classSymbol);

                if (!Configuration.AuditMode && isClassIgnored)
                    return;

                if (classSymbol.HasDerivedClassAttribute(HasAnonymousAttribute))
                    return;

                var antiForgeryAttributes = ConfigurationManager.Instance
                                                                .GetProjectConfiguration(ctx.Options.AdditionalFiles)
                                                                .AntiCsrfAttributes[Namespace];
                bool hasDerivedClassAttribute = classSymbol.HasDerivedClassAttribute(attributeData =>
                {
                    foreach (var antiForgeryAttribute in antiForgeryAttributes)
                    {
                        if (HasAntiForgeryToken(attributeData, antiForgeryAttribute))
                            return true;
                    }

                    return false;
                });

                foreach (var member in classSymbol.GetMembers())
                {
                    if (!(member is IMethodSymbol methodSymbol))
                        continue;

                    var isMethodIgnored = false;
                    if (!isClassIgnored)
                        isMethodIgnored = IsMethodIgnored != null && IsMethodIgnored(methodSymbol);

                    if (!Configuration.AuditMode && isMethodIgnored)
                        return;

                    var isArgumentIgnored = false;
                    if (!isClassIgnored && !isMethodIgnored)
                        isArgumentIgnored = IsArgumentIgnored != null && IsArgumentIgnored(methodSymbol);

                    if (!Configuration.AuditMode && isArgumentIgnored)
                        return;

                    if (!methodSymbol.HasDerivedMethodAttribute(attributeData =>
                                                                    MethodsHttp.Contains(attributeData.AttributeClass.ToString())))
                        continue;

                    if (methodSymbol.HasDerivedMethodAttribute(attributeData => attributeData.AttributeClass.ToString() == NonActionAttribute))
                        continue;

                    if (methodSymbol.HasDerivedMethodAttribute(HasAnonymousAttribute))
                        continue;

                    if (!hasDerivedClassAttribute && !AntiforgeryAttributeExists(methodSymbol, antiForgeryAttributes))
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

            private bool AntiforgeryAttributeExists(IMethodSymbol methodSymbol, IEnumerable<string> antiForgeryAttributes)
            {
                foreach (var antiForgeryAttribute in antiForgeryAttributes)
                {
                    if (methodSymbol.HasDerivedMethodAttribute(attributeData => HasAntiForgeryToken(attributeData, antiForgeryAttribute)))
                    {
                        return true;
                    }
                }

                return false;
            }
        }
    }
}
