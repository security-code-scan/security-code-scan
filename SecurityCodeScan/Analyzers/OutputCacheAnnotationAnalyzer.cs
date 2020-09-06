using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class OutputCacheAnnotationAnalyzer : DiagnosticAnalyzer
    {
        public const            string                               DiagnosticId = "SCS0019";
        private static readonly DiagnosticDescriptor                 Rule         = LocaleUtil.GetDescriptor(DiagnosticId);
        public override         ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(Rule);

        public override void Initialize(AnalysisContext context)
        {
            if (!Debugger.IsAttached) // prefer single thread for debugging in development
                context.EnableConcurrentExecution();

            if (context.IsAuditMode())
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
            else
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);

            context.RegisterSymbolAction(VisitClass, SymbolKind.NamedType);
        }

        private bool HasOutputCacheAttribute(ISymbol symbol, ref int duration, bool method)
        {
            int d = duration;

            bool Condition(AttributeData attributeData)
            {
                if (attributeData.AttributeClass.ToString() != "System.Web.Mvc.OutputCacheAttribute") return false;

                var durationArgument = attributeData.NamedArguments.FirstOrDefault(x => x.Key == "Duration");
                if (durationArgument.Equals(default(KeyValuePair<string, TypedConstant>)))
                {
                    d = int.MaxValue;
                }
                else
                {
                    if (durationArgument.Value.Value == null)
                        return false;

                    d = (int)durationArgument.Value.Value;
                }

                return true;
            }

            var ret = method
                          ? ((IMethodSymbol)symbol).HasDerivedAttribute(Condition)
                          : ((ITypeSymbol)symbol).HasDerivedAttribute(Condition);
            duration = d;
            return ret;
        }


        private void VisitClass(SymbolAnalysisContext ctx)
        {
            var classSymbol = (ITypeSymbol)ctx.Symbol;

            bool classHasAuthAnnotation  = classSymbol.HasDerivedAttribute(
                attributeData => attributeData.AttributeClass.ToString() == "System.Web.Mvc.AuthorizeAttribute");
            int  classCacheDuration      = 0;
            bool classHasCacheAnnotation = HasOutputCacheAttribute(classSymbol, ref classCacheDuration, method: false);

            foreach (var member in classSymbol.GetMembers())
            {
                if(!(member is IMethodSymbol methodSymbol))
                    continue;

                if(methodSymbol.MethodKind != MethodKind.Ordinary)
                    continue;

                if (methodSymbol.DeclaredAccessibility != Accessibility.Public)
                    continue;

                bool methodHasAuthAnnotation  = methodSymbol.HasDerivedAttribute(
                    attributeData => attributeData.AttributeClass.ToString() == "System.Web.Mvc.AuthorizeAttribute");
                int  methodCacheDuration      = 0;
                bool methodHasCacheAnnotation = HasOutputCacheAttribute(methodSymbol,
                                                                        ref methodCacheDuration,
                                                                        method: true);

                bool hasAuth  = classHasAuthAnnotation || methodHasAuthAnnotation;
                bool hasCache = methodHasCacheAnnotation
                                    ? methodCacheDuration                           > 0
                                    : classHasCacheAnnotation && classCacheDuration > 0;

                if (hasAuth && hasCache)
                {
                    ctx.ReportDiagnostic(Diagnostic.Create(Rule, member.Locations[0]));
                }
            }
        }
    }
}
