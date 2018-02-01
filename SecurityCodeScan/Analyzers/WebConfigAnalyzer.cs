using System;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Xml;
using System.Xml.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class WebConfigAnalyzer : DiagnosticAnalyzer, IExternalFileAnalyzer
    {
        public static readonly DiagnosticDescriptor RuleValidateRequest         = LocaleUtil.GetDescriptor("SCS0021");
        public static readonly DiagnosticDescriptor RuleEnableEventValidation   = LocaleUtil.GetDescriptor("SCS0022");
        public static readonly DiagnosticDescriptor RuleViewStateEncryptionMode = LocaleUtil.GetDescriptor("SCS0023");
        public static readonly DiagnosticDescriptor RuleEnableViewStateMac      = LocaleUtil.GetDescriptor("SCS0024");

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(
            RuleValidateRequest, RuleEnableEventValidation, RuleViewStateEncryptionMode, RuleEnableViewStateMac);

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterCompilationAction(Compilation);
        }

        private void Compilation(CompilationAnalysisContext ctx)
        {
            //Load Web.config files : ASP.net web application configuration
            foreach (AdditionalText file in ctx.Options
                                               .AdditionalFiles
                                               .Where(file => Path.GetFileName(file.Path).StartsWith("Web.config")))
            {
                AnalyzeFile(file, ctx);
            }
        }

        private void CheckAttribute(XElement                   element,
                                    string                     attributeName,
                                    string                     defaultValue,
                                    Func<string, bool>         isGoodValue,
                                    DiagnosticDescriptor       diagnosticDescriptor,
                                    AdditionalText             file,
                                    CompilationAnalysisContext context)
        {
            var attributeValue = element?.Attribute(attributeName);
            var value = attributeValue?.Value ?? defaultValue;

            if (isGoodValue(value.Trim()))
                return;

            var lineInfo   = (IXmlLineInfo)element;
            int lineNumber = element != null && lineInfo.HasLineInfo() ? lineInfo.LineNumber : 1;
            context.ReportDiagnostic(ExternalDiagnostic.Create(diagnosticDescriptor,
                                                               file.Path,
                                                               lineNumber,
                                                               element != null ? element.ToStringStartElement() : String.Empty));
        }

        private void CheckRequestValidationMode(XElement element, XDocument doc, AdditionalText file, CompilationAnalysisContext context)
        {
            CheckAttribute(element,
                           "requestValidationMode",
                           "4.0",
                           value =>
                           {
                               if (!decimal.TryParse(value, out var version))
                                   return true;

                               return version >= 4.0M;
                           },
                           RuleValidateRequest,
                           file,
                           context);
        }

        public void AnalyzeFile(AdditionalText file, CompilationAnalysisContext context)
        {
            var doc = XDocument.Load(file.Path, LoadOptions.SetLineInfo);

            var systemWebElement = doc.Element("configuration")?.Element("system.web");

            CheckAttribute(systemWebElement?.Element("pages"),
                           "validateRequest",
                           "True",
                           value => 0 == String.Compare("true", value, StringComparison.OrdinalIgnoreCase),
                           RuleValidateRequest,
                           file,
                           context);

            CheckRequestValidationMode(systemWebElement?.Element("httpRuntime"), doc, file, context);
            CheckRequestValidationMode(doc.Element("configuration")?.Element("location")?.Element("system.web")?.Element("httpRuntime"),
                                       doc,
                                       file,
                                       context);

            CheckAttribute(systemWebElement?.Element("pages"),
                           "enableEventValidation",
                           "True",
                           value => 0 == String.Compare("true", value, StringComparison.OrdinalIgnoreCase),
                           RuleEnableEventValidation,
                           file,
                           context);

            CheckAttribute(systemWebElement?.Element("pages"),
                           "viewStateEncryptionMode",
                           "Auto",
                           value => 0 == String.Compare("Always", value, StringComparison.OrdinalIgnoreCase),
                           RuleViewStateEncryptionMode,
                           file,
                           context);

            // https://blogs.msdn.microsoft.com/webdev/2014/09/09/farewell-enableviewstatemac/
            CheckAttribute(systemWebElement?.Element("pages"),
                           "enableViewStateMac",
                           "True",
                           value => 0 == String.Compare("true", value, StringComparison.OrdinalIgnoreCase),
                           RuleEnableViewStateMac,
                           file,
                           context);
        }
    }
}
