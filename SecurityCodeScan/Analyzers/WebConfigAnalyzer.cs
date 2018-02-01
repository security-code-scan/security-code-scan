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
    internal static class XElementExtensions
    {
        public static string ToStringStartElement(this XElement e)
        {
            var element = e.ToString();
            return element.Substring(0, element.IndexOf('>') + 1);
        }
    }

    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class WebConfigAnalyzer : DiagnosticAnalyzer
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
            var additionalFiles = ctx.Options.AdditionalFiles;

            //Load Web.config files : ASP.net web application configuration
            var configFiles = additionalFiles.Where(file => Path.GetFileName(file.Path).StartsWith("Web.config"));

            foreach (AdditionalText file in configFiles.ToList())
            {
                AnalyzeConfigurationFile( file, ctx);
            }
        }

        private void CheckAttribute(XElement                   element,
                                    string                     attribute,
                                    string                     defaultValue,
                                    Func<string, bool>         isGoodValue,
                                    DiagnosticDescriptor       diagnosticDescriptor,
                                    AdditionalText             file,
                                    CompilationAnalysisContext context)
        {
            var validateRequest = element?.Attribute(attribute);
            var value = validateRequest?.Value ?? defaultValue;

            if (isGoodValue(value))
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

        public void AnalyzeConfigurationFile(AdditionalText file, CompilationAnalysisContext context)
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
